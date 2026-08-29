#!/usr/bin/env python3
"""Recompute DriftBench traffic-shift results from public packet observations.

This standalone verifier reads only files in the curated traffic-distribution
directory.  It never reads packet captures, endpoint identifiers, fitted-model
outputs, private paths, or external authorities.  Its observation-recomputed
scope is recorded in ``RECOMPUTED_TABLES`` and its explicit limits in
``INTEGRITY_ONLY_TABLES``.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import statistics
import sys
from array import array
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np


VERSION = "driftbench-public-traffic-recompute-v1"
PRIMARY_SCOPE = "heldout_primary"
ALL_SCOPE = "general_all_sessions_sensitivity"
OBSERVATION_FIELDS = (
    "protocol_id", "configuration_id", "class_name", "session_view_index",
    "position", "direction", "frame_length_bytes", "ip_total_length_bytes",
    "tcp_payload_length_bytes", "ipv4_ttl", "tcp_window_raw", "iat_us",
    "tcp_flag_pattern",
)
NUMERIC_FEATURES = (
    "frame_length_bytes", "ip_total_length_bytes", "tcp_payload_length_bytes",
    "ipv4_ttl", "tcp_window_raw", "iat_us",
)
CATEGORICAL_FEATURES = ("direction", "tcp_flag_pattern")
PRIMARY_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
NONREDUNDANT_FEATURES = (
    "ip_total_length_bytes", "ipv4_ttl", "tcp_window_raw", "iat_us",
    "direction", "tcp_flag_pattern",
)
SEQUENTIAL_FEATURES = (
    "signed_ip_total_length_bytes", "direction", "iat_us", "ipv4_ttl",
    "tcp_window_raw", "tcp_payload_length_bytes",
)
CONTRASTS = (
    "client_browser", "client_os", "client_browser_and_os", "network", "temporal",
)
FEATURE_FAMILY = {
    "ip_total_length_bytes": "size_packetization",
    "ipv4_ttl": "host_path",
    "tcp_window_raw": "host_path",
    "direction": "direction_flags",
    "tcp_flag_pattern": "direction_flags",
    "iat_us": "timing",
}
COMPOSITE_FAMILIES = (
    "size_packetization", "host_path", "direction_flags", "timing",
)
FEATURE_DISPLAY = {
    "frame_length_bytes": "Captured frame length",
    "ip_total_length_bytes": "IPv4 total length",
    "tcp_payload_length_bytes": "TCP payload length",
    "ipv4_ttl": "IPv4 TTL / hop limit",
    "tcp_window_raw": "Raw TCP window",
    "iat_us": "Inter-arrival time",
    "direction": "Packet direction",
    "tcp_flag_pattern": "TCP flag pattern",
}
CONTRAST_DISPLAY = {
    "client_browser": "Browser only",
    "client_os": "OS only",
    "client_browser_and_os": "Browser + OS",
    "network": "Network A/B",
    "temporal": "Temporal",
}
RECOMPUTED_TABLES = (
    "tables/directional_pair_mapping.csv",
    "tables/numeric_group_descriptives.csv",
    "tables/categorical_group_descriptives.csv",
    "tables/within_class_marginal_distances.csv",
    "tables/marginal_shift_summary_long.csv",
    "tables/marginal_shift_summary_wide.csv",
    "tables/packet_pooled_sensitivity.csv",
    "tables/direction_stratified_marginal_distances.csv",
    "tables/general_all_session_sensitivity.csv",
    "tables/first40_contributors.csv",
    "tables/first40_unit_distances.csv",
    "tables/first40_position_summaries.csv",
    "tables/first40_persistence.csv",
    "tables/pair_feature_shifts.csv",
    "tables/pair_family_shifts.csv",
    "tables/pair_marginal_composites.csv",
    "tables/pair_sequential_feature_shifts.csv",
    "tables/pair_sequential_composites.csv",
    "tables/figure_data_direction_stratified.csv",
    "figure_data/2_distribution_heatmap.csv",
    "figure_data/3_per_class_distances.csv",
    "figure_data/4_packet_sequence_shifts.csv",
)
INTEGRITY_ONLY_TABLES = (
    "cohort_inventory.csv: 360 unique_content_hashes cells and 160 separate train/validation rows",
    "primary_cohort_selectors.csv: 12 cohort_sha256 cells",
    "feature_inventory.csv: 28 declarative interpretation/exclusion rows",
    "traffic_distribution_methods.json: one declarative method record",
)
_FLAG_BITS = (
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
)


class RecomputeError(RuntimeError):
    """Raised when public rows or a recomputed table violate the contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecomputeError(message)


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            require(reader.fieldnames is not None, f"CSV header is absent: {path}")
            return list(reader.fieldnames), [dict(row) for row in reader]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise RecomputeError(f"cannot read {path}: {exc}") from exc


def _canonical(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        require(math.isfinite(value), "non-finite recomputed value")
        return format(value, ".12g")
    return str(value)


def _compare_rows(
    root: Path,
    relative: str,
    rows: Sequence[Mapping[str, Any]],
    *,
    fields: Sequence[str] | None = None,
) -> None:
    observed_fields, observed = _read_csv(root / relative)
    if fields is not None:
        require(observed_fields == list(fields), f"schema differs: {relative}")
    require(len(observed) == len(rows),
            f"row count differs for {relative}: {len(observed)} != {len(rows)}")
    for index, (published, recomputed) in enumerate(zip(observed, rows, strict=True), 2):
        require(set(published) == set(recomputed),
                f"field set differs at {relative}:{index}")
        for field, published_value in published.items():
            actual = _canonical(recomputed[field])
            require(published_value == actual,
                    f"value differs at {relative}:{index}:{field}: "
                    f"{published_value!r} != {actual!r}")


def _flag_value(pattern: str) -> int:
    if pattern == "NONE":
        return 0
    names = pattern.split("|")
    by_name = {name: bit for bit, name in _FLAG_BITS}
    require(names and len(names) == len(set(names)), "invalid TCP flag pattern")
    require(all(name in by_name for name in names), "unknown TCP flag name")
    value = sum(by_name[name] for name in names)
    canonical = "|".join(name for bit, name in _FLAG_BITS if value & bit) or "NONE"
    require(canonical == pattern, "TCP flag pattern is not canonical")
    return value


class PacketGroup:
    """Compact arrays for one public scope/configuration/class group."""

    __slots__ = (
        "session", "position", "frame", "ip_total", "payload", "ttl", "window",
        "iat", "direction", "flags", "sessions", "_cache",
    )

    def __init__(self) -> None:
        self.session = array("I")
        self.position = array("B")
        self.frame = array("I")
        self.ip_total = array("I")
        self.payload = array("I")
        self.ttl = array("B")
        self.window = array("I")
        self.iat = array("q")
        self.direction = array("b")
        self.flags = array("B")
        self.sessions: set[int] = set()
        self._cache: dict[str, np.ndarray] | None = None

    def append(self, session_id: int, row: Mapping[str, str]) -> None:
        self._cache = None
        self.sessions.add(session_id)
        self.session.append(session_id)
        self.position.append(int(row["position"]))
        self.frame.append(int(row["frame_length_bytes"]))
        self.ip_total.append(int(row["ip_total_length_bytes"]))
        self.payload.append(int(row["tcp_payload_length_bytes"]))
        self.ttl.append(int(row["ipv4_ttl"]))
        self.window.append(int(row["tcp_window_raw"]))
        self.iat.append(-1 if row["iat_us"] == "" else int(row["iat_us"]))
        self.direction.append(1 if row["direction"] == "c2s" else -1)
        self.flags.append(_flag_value(row["tcp_flag_pattern"]))

    @property
    def session_total(self) -> int:
        return len(self.sessions)

    def arrays(self) -> dict[str, np.ndarray]:
        if self._cache is None:
            self._cache = {
                "session": np.asarray(self.session, dtype=np.int64),
                "position": np.asarray(self.position, dtype=np.int16),
                "frame_length_bytes": np.asarray(self.frame, dtype=np.float64),
                "ip_total_length_bytes": np.asarray(self.ip_total, dtype=np.float64),
                "tcp_payload_length_bytes": np.asarray(self.payload, dtype=np.float64),
                "ipv4_ttl": np.asarray(self.ttl, dtype=np.float64),
                "tcp_window_raw": np.asarray(self.window, dtype=np.float64),
                "iat_us": np.asarray(self.iat, dtype=np.float64),
                "direction_code": np.asarray(self.direction, dtype=np.int8),
                "tcp_flags_value": np.asarray(self.flags, dtype=np.uint8),
            }
        return self._cache


def _load_observation_file(
    path: Path,
    scope: str,
    groups: dict[tuple[str, str, str, str], PacketGroup],
) -> tuple[int, int]:
    expected_rows = 179_089 if scope == PRIMARY_SCOPE else 845_137
    expected_sessions = 5_288 if scope == PRIMARY_SCOPE else 23_272
    seen_sessions: set[tuple[str, str, str, int]] = set()
    previous_session: tuple[str, str, str, int] | None = None
    previous_position = 0
    packet_count = 0
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            require(reader.fieldnames == list(OBSERVATION_FIELDS),
                    f"observation schema differs: {path.name}")
            for row in reader:
                packet_count += 1
                protocol = row["protocol_id"]
                if scope == ALL_SCOPE:
                    require(protocol == "general_2026",
                            "non-general row entered all-session sensitivity")
                session_id = int(row["session_view_index"])
                session_key = (
                    protocol, row["configuration_id"], row["class_name"], session_id,
                )
                position = int(row["position"])
                if session_key != previous_session:
                    require(session_key not in seen_sessions, "observation session is noncontiguous")
                    seen_sessions.add(session_key)
                    require(position == 1, "session does not begin at position one")
                    previous_position = 0
                    previous_session = session_key
                require(position == previous_position + 1,
                        "packet positions are not contiguous within a session")
                require(1 <= position <= 50, "packet position is outside 1..50")
                previous_position = position

                ip_length = int(row["ip_total_length_bytes"])
                frame_length = int(row["frame_length_bytes"])
                payload_length = int(row["tcp_payload_length_bytes"])
                require(payload_length == ip_length - 40, "payload-length identity differs")
                require(frame_length == max(60, ip_length + 14), "frame-length identity differs")
                require(row["direction"] in {"c2s", "s2c"}, "direction differs")
                require((position == 1) == (row["iat_us"] == ""),
                        "IAT missingness differs")
                if position > 1:
                    require(int(row["iat_us"]) >= 0, "negative IAT")
                require(1 <= int(row["ipv4_ttl"]) <= 255, "IPv4 TTL outside range")
                require(0 <= int(row["tcp_window_raw"]) <= 65_535,
                        "raw TCP window outside range")
                group_key = (scope, protocol, row["configuration_id"], row["class_name"])
                groups.setdefault(group_key, PacketGroup()).append(session_id, row)
    except (OSError, UnicodeDecodeError, csv.Error, ValueError) as exc:
        if isinstance(exc, RecomputeError):
            raise
        raise RecomputeError(f"cannot parse public observations {path}: {exc}") from exc
    require(packet_count == expected_rows, f"observation count differs: {path.name}")
    require(len(seen_sessions) == expected_sessions, f"session count differs: {path.name}")
    return packet_count, len(seen_sessions)


def load_observations(root: Path) -> tuple[dict[tuple[str, str, str, str], PacketGroup], dict[str, int]]:
    groups: dict[tuple[str, str, str, str], PacketGroup] = {}
    primary_packets, primary_sessions = _load_observation_file(
        root / "observations/packet_observations_heldout.csv.gz", PRIMARY_SCOPE, groups
    )
    all_packets, all_sessions = _load_observation_file(
        root / "observations/packet_observations_general_all_sessions.csv.gz", ALL_SCOPE, groups
    )
    require(len(groups) == 200, "public observation group count differs")
    return groups, {
        "primary_packets": primary_packets,
        "primary_sessions": primary_sessions,
        "all_session_packets": all_packets,
        "all_session_sessions": all_sessions,
    }


def _weights(session_ids: np.ndarray, estimator: str) -> np.ndarray:
    require(len(session_ids) > 0, "cannot weight empty observations")
    if estimator == "packet_pooled":
        return np.full(len(session_ids), 1.0 / len(session_ids), dtype=np.float64)
    require(estimator == "session_balanced", "unknown estimator")
    unique, inverse, counts = np.unique(session_ids, return_inverse=True, return_counts=True)
    return 1.0 / (float(len(unique)) * counts[inverse].astype(np.float64))


def _weighted_quantile(
    values: np.ndarray, weights: np.ndarray, quantile: float
) -> float:
    require(len(values) == len(weights) and len(values) > 0, "weighted quantile input differs")
    order = np.argsort(values, kind="mergesort")
    observed = values[order].astype(np.float64, copy=False)
    mass = weights[order].astype(np.float64, copy=False)
    cumulative = np.cumsum(mass)
    index = int(np.searchsorted(cumulative, quantile * float(cumulative[-1]), side="left"))
    return float(observed[min(index, len(observed) - 1)])


def _numeric_descriptive(values: np.ndarray, weights: np.ndarray) -> dict[str, float]:
    require(len(values) == len(weights) and len(values) > 0, "numeric descriptive input differs")
    normalized = weights / weights.sum()
    q10 = _weighted_quantile(values, weights, 0.10)
    q25 = _weighted_quantile(values, weights, 0.25)
    median = _weighted_quantile(values, weights, 0.50)
    q75 = _weighted_quantile(values, weights, 0.75)
    q90 = _weighted_quantile(values, weights, 0.90)
    return {
        "mean": float(np.sum(values * normalized)),
        "q10": q10,
        "q25": q25,
        "median": median,
        "q75": q75,
        "q90": q90,
        "iqr": q75 - q25,
        "minimum": float(np.min(values)),
        "maximum": float(np.max(values)),
    }


def _feature_values(
    group: PacketGroup,
    feature: str,
    *,
    direction_stratum: str = "all",
    position: int | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    data = group.arrays()
    mask = np.ones(len(data["session"]), dtype=bool)
    if direction_stratum == "c2s":
        mask &= data["direction_code"] == 1
    elif direction_stratum == "s2c":
        mask &= data["direction_code"] == -1
    else:
        require(direction_stratum == "all", "unknown direction stratum")
    if position is not None:
        mask &= data["position"] == position
    if feature == "direction":
        values = data["direction_code"]
    elif feature == "tcp_flag_pattern":
        values = data["tcp_flags_value"]
    elif feature == "signed_ip_total_length_bytes":
        values = data["ip_total_length_bytes"] * data["direction_code"]
    else:
        require(feature in NUMERIC_FEATURES, f"unknown feature: {feature}")
        values = data[feature]
        if feature == "iat_us":
            mask &= values >= 0
    return values[mask], data["session"][mask]


NUMERIC_DESCRIPTIVE_FIELDS = (
    "cohort_scope", "protocol_id", "configuration_id", "class_name", "estimator",
    "direction_stratum", "feature", "unit", "contributing_sessions", "observations",
    "mean", "q10", "q25", "median", "q75", "q90", "iqr", "minimum", "maximum",
)
CATEGORICAL_DESCRIPTIVE_FIELDS = (
    "cohort_scope", "protocol_id", "configuration_id", "class_name", "estimator",
    "feature", "category", "category_code", "termination_sensitive",
    "contributing_sessions", "observations", "weighted_prevalence",
)


def _flag_pattern(value: int) -> str:
    return "|".join(name for bit, name in _FLAG_BITS if value & bit) or "NONE"


def compute_group_descriptives(
    groups: Mapping[tuple[str, str, str, str], PacketGroup],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    numeric_rows: list[dict[str, Any]] = []
    categorical_rows: list[dict[str, Any]] = []
    for key in sorted(groups):
        scope, protocol, config, class_name = key
        group = groups[key]
        for estimator in ("session_balanced", "packet_pooled"):
            for stratum in ("all", "c2s", "s2c"):
                for feature in NUMERIC_FEATURES:
                    values, sessions = _feature_values(
                        group, feature, direction_stratum=stratum
                    )
                    if not len(values):
                        continue
                    desc = _numeric_descriptive(values, _weights(sessions, estimator))
                    divisor = 1000.0 if feature == "iat_us" else 1.0
                    numeric_rows.append({
                        "cohort_scope": scope,
                        "protocol_id": protocol,
                        "configuration_id": config,
                        "class_name": class_name,
                        "estimator": estimator,
                        "direction_stratum": stratum,
                        "feature": feature,
                        "unit": (
                            "milliseconds" if feature == "iat_us"
                            else "bytes" if "length" in feature else "raw_value"
                        ),
                        "contributing_sessions": int(len(np.unique(sessions))),
                        "observations": int(len(values)),
                        **{name: value / divisor for name, value in desc.items()},
                    })
            for feature in CATEGORICAL_FEATURES:
                values, sessions = _feature_values(group, feature)
                weights = _weights(sessions, estimator)
                weights = weights / weights.sum()
                for category in sorted(set(int(value) for value in values)):
                    categorical_rows.append({
                        "cohort_scope": scope,
                        "protocol_id": protocol,
                        "configuration_id": config,
                        "class_name": class_name,
                        "estimator": estimator,
                        "feature": feature,
                        "category": (
                            ("c2s" if category == 1 else "s2c")
                            if feature == "direction" else _flag_pattern(category)
                        ),
                        "category_code": category,
                        "termination_sensitive": (
                            feature == "tcp_flag_pattern" and bool(category & (0x01 | 0x04))
                        ),
                        "contributing_sessions": int(len(np.unique(sessions))),
                        "observations": int(len(values)),
                        "weighted_prevalence": float(weights[values == category].sum()),
                    })
    numeric_rows.sort(key=lambda row: tuple(str(row[field]) for field in (
        "cohort_scope", "protocol_id", "configuration_id", "class_name", "estimator",
        "direction_stratum", "feature",
    )))
    categorical_rows.sort(key=lambda row: tuple(str(row[field]) for field in (
        "cohort_scope", "protocol_id", "configuration_id", "class_name", "estimator",
        "feature", "category_code",
    )))
    require(len(numeric_rows) == 7_200, "numeric descriptive row count differs")
    require(len(categorical_rows) == 1_716, "categorical descriptive row count differs")
    return numeric_rows, categorical_rows


def _weighted_ks(
    left: np.ndarray,
    left_weights: np.ndarray,
    right: np.ndarray,
    right_weights: np.ndarray,
) -> float:
    left_order = np.argsort(left, kind="mergesort")
    right_order = np.argsort(right, kind="mergesort")
    left = left[left_order]
    right = right[right_order]
    left_mass = left_weights[left_order] / float(np.sum(left_weights))
    right_mass = right_weights[right_order] / float(np.sum(right_weights))
    support = np.union1d(left, right)
    left_cdf = np.searchsorted(left, support, side="right")
    right_cdf = np.searchsorted(right, support, side="right")
    left_cumulative = np.concatenate(([0.0], np.cumsum(left_mass)))
    right_cumulative = np.concatenate(([0.0], np.cumsum(right_mass)))
    return min(1.0, max(0.0, float(np.max(
        np.abs(left_cumulative[left_cdf] - right_cumulative[right_cdf])
    ))))


def _total_variation(
    left: np.ndarray,
    left_weights: np.ndarray,
    right: np.ndarray,
    right_weights: np.ndarray,
) -> float:
    left_pmf: defaultdict[int, float] = defaultdict(float)
    right_pmf: defaultdict[int, float] = defaultdict(float)
    left_total = math.fsum(float(value) for value in left_weights)
    right_total = math.fsum(float(value) for value in right_weights)
    for value, weight in zip(left, left_weights, strict=True):
        left_pmf[int(value)] += float(weight) / left_total
    for value, weight in zip(right, right_weights, strict=True):
        right_pmf[int(value)] += float(weight) / right_total
    distance = 0.5 * math.fsum(
        abs(left_pmf[value] - right_pmf[value])
        for value in set(left_pmf) | set(right_pmf)
    )
    return min(1.0, max(0.0, distance))


def _plain_summary(values: Sequence[float]) -> dict[str, Any]:
    data = np.asarray(values, dtype=np.float64)
    require(len(data) > 0 and np.all(np.isfinite(data)), "invalid summary values")
    q25, median, q75 = np.quantile(data, [0.25, 0.5, 0.75], method="linear")
    return {
        "count": int(len(data)),
        "mean": float(np.mean(data)),
        "median": float(median),
        "q25": float(q25),
        "q75": float(q75),
        "iqr": float(q75 - q25),
        "maximum": float(np.max(data)),
    }


def load_pairs(root: Path) -> list[dict[str, str]]:
    fields, pairs = _read_csv(root / "tables/configuration_pairs.csv")
    required = {
        "pair_id", "contrast", "contrast_type", "protocol_id",
        "left_configuration_id", "right_configuration_id",
    }
    require(required.issubset(fields), "configuration-pair schema differs")
    require(len(pairs) == 18 and len({row["pair_id"] for row in pairs}) == 18,
            "configuration-pair inventory differs")
    require({row["contrast"] for row in pairs} == set(CONTRASTS), "contrasts differ")
    return sorted(pairs, key=lambda row: row["pair_id"])


def validate_pair_and_cohort_metadata(
    root: Path,
    groups: Mapping[tuple[str, str, str, str], PacketGroup],
    pairs: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    directional_rows: list[dict[str, Any]] = []
    for pair in pairs:
        left = pair["left_configuration_id"]
        right = pair["right_configuration_id"]
        require(pair["unordered_configuration_key"] == "|".join(sorted((left, right))),
                f"unordered pair key differs: {pair['pair_id']}")
        left_classes = {
            key[3] for key in groups
            if key[:3] == (PRIMARY_SCOPE, pair["protocol_id"], left)
        }
        right_classes = {
            key[3] for key in groups
            if key[:3] == (PRIMARY_SCOPE, pair["protocol_id"], right)
        }
        require(int(pair["class_units"]) == len(left_classes & right_classes) == 10,
                f"pair class-unit count differs: {pair['pair_id']}")
        evaluation_ids = pair["directed_evaluation_ids"].split(";")
        directed_count = int(pair["directed_count"])
        require(len(evaluation_ids) == directed_count, "directed evaluation count differs")
        for offset, evaluation_id in enumerate(evaluation_ids):
            if offset == 0:
                source = pair["left_configuration_id"]
                target = pair["right_configuration_id"]
            else:
                require(directed_count == 2 and offset == 1, "unsupported directed mapping")
                source = pair["right_configuration_id"]
                target = pair["left_configuration_id"]
            directional_rows.append({
                "pair_id": pair["pair_id"],
                "condition": pair["contrast"],
                "contrast_type": pair["contrast_type"],
                "direction_index": offset + 1,
                "evaluation_id": evaluation_id,
                "source_configuration_id": source,
                "target_configuration_id": target,
                "protocol_id": pair["protocol_id"],
                "label_schema_id": pair["label_schema_id"],
            })
    require(len(directional_rows) == 34, "directional pair count differs")
    _compare_rows(root, "tables/directional_pair_mapping.csv", directional_rows)

    _, inventory = _read_csv(root / "tables/cohort_inventory.csv")
    require(len(inventory) == 360, "cohort inventory row count differs")
    inventory_groups: defaultdict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in inventory:
        inventory_groups[(
            row["cohort_scope"], row["protocol_id"], row["configuration_id"], row["class_name"]
        )].append(row)
        unique_count = int(row["unique_content_hashes"])
        require(0 < unique_count <= int(row["sessions"]), "unique-content count differs")
    require(set(inventory_groups) == set(groups), "cohort inventory group keys differ")

    schema_by_protocol: dict[str, str] = {}
    for pair in pairs:
        protocol = pair["protocol_id"]
        schema = pair["label_schema_id"]
        require(schema_by_protocol.setdefault(protocol, schema) == schema,
                f"inconsistent label schema: {protocol}")
    temporal_sources = {
        row["source_configuration_id"]
        for row in directional_rows if row["protocol_id"] == "temporal_2024_to_2026"
    }
    temporal_targets = {
        row["target_configuration_id"]
        for row in directional_rows if row["protocol_id"] == "temporal_2024_to_2026"
    }
    _, selectors = _read_csv(root / "tables/primary_cohort_selectors.csv")
    require(len(selectors) == 12, "primary selector count differs")
    selected_configs: set[tuple[str, str]] = set()
    for row in selectors:
        protocol = row["protocol_id"]
        config = row["configuration_id"]
        identity = (protocol, config)
        require(identity not in selected_configs, "duplicate primary selector")
        selected_configs.add(identity)
        observed_sessions = sum(
            group.session_total
            for key, group in groups.items()
            if key[:3] == (PRIMARY_SCOPE, protocol, config)
        )
        require(observed_sessions == int(row["sessions"]),
                f"selector session count differs: {protocol}/{config}")
        metadata = [
            item for item in inventory
            if item["cohort_scope"] == PRIMARY_SCOPE
            and item["protocol_id"] == protocol
            and item["configuration_id"] == config
        ]
        evaluation_roles = {item["evaluation_role"] for item in metadata}
        require(len(evaluation_roles) == 1, f"selector evaluation role is ambiguous: {config}")
        evaluation_role = next(iter(evaluation_roles))
        if protocol == "general_2026":
            cohort_role = "general_test"
        elif config in temporal_sources:
            cohort_role = "temporal_source_test"
        else:
            require(config in temporal_targets, f"temporal selector role differs: {config}")
            cohort_role = "temporal_target_test"
        expected = {
            "selector_id": f"{protocol}::{config}::test::{evaluation_role}",
            "cohort_role": cohort_role,
            "protocol_id": protocol,
            "label_schema_id": schema_by_protocol[protocol],
            "configuration_id": config,
            "split": "test",
            "evaluation_role": evaluation_role,
            "sessions": str(observed_sessions),
        }
        for field, value in expected.items():
            require(row[field] == value, f"selector field differs: {config}/{field}")
        digest = row["cohort_sha256"]
        require(len(digest) == 64 and all(char in "0123456789abcdef" for char in digest),
                "primary selector digest syntax differs")

    for key, group in groups.items():
        metadata = inventory_groups[key]
        data = group.arrays()
        _, packet_counts = np.unique(data["session"], return_counts=True)
        require(sum(int(row["sessions"]) for row in metadata) == group.session_total,
                f"cohort sessions differ: {key}")
        require(sum(int(row["packet_observations"]) for row in metadata) == len(data["session"]),
                f"cohort packet count differs: {key}")
        require(min(int(row["minimum_packets_per_session"]) for row in metadata)
                == int(np.min(packet_counts)), f"cohort minimum packet count differs: {key}")
        require(max(int(row["maximum_packets_per_session"]) for row in metadata)
                == int(np.max(packet_counts)), f"cohort maximum packet count differs: {key}")
        expected_rows = 3 if key[0] == ALL_SCOPE else 1
        require(len(metadata) == expected_rows, f"cohort split-row count differs: {key}")
        if key[0] == ALL_SCOPE:
            by_split = {row["split"]: row for row in metadata}
            require(set(by_split) == {"train", "validation", "test"},
                    f"general split inventory differs: {key}")
            primary_key = (PRIMARY_SCOPE, key[1], key[2], key[3])
            primary = groups[primary_key]
            primary_data = primary.arrays()
            _, primary_counts = np.unique(primary_data["session"], return_counts=True)
            test = by_split["test"]
            require(int(test["sessions"]) == primary.session_total,
                    f"test split sessions differ: {key}")
            require(int(test["packet_observations"]) == len(primary_data["session"]),
                    f"test split packets differ: {key}")
            require(int(test["minimum_packets_per_session"]) == int(np.min(primary_counts)),
                    f"test split minimum differs: {key}")
            require(int(test["maximum_packets_per_session"]) == int(np.max(primary_counts)),
                    f"test split maximum differs: {key}")
            remaining = [by_split["train"], by_split["validation"]]
            remaining_ids = np.asarray(
                [value for value in group.sessions if value not in primary.sessions],
                dtype=np.int64,
            )
            remaining_mask = np.isin(data["session"], remaining_ids)
            _, remaining_counts = np.unique(data["session"][remaining_mask], return_counts=True)
            require(sum(int(row["sessions"]) for row in remaining) == len(remaining_ids),
                    f"train/validation combined sessions differ: {key}")
            require(sum(int(row["packet_observations"]) for row in remaining)
                    == int(np.sum(remaining_mask)),
                    f"train/validation combined packets differ: {key}")
            require(min(int(row["minimum_packets_per_session"]) for row in remaining)
                    == int(np.min(remaining_counts)),
                    f"train/validation combined minimum differs: {key}")
            require(max(int(row["maximum_packets_per_session"]) for row in remaining)
                    == int(np.max(remaining_counts)),
                    f"train/validation combined maximum differs: {key}")

    feature_fields, feature_rows = _read_csv(root / "tables/feature_inventory.csv")
    require(len(feature_rows) == 28 and len(feature_fields) > 10,
            "declarative feature inventory differs")
    try:
        methods = json.loads(
            (root / "methods/traffic_distribution_methods.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecomputeError(f"cannot read public traffic methods: {exc}") from exc
    require(isinstance(methods, dict) and methods.get("version"),
            "declarative traffic methods differ")
    return {
        "directional_pair_rows": len(directional_rows),
        "selector_rows": len(selectors),
        "cohort_inventory_rows": len(inventory),
        "derived_cohort_rows": 200,
        "derived_test_split_rows": 80,
        "combined_train_validation_groups": 80,
        "irreducible_unique_content_cells": 360,
        "irreducible_train_validation_rows": 160,
        "irreducible_selector_digest_cells": 12,
        "declarative_feature_rows": len(feature_rows),
        "declarative_method_records": 1,
    }


MARGINAL_FIELDS = (
    "cohort_scope", "estimator", "direction_stratum", "pair_id", "contrast",
    "protocol_id", "left_configuration_id", "right_configuration_id", "class_name",
    "feature", "feature_kind", "distance_statistic", "distance", "left_sessions",
    "right_sessions", "left_observations", "right_observations",
    "secondary_direction_stratified",
)


def compute_marginal_distances(
    groups: Mapping[tuple[str, str, str, str], PacketGroup],
    pairs: Sequence[Mapping[str, str]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for scope in (PRIMARY_SCOPE, ALL_SCOPE):
        for pair in pairs:
            if scope == ALL_SCOPE and pair["contrast"] == "temporal":
                continue
            protocol = pair["protocol_id"]
            left_config = pair["left_configuration_id"]
            right_config = pair["right_configuration_id"]
            left_classes = {
                key[3] for key in groups if key[:3] == (scope, protocol, left_config)
            }
            right_classes = {
                key[3] for key in groups if key[:3] == (scope, protocol, right_config)
            }
            classes = sorted(left_classes & right_classes)
            require(len(classes) == 10, f"pair class coverage differs: {pair['pair_id']}")
            for class_name in classes:
                left_group = groups[(scope, protocol, left_config, class_name)]
                right_group = groups[(scope, protocol, right_config, class_name)]
                for estimator in ("session_balanced", "packet_pooled"):
                    for feature in NUMERIC_FEATURES:
                        for stratum in ("all", "c2s", "s2c"):
                            lv, ls = _feature_values(
                                left_group, feature, direction_stratum=stratum
                            )
                            rv, rs = _feature_values(
                                right_group, feature, direction_stratum=stratum
                            )
                            if not len(lv) or not len(rv):
                                continue
                            lw, rw = _weights(ls, estimator), _weights(rs, estimator)
                            rows.append({
                                "cohort_scope": scope,
                                "estimator": estimator,
                                "direction_stratum": stratum,
                                "pair_id": pair["pair_id"],
                                "contrast": pair["contrast"],
                                "protocol_id": protocol,
                                "left_configuration_id": left_config,
                                "right_configuration_id": right_config,
                                "class_name": class_name,
                                "feature": feature,
                                "feature_kind": "numeric",
                                "distance_statistic": "weighted_ks",
                                "distance": _weighted_ks(lv, lw, rv, rw),
                                "left_sessions": int(len(np.unique(ls))),
                                "right_sessions": int(len(np.unique(rs))),
                                "left_observations": int(len(lv)),
                                "right_observations": int(len(rv)),
                                "secondary_direction_stratified": stratum != "all",
                            })
                    for feature in CATEGORICAL_FEATURES:
                        lv, ls = _feature_values(left_group, feature)
                        rv, rs = _feature_values(right_group, feature)
                        lw, rw = _weights(ls, estimator), _weights(rs, estimator)
                        rows.append({
                            "cohort_scope": scope,
                            "estimator": estimator,
                            "direction_stratum": "all",
                            "pair_id": pair["pair_id"],
                            "contrast": pair["contrast"],
                            "protocol_id": protocol,
                            "left_configuration_id": left_config,
                            "right_configuration_id": right_config,
                            "class_name": class_name,
                            "feature": feature,
                            "feature_kind": "categorical",
                            "distance_statistic": "total_variation",
                            "distance": _total_variation(lv, lw, rv, rw),
                            "left_sessions": int(len(np.unique(ls))),
                            "right_sessions": int(len(np.unique(rs))),
                            "left_observations": int(len(lv)),
                            "right_observations": int(len(rv)),
                            "secondary_direction_stratified": False,
                        })
    rows.sort(key=lambda row: tuple(str(row[key]) for key in (
        "cohort_scope", "estimator", "direction_stratum", "pair_id", "class_name", "feature",
    )))
    require(len(rows) == 13_600, "within-class marginal row count differs")
    return rows


MARGINAL_SUMMARY_FIELDS = (
    "cohort_scope", "estimator", "direction_stratum", "feature", "contrast", "count",
    "mean", "median", "q25", "q75", "iqr", "maximum", "mean_ci_low",
    "mean_ci_high", "median_ci_low", "median_ci_high", "bootstrap_replicates",
    "bootstrap_master_seed",
)


def _bootstrap_summary(values: Sequence[float], group_key: str) -> dict[str, float]:
    observed = np.asarray(values, dtype=np.float64)
    require(len(observed) > 0 and np.all(np.isfinite(observed)), "bootstrap values differ")
    digest = hashlib.sha256(group_key.encode("utf-8")).digest()
    stream_words = np.frombuffer(digest[:16], dtype="<u4").astype(np.uint32).tolist()
    seed = np.random.SeedSequence([20_260_824, *stream_words])
    rng = np.random.Generator(np.random.PCG64(seed))
    selected = rng.integers(0, len(observed), size=(10_000, len(observed)))
    samples = observed[selected]
    replicate_means = np.mean(samples, axis=1)
    replicate_medians = np.median(samples, axis=1)
    mean_low, mean_high = np.quantile(replicate_means, [0.025, 0.975])
    median_low, median_high = np.quantile(replicate_medians, [0.025, 0.975])
    return {
        "mean_ci_low": float(mean_low),
        "mean_ci_high": float(mean_high),
        "median_ci_low": float(median_low),
        "median_ci_high": float(median_high),
    }


def compute_marginal_summaries(
    unit_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    buckets: defaultdict[tuple[str, str, str, str, str], list[float]] = defaultdict(list)
    for row in unit_rows:
        key = (
            str(row["cohort_scope"]), str(row["estimator"]),
            str(row["direction_stratum"]), str(row["feature"]), str(row["contrast"]),
        )
        buckets[key].append(float(row["distance"]))
    output: list[dict[str, Any]] = []
    for key in sorted(buckets):
        scope, estimator, stratum, feature, contrast = key
        values = buckets[key]
        output.append({
            "cohort_scope": scope,
            "estimator": estimator,
            "direction_stratum": stratum,
            "feature": feature,
            "contrast": contrast,
            **_plain_summary(values),
            **_bootstrap_summary(values, "|".join(key)),
            "bootstrap_replicates": 10_000,
            "bootstrap_master_seed": 20_260_824,
        })
    require(len(output) == 360, "marginal summary row count differs")
    return output


def compute_marginal_wide(
    summary_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    lookup = {
        (str(row["feature"]), str(row["contrast"])): row
        for row in summary_rows
        if row["cohort_scope"] == PRIMARY_SCOPE
        and row["estimator"] == "session_balanced"
        and row["direction_stratum"] == "all"
    }
    output: list[dict[str, Any]] = []
    for feature in PRIMARY_FEATURES:
        row: dict[str, Any] = {
            "feature": feature,
            "display_name": FEATURE_DISPLAY[feature],
        }
        for contrast in CONTRASTS:
            value = lookup[(feature, contrast)]
            row[f"{contrast}_mean"] = value["mean"]
            row[f"{contrast}_median"] = value["median"]
            row[f"{contrast}_units"] = value["count"]
        output.append(row)
    return output


def _average_ranks(values: Sequence[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: (item[1], item[0]))
    ranks = [0.0] * len(values)
    cursor = 0
    while cursor < len(indexed):
        end = cursor + 1
        while end < len(indexed) and indexed[end][1] == indexed[cursor][1]:
            end += 1
        rank = ((cursor + 1) + end) / 2.0
        for position in range(cursor, end):
            ranks[indexed[position][0]] = rank
        cursor = end
    return ranks


def _spearman(left: Sequence[float], right: Sequence[float]) -> float:
    x = _average_ranks(left)
    y = _average_ranks(right)
    mean_x = statistics.fmean(x)
    mean_y = statistics.fmean(y)
    covariance = math.fsum((a - mean_x) * (b - mean_y) for a, b in zip(x, y, strict=True))
    variance_x = math.fsum((value - mean_x) ** 2 for value in x)
    variance_y = math.fsum((value - mean_y) ** 2 for value in y)
    require(variance_x > 0 and variance_y > 0, "constant Spearman input")
    return max(-1.0, min(1.0, covariance / math.sqrt(variance_x * variance_y)))


def compute_all_session_sensitivity(
    summary_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    lookup = {
        (str(row["cohort_scope"]), str(row["feature"]), str(row["contrast"])): row
        for row in summary_rows
        if row["estimator"] == "session_balanced"
        and row["direction_stratum"] == "all"
        and row["contrast"] != "temporal"
    }
    ranked_features = tuple(FEATURE_FAMILY)
    output: list[dict[str, Any]] = []
    for contrast in CONTRASTS[:-1]:
        held = [lookup[(PRIMARY_SCOPE, feature, contrast)] for feature in PRIMARY_FEATURES]
        all_rows = [lookup[(ALL_SCOPE, feature, contrast)] for feature in PRIMARY_FEATURES]
        held_rank_values = [
            float(lookup[(PRIMARY_SCOPE, feature, contrast)]["median"])
            for feature in ranked_features
        ]
        all_rank_values = [
            float(lookup[(ALL_SCOPE, feature, contrast)]["median"])
            for feature in ranked_features
        ]
        # scipy.stats.rankdata(-values, method="average") without requiring SciPy.
        held_rank_list = _average_ranks([-value for value in held_rank_values])
        all_rank_list = _average_ranks([-value for value in all_rank_values])
        held_ranks = dict(zip(ranked_features, held_rank_list, strict=True))
        all_ranks = dict(zip(ranked_features, all_rank_list, strict=True))
        rank_rho = _spearman(held_rank_values, all_rank_values)
        held_top = {
            ranked_features[index]
            for index in np.argsort(np.asarray(held_rank_values))[-3:]
        }
        all_top = {
            ranked_features[index]
            for index in np.argsort(np.asarray(all_rank_values))[-3:]
        }
        for feature, held_row, all_row in zip(PRIMARY_FEATURES, held, all_rows, strict=True):
            held_median = float(held_row["median"])
            all_median = float(all_row["median"])
            output.append({
                "contrast": contrast,
                "feature": feature,
                "heldout_mean": held_row["mean"],
                "all_sessions_mean": all_row["mean"],
                "mean_difference_all_minus_heldout": (
                    float(all_row["mean"]) - float(held_row["mean"])
                ),
                "heldout_median": held_median,
                "all_sessions_median": all_median,
                "median_difference_all_minus_heldout": all_median - held_median,
                "median_ratio_all_over_heldout": (
                    all_median / held_median if held_median != 0 else None
                ),
                "rank_scope": (
                    "six_nonredundant_characteristics"
                    if feature in ranked_features else "not_applicable_redundant_size_field"
                ),
                "heldout_rank": held_ranks.get(feature),
                "all_sessions_rank": all_ranks.get(feature),
                "feature_rank_spearman_rho": rank_rho,
                "heldout_top3": feature in held_top,
                "all_sessions_top3": feature in all_top,
                "top3_overlap_count": len(held_top & all_top),
            })
    require(len(output) == 32, "all-session sensitivity row count differs")
    return output


FIRST40_CONTRIBUTOR_FIELDS = (
    "cohort_scope", "protocol_id", "configuration_id", "class_name", "position",
    "sessions_in_group", "contributing_sessions", "contributor_fraction",
)
FIRST40_UNIT_FIELDS = (
    "pair_id", "contrast", "protocol_id", "left_configuration_id",
    "right_configuration_id", "class_name", "position", "feature",
    "distance_statistic", "distance", "left_contributing_sessions",
    "right_contributing_sessions", "minimum_contributing_sessions", "support_status",
    "included_in_primary_summary",
)
FIRST40_SUMMARY_FIELDS = (
    "feature", "contrast", "position", "count", "mean", "median", "q25", "q75",
    "iqr", "maximum", "minimum_sessions_per_arm", "median_minimum_sessions_per_arm",
)
FIRST40_PERSISTENCE_FIELDS = (
    "feature", "contrast", "threshold", "supported_positions",
    "positions_at_or_above_threshold", "fraction_at_or_above_threshold",
    "longest_consecutive_run", "qualifying_positions",
)


def _longest_run(values: Iterable[int]) -> int:
    longest = current = 0
    previous: int | None = None
    for value in sorted(set(values)):
        current = current + 1 if previous is not None and value == previous + 1 else 1
        longest = max(longest, current)
        previous = value
    return longest


def compute_first40(
    groups: Mapping[tuple[str, str, str, str], PacketGroup],
    pairs: Sequence[Mapping[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    primary_groups = {key: group for key, group in groups.items() if key[0] == PRIMARY_SCOPE}
    contributor_rows: list[dict[str, Any]] = []
    for key in sorted(primary_groups):
        scope, protocol, config, class_name = key
        group = primary_groups[key]
        data = group.arrays()
        for position in range(1, 41):
            contributors = int(len(np.unique(data["session"][data["position"] == position])))
            contributor_rows.append({
                "cohort_scope": scope,
                "protocol_id": protocol,
                "configuration_id": config,
                "class_name": class_name,
                "position": position,
                "sessions_in_group": group.session_total,
                "contributing_sessions": contributors,
                "contributor_fraction": contributors / group.session_total,
            })

    unit_rows: list[dict[str, Any]] = []
    for pair in pairs:
        protocol = pair["protocol_id"]
        left_config = pair["left_configuration_id"]
        right_config = pair["right_configuration_id"]
        left_classes = {
            key[3] for key in primary_groups
            if key[:3] == (PRIMARY_SCOPE, protocol, left_config)
        }
        right_classes = {
            key[3] for key in primary_groups
            if key[:3] == (PRIMARY_SCOPE, protocol, right_config)
        }
        classes = sorted(left_classes & right_classes)
        require(len(classes) == 10, f"first-40 class coverage differs: {pair['pair_id']}")
        for class_name in classes:
            left = primary_groups[(PRIMARY_SCOPE, protocol, left_config, class_name)]
            right = primary_groups[(PRIMARY_SCOPE, protocol, right_config, class_name)]
            for position in range(1, 41):
                for feature in SEQUENTIAL_FEATURES:
                    lv, ls = _feature_values(left, feature, position=position)
                    rv, rs = _feature_values(right, feature, position=position)
                    n_left = int(len(np.unique(ls)))
                    n_right = int(len(np.unique(rs)))
                    minimum = min(n_left, n_right)
                    statistic = "total_variation" if feature == "direction" else "two_sample_ks"
                    if minimum < 2:
                        distance: float | None = None
                        status = "insufficient"
                    else:
                        lw = np.full(len(lv), 1.0 / len(lv), dtype=np.float64)
                        rw = np.full(len(rv), 1.0 / len(rv), dtype=np.float64)
                        distance = (
                            _total_variation(lv, lw, rv, rw)
                            if feature == "direction"
                            else _weighted_ks(lv, lw, rv, rw)
                        )
                        status = "primary_supported" if minimum >= 10 else "low_support"
                    unit_rows.append({
                        "pair_id": pair["pair_id"],
                        "contrast": pair["contrast"],
                        "protocol_id": protocol,
                        "left_configuration_id": left_config,
                        "right_configuration_id": right_config,
                        "class_name": class_name,
                        "position": position,
                        "feature": feature,
                        "distance_statistic": statistic,
                        "distance": distance,
                        "left_contributing_sessions": n_left,
                        "right_contributing_sessions": n_right,
                        "minimum_contributing_sessions": minimum,
                        "support_status": status,
                        "included_in_primary_summary": status == "primary_supported",
                    })

    summary_buckets: defaultdict[tuple[str, str, int], list[float]] = defaultdict(list)
    support_buckets: defaultdict[tuple[str, str, int], list[int]] = defaultdict(list)
    for row in unit_rows:
        if not row["included_in_primary_summary"]:
            continue
        key = (str(row["feature"]), str(row["contrast"]), int(row["position"]))
        summary_buckets[key].append(float(row["distance"]))
        support_buckets[key].append(int(row["minimum_contributing_sessions"]))
    summary_rows: list[dict[str, Any]] = []
    for feature, contrast, position in sorted(
        summary_buckets, key=lambda key: (key[0], CONTRASTS.index(key[1]), key[2])
    ):
        key = (feature, contrast, position)
        summary_rows.append({
            "feature": feature,
            "contrast": contrast,
            "position": position,
            **_plain_summary(summary_buckets[key]),
            "minimum_sessions_per_arm": min(support_buckets[key]),
            "median_minimum_sessions_per_arm": float(np.median(support_buckets[key])),
        })

    persistence_rows: list[dict[str, Any]] = []
    for feature in SEQUENTIAL_FEATURES:
        for contrast in CONTRASTS:
            group = [
                row for row in summary_rows
                if row["feature"] == feature and row["contrast"] == contrast
            ]
            # The public persistence table is derived from the serialized
            # first-40 summary, so apply the same 12-significant-digit boundary
            # before testing the 0.10/0.20 thresholds.
            supported = {
                int(row["position"]): float(_canonical(float(row["median"])))
                for row in group
            }
            require(supported, f"first-40 summary group absent: {feature}/{contrast}")
            for threshold in (0.1, 0.2):
                qualifying = sorted(
                    position for position, value in supported.items() if value >= threshold
                )
                persistence_rows.append({
                    "feature": feature,
                    "contrast": contrast,
                    "threshold": threshold,
                    "supported_positions": len(supported),
                    "positions_at_or_above_threshold": len(qualifying),
                    "fraction_at_or_above_threshold": len(qualifying) / len(supported),
                    "longest_consecutive_run": _longest_run(qualifying),
                    "qualifying_positions": ";".join(str(value) for value in qualifying),
                })
    contributor_rows.sort(key=lambda row: (
        row["protocol_id"], row["configuration_id"], row["class_name"], row["position"],
    ))
    unit_rows.sort(key=lambda row: (
        row["pair_id"], row["class_name"], row["feature"], row["position"],
    ))
    require(len(contributor_rows) == 4_800, "first-40 contributor count differs")
    require(len(unit_rows) == 43_200, "first-40 unit count differs")
    require(len(summary_rows) == 1_195, "first-40 summary count differs")
    require(len(persistence_rows) == 60, "first-40 persistence count differs")
    return contributor_rows, unit_rows, summary_rows, persistence_rows


def compute_pair_tables(
    marginal_rows: Sequence[Mapping[str, Any]],
    first40_units: Sequence[Mapping[str, Any]],
    pairs: Sequence[Mapping[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
           list[dict[str, Any]], list[dict[str, Any]]]:
    pair_lookup = {row["pair_id"]: row for row in pairs}
    buckets: defaultdict[tuple[str, str], list[float]] = defaultdict(list)
    for row in marginal_rows:
        if (
            row["cohort_scope"] == PRIMARY_SCOPE
            and row["estimator"] == "session_balanced"
            and row["direction_stratum"] == "all"
        ):
            buckets[(str(row["pair_id"]), str(row["feature"]))].append(
                float(row["distance"])
            )
    pair_feature_rows: list[dict[str, Any]] = []
    for (pair_id, feature), values in sorted(buckets.items()):
        pair = pair_lookup[pair_id]
        summary = _plain_summary(values)
        family = FEATURE_FAMILY.get(feature, "redundant_reported_only")
        pair_feature_rows.append({
            "pair_id": pair_id,
            "condition": pair["contrast"],
            "contrast_type": pair["contrast_type"],
            "configuration_a": pair["left_configuration_id"],
            "configuration_b": pair["right_configuration_id"],
            "feature": feature,
            "feature_family": family,
            "include_in_composite": feature in FEATURE_FAMILY,
            "class_count": summary["count"],
            "class_mean_distance": summary["mean"],
            "class_median_distance": summary["median"],
            "class_max_distance": summary["maximum"],
        })
    require(len(pair_feature_rows) == 18 * len(PRIMARY_FEATURES),
            "pair-feature row count differs")

    family_buckets: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in pair_feature_rows:
        if row["include_in_composite"]:
            family_buckets[(str(row["pair_id"]), str(row["feature_family"]))].append(row)
    family_rows: list[dict[str, Any]] = []
    for (pair_id, family), group in sorted(family_buckets.items()):
        first = group[0]
        family_rows.append({
            "pair_id": pair_id,
            "feature_family": family,
            "included_feature_count": len(group),
            "included_features": ";".join(sorted(str(row["feature"]) for row in group)),
            "condition": first["condition"],
            "contrast_type": first["contrast_type"],
            "configuration_a": first["configuration_a"],
            "configuration_b": first["configuration_b"],
            "family_mean_of_class_mean_distance": statistics.fmean(
                float(row["class_mean_distance"]) for row in group
            ),
            "family_mean_of_class_median_distance": statistics.fmean(
                float(row["class_median_distance"]) for row in group
            ),
            "family_mean_of_class_max_distance": statistics.fmean(
                float(row["class_max_distance"]) for row in group
            ),
        })
    require(len(family_rows) == 18 * 4, "pair-family row count differs")
    by_pair: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in family_rows:
        by_pair[str(row["pair_id"])].append(row)
    composite_rows: list[dict[str, Any]] = []
    for pair_id in sorted(by_pair):
        group = by_pair[pair_id]
        require({row["feature_family"] for row in group} == set(COMPOSITE_FAMILIES),
                f"composite family coverage differs: {pair_id}")
        first = group[0]
        composite_rows.append({
            "pair_id": pair_id,
            "family_count": 4,
            "overall_marginal_composite_mean": statistics.fmean(
                float(row["family_mean_of_class_mean_distance"]) for row in group
            ),
            "overall_marginal_composite_median_sensitivity": statistics.fmean(
                float(row["family_mean_of_class_median_distance"]) for row in group
            ),
            "overall_marginal_composite_max_sensitivity": statistics.fmean(
                float(row["family_mean_of_class_max_distance"]) for row in group
            ),
            "condition": first["condition"],
            "contrast_type": first["contrast_type"],
            "configuration_a": first["configuration_a"],
            "configuration_b": first["configuration_b"],
        })

    position_buckets: defaultdict[tuple[str, str, int], list[float]] = defaultdict(list)
    for row in first40_units:
        if row["included_in_primary_summary"]:
            position_buckets[(
                str(row["pair_id"]), str(row["feature"]), int(row["position"])
            )].append(float(_canonical(float(row["distance"]))))
    sequential_feature_rows: list[dict[str, Any]] = []
    for pair in pairs:
        pair_id = pair["pair_id"]
        for feature in SEQUENTIAL_FEATURES:
            positions: list[int] = []
            position_means: list[float] = []
            for position in range(1, 41):
                values = position_buckets.get((pair_id, feature, position), [])
                if values:
                    positions.append(position)
                    position_means.append(statistics.fmean(values))
            require(position_means, f"sequential rows absent: {pair_id}/{feature}")
            sequential_feature_rows.append({
                "pair_id": pair_id,
                "condition": pair["contrast"],
                "feature": feature,
                "supported_positions": len(positions),
                "first_supported_position": min(positions),
                "last_supported_position": max(positions),
                "mean_of_position_class_mean_distances": statistics.fmean(position_means),
                "median_of_position_class_mean_distances": statistics.median(position_means),
                "maximum_position_class_mean_distance": max(position_means),
            })
    sequential_composite_rows: list[dict[str, Any]] = []
    by_pair_sequence: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sequential_feature_rows:
        by_pair_sequence[str(row["pair_id"])].append(row)
    for pair_id in sorted(by_pair_sequence):
        group = by_pair_sequence[pair_id]
        sequential_composite_rows.append({
            "pair_id": pair_id,
            "condition": group[0]["condition"],
            "sequential_feature_count": len(group),
            "overall_sequential_composite_mean": statistics.fmean(
                float(_canonical(float(row["mean_of_position_class_mean_distances"])))
                for row in group
            ),
            "overall_sequential_composite_median_sensitivity": statistics.fmean(
                float(_canonical(float(row["median_of_position_class_mean_distances"])))
                for row in group
            ),
        })
    require(len(composite_rows) == 18, "pair composite count differs")
    require(len(sequential_feature_rows) == 108, "sequential pair-feature count differs")
    require(len(sequential_composite_rows) == 18, "sequential composite count differs")
    return (
        pair_feature_rows, family_rows, composite_rows,
        sequential_feature_rows, sequential_composite_rows,
    )


def _validate_figure_data(
    root: Path,
    marginal_rows: Sequence[Mapping[str, Any]],
    summary_rows: Sequence[Mapping[str, Any]],
    first40_summary: Sequence[Mapping[str, Any]],
) -> None:
    per_class = [
        {
            "pair_id": row["pair_id"],
            "contrast": row["contrast"],
            "class_name": row["class_name"],
            "feature": row["feature"],
            "distance": row["distance"],
        }
        for row in marginal_rows
        if row["cohort_scope"] == PRIMARY_SCOPE
        and row["estimator"] == "session_balanced"
        and row["direction_stratum"] == "all"
        and row["feature"] in NONREDUNDANT_FEATURES
    ]
    require(len(per_class) == 1_080, "per-class figure row count differs")
    _compare_rows(root, "figure_data/3_per_class_distances.csv", per_class)
    _compare_rows(
        root, "figure_data/4_packet_sequence_shifts.csv", first40_summary,
        fields=FIRST40_SUMMARY_FIELDS,
    )

    buckets: defaultdict[tuple[str, str], list[float]] = defaultdict(list)
    for row in per_class:
        buckets[(str(row["feature"]), str(row["contrast"]))].append(float(row["distance"]))
    source_fields, source_rows = _read_csv(root / "figure_data/2_distribution_heatmap.csv")
    require(len(source_rows) == 30, "heatmap figure row count differs")
    heat_rows: list[dict[str, Any]] = []
    for published in source_rows:
        feature = published["feature"]
        contrast = published["contrast"]
        values = buckets[(feature, contrast)]
        summary = _plain_summary(values)
        heat_rows.append({
            "feature": feature,
            "display_name": published["display_name"],
            "contrast": contrast,
            "contrast_display": published["contrast_display"],
            "median_distance": summary["median"],
            "mean_distance": summary["mean"],
            "class_pair_units": summary["count"],
        })
    _compare_rows(
        root, "figure_data/2_distribution_heatmap.csv", heat_rows, fields=source_fields
    )

    direction_rows = [
        {
            "feature": row["feature"],
            "display_name": FEATURE_DISPLAY[str(row["feature"])],
            "contrast": row["contrast"],
            "contrast_display": CONTRAST_DISPLAY[str(row["contrast"])],
            "direction_stratum": row["direction_stratum"],
            "median_distance": row["median"],
            "mean_distance": row["mean"],
            "class_pair_units": row["count"],
        }
        for row in summary_rows
        if row["cohort_scope"] == PRIMARY_SCOPE
        and row["estimator"] == "session_balanced"
        and row["direction_stratum"] in {"c2s", "s2c"}
    ]
    require(len(direction_rows) == 60, "direction-stratified figure row count differs")
    _compare_rows(root, "tables/figure_data_direction_stratified.csv", direction_rows)


def recompute_and_verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    require(root.is_dir(), f"traffic-distribution root is absent: {root}")
    groups, counts = load_observations(root)
    pairs = load_pairs(root)
    metadata_validation = validate_pair_and_cohort_metadata(root, groups, pairs)
    numeric_rows, categorical_rows = compute_group_descriptives(groups)
    _compare_rows(
        root, "tables/numeric_group_descriptives.csv", numeric_rows,
        fields=NUMERIC_DESCRIPTIVE_FIELDS,
    )
    _compare_rows(
        root, "tables/categorical_group_descriptives.csv", categorical_rows,
        fields=CATEGORICAL_DESCRIPTIVE_FIELDS,
    )
    marginal_rows = compute_marginal_distances(groups, pairs)
    _compare_rows(
        root, "tables/within_class_marginal_distances.csv", marginal_rows,
        fields=MARGINAL_FIELDS,
    )
    direction_rows = [row for row in marginal_rows if row["direction_stratum"] != "all"]
    _compare_rows(
        root, "tables/direction_stratified_marginal_distances.csv", direction_rows,
        fields=MARGINAL_FIELDS,
    )
    marginal_summaries = compute_marginal_summaries(marginal_rows)
    _compare_rows(
        root, "tables/marginal_shift_summary_long.csv", marginal_summaries,
        fields=MARGINAL_SUMMARY_FIELDS,
    )
    marginal_wide = compute_marginal_wide(marginal_summaries)
    _compare_rows(root, "tables/marginal_shift_summary_wide.csv", marginal_wide)
    packet_pooled = [
        row for row in marginal_summaries if row["estimator"] == "packet_pooled"
    ]
    require(len(packet_pooled) == 180, "packet-pooled summary count differs")
    _compare_rows(
        root, "tables/packet_pooled_sensitivity.csv", packet_pooled,
        fields=MARGINAL_SUMMARY_FIELDS,
    )
    all_session_sensitivity = compute_all_session_sensitivity(marginal_summaries)
    _compare_rows(
        root, "tables/general_all_session_sensitivity.csv", all_session_sensitivity
    )

    contributors, units, summaries, persistence = compute_first40(groups, pairs)
    _compare_rows(
        root, "tables/first40_contributors.csv", contributors,
        fields=FIRST40_CONTRIBUTOR_FIELDS,
    )
    _compare_rows(root, "tables/first40_unit_distances.csv", units, fields=FIRST40_UNIT_FIELDS)
    _compare_rows(
        root, "tables/first40_position_summaries.csv", summaries,
        fields=FIRST40_SUMMARY_FIELDS,
    )
    _compare_rows(
        root, "tables/first40_persistence.csv", persistence,
        fields=FIRST40_PERSISTENCE_FIELDS,
    )

    pair_tables = compute_pair_tables(marginal_rows, units, pairs)
    pair_paths = (
        "tables/pair_feature_shifts.csv",
        "tables/pair_family_shifts.csv",
        "tables/pair_marginal_composites.csv",
        "tables/pair_sequential_feature_shifts.csv",
        "tables/pair_sequential_composites.csv",
    )
    for relative, rows in zip(pair_paths, pair_tables, strict=True):
        _compare_rows(root, relative, rows)
    _validate_figure_data(root, marginal_rows, marginal_summaries, summaries)
    return {
        "status": "recomputed_and_verified",
        "version": VERSION,
        "observation_counts": counts,
        "configuration_pairs": len(pairs),
        "marginal_unit_rows": len(marginal_rows),
        "marginal_summary_rows": len(marginal_summaries),
        "numeric_descriptive_rows": len(numeric_rows),
        "categorical_descriptive_rows": len(categorical_rows),
        "first40_unit_rows": len(units),
        "metadata_validation": metadata_validation,
        "recomputed_tables": list(RECOMPUTED_TABLES),
        "integrity_only_scope": list(INTEGRITY_ONLY_TABLES),
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = recompute_and_verify(args.root)
    except RecomputeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
