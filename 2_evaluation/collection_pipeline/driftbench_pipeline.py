#!/usr/bin/env python3
"""
This self-contained CLI provides safe reference implementations for collection orchestration, Ethernet/IPv4/TCP sessionization, exact-allowlist SNI annotation, deterministic parent/content-hash-grouped 70:15:15 selection, the canonical DriftBench sanitizer, and independent manifest verification.

The canonical sanitization and payload-start implementations are embedded in this file.

Every mutating command publishes a new directory through a sibling staging directory and refuses an existing destination. Source captures are opened read-only and are never moved, renamed, or deleted.

"""

from __future__ import annotations

import argparse
import contextlib
import csv
import ctypes
import dataclasses
import errno
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import types
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit


PIPELINE_VERSION = "driftbench-open-science-pipeline-v1"
SPLIT_VERSION = "driftbench-reference-split-v1"
PCAP_LINKTYPE_ETHERNET = 1
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

COLLECTION_FIELDS = (
    "visit_id",
    "parent_group_id",
    "campaign",
    "configuration_id",
    "os",
    "browser",
    "network",
    "class_name",
    "page_id",
    "url",
    "repetition",
    "os_version",
    "environment_image_digest",
    "capture_interface",
    "capture_binary",
    "capture_binary_version",
    "capture_binary_sha256",
    "browser_binary",
    "browser_version",
    "browser_binary_sha256",
    "driver_binary",
    "driver_version",
    "driver_binary_sha256",
    "sessionizer_binary",
    "sessionizer_version",
    "sessionizer_binary_sha256",
    "sessionizer_compatibility",
)

PAGE_INVENTORY_VERSION = "driftbench-page-inventory-v1"
CONFIGURATION_INVENTORY_VERSION = "driftbench-configuration-inventory-v1"
RETRY_REASONS = frozenset(
    {
        "capture_launch_failed",
        "capture_exited_before_visit",
        "visit_launch_failed",
        "visit_timeout",
        "visit_command_failed",
        "capture_missing_or_empty",
        "capture_stop_failed",
    }
)
CONFIGURATION_FIELDS = (
    "configuration_id",
    "campaign",
    "os",
    "os_version",
    "browser",
    "browser_version",
    "network",
    "capture_interface",
    "capture_binary",
    "capture_binary_version",
    "capture_binary_sha256",
    "browser_binary",
    "browser_binary_sha256",
    "driver_binary",
    "driver_version",
    "driver_binary_sha256",
    "sessionizer_binary",
    "sessionizer_version",
    "sessionizer_binary_sha256",
    "sessionizer_compatibility",
    "environment_image_digest",
    "enabled",
)


class PipelineError(RuntimeError):
    """Raised when a pipeline contract is violated."""


class PipelineConfig(dict[str, object]):
    """Validated campaign mapping carrying its non-serialized source path."""

    def __init__(self, value: Mapping[str, object], source_path: Path):
        super().__init__(value)
        self.source_path = source_path


@dataclasses.dataclass(frozen=True)
class PcapRecord:
    index: int
    raw_record: bytes
    frame: bytes


@dataclasses.dataclass(frozen=True)
class ParsedPcap:
    global_header: bytes
    endian: str
    records: tuple[PcapRecord, ...]


@dataclasses.dataclass(frozen=True)
class TcpPacket:
    source_ip: bytes
    destination_ip: bytes
    source_port: int
    destination_port: int
    sequence: int
    flags: int
    payload: bytes

    @property
    def flow_key(self) -> tuple[tuple[bytes, int], tuple[bytes, int]]:
        endpoints = sorted(
            (
                (self.source_ip, self.source_port),
                (self.destination_ip, self.destination_port),
            )
        )
        return endpoints[0], endpoints[1]

    @property
    def direction_key(self) -> tuple[bytes, int, bytes, int]:
        return (
            self.source_ip,
            self.source_port,
            self.destination_ip,
            self.destination_port,
        )


@dataclasses.dataclass
class SessionBuffer:
    records: list[PcapRecord]
    first_record_index: int
    initial_syn_sequence: int | None


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_safe_component(value: str, field: str) -> str:
    if not SAFE_COMPONENT.fullmatch(value):
        raise PipelineError(f"invalid {field}: {value!r}")
    return value


def _normalize_hostname(value: str) -> str:
    normalized = value.strip().rstrip(".").lower()
    if not normalized or len(normalized) > 253:
        raise PipelineError(f"invalid hostname: {value!r}")
    try:
        ascii_name = normalized.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PipelineError(f"invalid hostname: {value!r}") from exc
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        raise PipelineError(f"invalid hostname: {value!r}")
    return ascii_name


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise PipelineError(f"duplicate JSON object key: {key!r}")
        output[key] = value
    return output


def _read_json_object(path: Path, label: str) -> tuple[dict[str, object], str]:
    if path.is_symlink():
        raise PipelineError(f"{label} must not be a symlink: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PipelineError(f"cannot read {label} {path}: {exc}") from exc
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, PipelineError) as exc:
        raise PipelineError(f"invalid JSON {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"{label} root must be a JSON object")
    return value, sha256_bytes(raw)


def _require_exact_keys(
    value: Mapping[str, object], required: Iterable[str], optional: Iterable[str], label: str
) -> None:
    required_keys = set(required)
    allowed = required_keys | set(optional)
    missing = required_keys - set(value)
    unexpected = set(value) - allowed
    if missing:
        raise PipelineError(f"{label} missing fields: {sorted(missing)}")
    if unexpected:
        raise PipelineError(f"{label} has unexpected fields: {sorted(unexpected)}")


def _relative_config_path(config: Mapping[str, object], field: str) -> Path:
    raw = config.get(field)
    if not isinstance(raw, str) or not raw:
        raise PipelineError(f"config.{field} must be a non-empty relative path")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise PipelineError(f"config.{field} must be a contained relative path")
    source_path = getattr(config, "source_path", None)
    if not isinstance(source_path, Path):
        raise PipelineError("config source path is unavailable")
    return (source_path.parent / path).resolve()


def _number(
    value: object, label: str, *, minimum: float, exclusive_minimum: bool = False
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PipelineError(f"{label} must be numeric")
    result = float(value)
    if (exclusive_minimum and result <= minimum) or (
        not exclusive_minimum and result < minimum
    ):
        comparison = "greater than" if exclusive_minimum else "at least"
        raise PipelineError(f"{label} must be {comparison} {minimum}")
    return result


def load_config(path: Path) -> tuple[dict[str, object], str]:
    raw = path.read_bytes()
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, PipelineError) as exc:
        raise PipelineError(f"invalid JSON config {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PipelineError("config root must be a JSON object")
    config = PipelineConfig(parsed, path.resolve())
    _require_exact_keys(
        config,
        (
            "schema_version",
            "campaign_id",
            "page_inventory",
            "configuration_inventory",
            "schedule",
            "repetitions_per_page",
            "collection",
            "annotation",
            "selection",
            "sanitization",
        ),
        ("$schema",),
        "config",
    )
    if config.get("schema_version") != PIPELINE_VERSION:
        raise PipelineError(
            f"config schema_version must be {PIPELINE_VERSION!r}"
        )
    if not isinstance(config["campaign_id"], str):
        raise PipelineError("config.campaign_id must be a string")
    _require_safe_component(config["campaign_id"], "campaign_id")
    for field in ("page_inventory", "configuration_inventory", "schedule"):
        _relative_config_path(config, field)
    repetitions = config["repetitions_per_page"]
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions < 1:
        raise PipelineError("config.repetitions_per_page must be a positive integer")
    collection = config["collection"]
    if not isinstance(collection, dict):
        raise PipelineError("config.collection must be an object")
    _require_exact_keys(
        collection,
        (
            "capture_command",
            "visit_command",
            "capture_ready_seconds",
            "post_visit_seconds",
            "visit_timeout_seconds",
            "capture_stop_timeout_seconds",
            "environment",
            "retry_policy",
        ),
        (),
        "config.collection",
    )
    for field in ("capture_command", "visit_command"):
        template = collection[field]
        if not isinstance(template, list) or not template or not all(
            isinstance(item, str) and item for item in template
        ):
            raise PipelineError(f"config.collection.{field} must be a command array")
    capture_text = "\0".join(collection["capture_command"])
    visit_text = "\0".join(collection["visit_command"])
    for placeholder in ("{capture_binary}", "{capture_interface}", "{capture_path}"):
        if placeholder not in capture_text:
            raise PipelineError(f"collection.capture_command must contain {placeholder}")
    for placeholder in ("{browser_binary}", "{driver_binary}", "{url}"):
        if placeholder not in visit_text:
            raise PipelineError(f"collection.visit_command must contain {placeholder}")
    _number(collection["capture_ready_seconds"], "capture_ready_seconds", minimum=0)
    _number(collection["post_visit_seconds"], "post_visit_seconds", minimum=0)
    _number(
        collection["visit_timeout_seconds"],
        "visit_timeout_seconds",
        minimum=0,
        exclusive_minimum=True,
    )
    _number(
        collection["capture_stop_timeout_seconds"],
        "capture_stop_timeout_seconds",
        minimum=0,
        exclusive_minimum=True,
    )
    environment = collection["environment"]
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in environment.items()
    ):
        raise PipelineError("collection.environment must map strings to strings")
    retry = collection["retry_policy"]
    if not isinstance(retry, dict):
        raise PipelineError("collection.retry_policy must be an object")
    _require_exact_keys(
        retry,
        ("max_attempts", "backoff_seconds", "retryable_reasons"),
        (),
        "collection.retry_policy",
    )
    max_attempts = retry["max_attempts"]
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
        raise PipelineError("retry_policy.max_attempts must be a positive integer")
    _number(retry["backoff_seconds"], "retry_policy.backoff_seconds", minimum=0)
    reasons = retry["retryable_reasons"]
    if not isinstance(reasons, list) or not all(isinstance(item, str) for item in reasons):
        raise PipelineError("retry_policy.retryable_reasons must be a string array")
    if len(reasons) != len(set(reasons)) or not set(reasons) <= RETRY_REASONS:
        raise PipelineError("retry_policy.retryable_reasons contains duplicates or unknown values")
    return config, sha256_bytes(raw)


def annotation_allowlist(config: Mapping[str, object]) -> dict[str, str]:
    section = config.get("annotation")
    if not isinstance(section, dict):
        raise PipelineError("config.annotation must be an object")
    raw = section.get("allowlist")
    if isinstance(raw, list):
        pairs = [(item, item) for item in raw]
    elif isinstance(raw, dict):
        pairs = list(raw.items())
    else:
        raise PipelineError("config.annotation.allowlist must be a list or object")
    output: dict[str, str] = {}
    for raw_sni, raw_class in pairs:
        if not isinstance(raw_sni, str) or not isinstance(raw_class, str):
            raise PipelineError("allowlist hostnames and class names must be strings")
        sni = _normalize_hostname(raw_sni)
        class_name = _require_safe_component(raw_class, "allowlist class name")
        if sni in output:
            raise PipelineError(f"duplicate normalized allowlist SNI: {sni}")
        output[sni] = class_name
    if not output:
        raise PipelineError("annotation allowlist must not be empty")
    return output


def read_csv(path: Path, required: Iterable[str] = ()) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise PipelineError(f"CSV has no header: {path}")
        missing = set(required) - set(reader.fieldnames)
        if missing:
            raise PipelineError(f"{path} missing fields: {sorted(missing)}")
        rows = list(reader)
    return rows


def write_csv(
    path: Path, rows: Sequence[Mapping[str, object]], fieldnames: Sequence[str]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _publish_directory_noreplace(staging: Path, destination: Path) -> None:
    """Atomically publish one sibling directory without replacing a winner."""

    if staging.parent.resolve() != destination.parent.resolve():
        raise PipelineError("staging and destination must share a parent")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise PipelineError("Linux renameat2 is required for no-clobber publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(staging),
        -100,
        os.fsencode(destination),
        1,  # RENAME_NOREPLACE
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise PipelineError(f"refusing existing destination: {destination}")
        raise PipelineError(f"atomic publication failed with errno {error}")
    parent_fd = os.open(
        destination.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _fsync_tree(root: Path) -> None:
    """Make all staged regular files and directories durable before rename."""

    directories = [root]
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PipelineError(f"staged output unexpectedly contains a symlink: {path}")
        if path.is_dir():
            directories.append(path)
        elif path.is_file():
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


@contextlib.contextmanager
def staged_directory(destination: Path) -> Iterator[Path]:
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise PipelineError(f"refusing existing destination: {destination}")
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.staging.", dir=destination.parent
        )
    )
    try:
        yield staging
        _fsync_tree(staging)
        _publish_directory_noreplace(staging, destination)
    except BaseException:
        # Preserve the staging directory for diagnosis.  In particular, never
        # delete partially captured source traffic after a failed command.
        raise


def _portable_path(path: Path, destination: Path) -> str:
    return Path(os.path.relpath(path.resolve(), destination.resolve())).as_posix()


def _resolve_pcap(manifest: Path, row: Mapping[str, str]) -> Path:
    raw_path = row.get("pcap_path", "")
    if not raw_path:
        raise PipelineError("manifest row has no pcap_path")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = manifest.parent / candidate
    if candidate.is_symlink():
        raise PipelineError(f"PCAP symlinks are not accepted: {candidate}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PipelineError(f"missing PCAP: {candidate}") from exc
    if not resolved.is_file():
        raise PipelineError(f"PCAP is not a regular file: {resolved}")
    expected = row.get("pcap_sha256", "")
    if not SHA256_PATTERN.fullmatch(expected):
        raise PipelineError(f"invalid declared PCAP SHA-256: {expected!r}")
    observed = sha256_file(resolved)
    if observed != expected:
        raise PipelineError(f"PCAP hash mismatch: {resolved}")
    return resolved


def parse_classic_pcap(raw: bytes) -> ParsedPcap:
    magic_to_endian = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    if len(raw) < 24 or raw[:4] not in magic_to_endian:
        raise PipelineError("expected classic PCAP")
    endian = magic_to_endian[raw[:4]]
    if struct.unpack_from(f"{endian}I", raw, 20)[0] != PCAP_LINKTYPE_ETHERNET:
        raise PipelineError("expected Ethernet PCAP link type")
    cursor = 24
    records: list[PcapRecord] = []
    while cursor < len(raw):
        if cursor + 16 > len(raw):
            raise PipelineError("truncated PCAP record header")
        captured_length = struct.unpack_from(f"{endian}I", raw, cursor + 8)[0]
        frame_start = cursor + 16
        frame_end = frame_start + captured_length
        if frame_end > len(raw):
            raise PipelineError("truncated PCAP frame")
        records.append(
            PcapRecord(
                index=len(records),
                raw_record=raw[cursor:frame_end],
                frame=raw[frame_start:frame_end],
            )
        )
        cursor = frame_end
    if not records:
        raise PipelineError("empty PCAP")
    return ParsedPcap(raw[:24], endian, tuple(records))


def parse_ipv4_tcp(frame: bytes) -> TcpPacket | None:
    if len(frame) < 14:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    ip_start = 14
    while ether_type in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < ip_start + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, ip_start + 2)[0]
        ip_start += 4
    if ether_type != 0x0800 or len(frame) < ip_start + 20:
        return None
    version_ihl = frame[ip_start]
    ihl = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or ihl < 20 or len(frame) < ip_start + ihl:
        return None
    total_length = struct.unpack_from("!H", frame, ip_start + 2)[0]
    fragment = struct.unpack_from("!H", frame, ip_start + 6)[0]
    if frame[ip_start + 9] != 6 or fragment & 0x3FFF:
        return None
    ip_end = ip_start + total_length
    if total_length < ihl + 20 or ip_end > len(frame):
        return None
    tcp_start = ip_start + ihl
    tcp_header_length = (frame[tcp_start + 12] >> 4) * 4
    if tcp_header_length < 20 or tcp_start + tcp_header_length > ip_end:
        return None
    return TcpPacket(
        source_ip=frame[ip_start + 12 : ip_start + 16],
        destination_ip=frame[ip_start + 16 : ip_start + 20],
        source_port=struct.unpack_from("!H", frame, tcp_start)[0],
        destination_port=struct.unpack_from("!H", frame, tcp_start + 2)[0],
        sequence=struct.unpack_from("!I", frame, tcp_start + 4)[0],
        flags=frame[tcp_start + 13],
        payload=frame[tcp_start + tcp_header_length : ip_end],
    )


def sessionize_pcap(raw: bytes) -> tuple[bytes, list[SessionBuffer], int]:
    parsed = parse_classic_pcap(raw)
    active: dict[
        tuple[tuple[bytes, int], tuple[bytes, int]], SessionBuffer
    ] = {}
    sessions: list[SessionBuffer] = []
    skipped = 0
    for record in parsed.records:
        packet = parse_ipv4_tcp(record.frame)
        if packet is None:
            skipped += 1
            continue
        key = packet.flow_key
        syn_without_ack = bool(packet.flags & TCP_SYN) and not bool(
            packet.flags & TCP_ACK
        )
        current = active.get(key)
        is_syn_retransmission = (
            current is not None
            and syn_without_ack
            and current.initial_syn_sequence == packet.sequence
        )
        if current is None or (syn_without_ack and not is_syn_retransmission):
            current = SessionBuffer(
                records=[],
                first_record_index=record.index,
                initial_syn_sequence=packet.sequence if syn_without_ack else None,
            )
            sessions.append(current)
            active[key] = current
        current.records.append(record)
    sessions.sort(key=lambda item: item.first_record_index)
    return parsed.global_header, sessions, skipped


def _pcap_for_records(global_header: bytes, records: Sequence[PcapRecord]) -> bytes:
    return global_header + b"".join(record.raw_record for record in records)


def _template_command(template: object, context: Mapping[str, str], field: str) -> list[str]:
    if not isinstance(template, list) or not template or not all(
        isinstance(item, str) and item for item in template
    ):
        raise PipelineError(f"{field} must be a non-empty list of strings")
    try:
        return [item.format_map(context) for item in template]
    except KeyError as exc:
        raise PipelineError(f"unknown template field in {field}: {exc}") from exc


def _validate_https_url(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise PipelineError(f"{label} must be a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise PipelineError(f"{label} must be an HTTPS URL without credentials or fragment")
    _normalize_hostname(parsed.hostname)
    return value


def _validate_page_inventory(path: Path) -> tuple[dict[str, dict[str, object]], str]:
    value, digest = _read_json_object(path, "page inventory")
    _require_exact_keys(value, ("schema_version", "pages"), (), "page inventory")
    if value["schema_version"] != PAGE_INVENTORY_VERSION:
        raise PipelineError(f"page inventory schema_version must be {PAGE_INVENTORY_VERSION!r}")
    raw_pages = value["pages"]
    if not isinstance(raw_pages, list) or not raw_pages:
        raise PipelineError("page inventory pages must be a non-empty array")
    pages: dict[str, dict[str, object]] = {}
    replacement_ids: set[str] = set()
    for index, raw_page in enumerate(raw_pages):
        label = f"page inventory pages[{index}]"
        if not isinstance(raw_page, dict):
            raise PipelineError(f"{label} must be an object")
        _require_exact_keys(
            raw_page,
            (
                "page_id",
                "class_name",
                "url",
                "page_role",
                "replacement_for_page_id",
                "replacement_reason",
            ),
            (),
            label,
        )
        if not isinstance(raw_page["page_id"], str):
            raise PipelineError(f"{label}.page_id must be a string")
        page_id = _require_safe_component(raw_page["page_id"], "page_id")
        if page_id in pages:
            raise PipelineError(f"duplicate page_id: {page_id}")
        if not isinstance(raw_page["class_name"], str):
            raise PipelineError(f"{label}.class_name must be a string")
        class_name = _normalize_hostname(raw_page["class_name"])
        if class_name != raw_page["class_name"]:
            raise PipelineError(f"{label}.class_name must already be normalized")
        _validate_https_url(raw_page["url"], f"{label}.url")
        if raw_page["page_role"] not in {"index", "subpage"}:
            raise PipelineError(f"{label}.page_role must be index or subpage")
        replaced = raw_page["replacement_for_page_id"]
        reason = raw_page["replacement_reason"]
        if (replaced is None) != (reason is None):
            raise PipelineError(f"{label} replacement fields must both be null or both populated")
        if replaced is not None:
            if not isinstance(replaced, str) or not isinstance(reason, str) or not reason:
                raise PipelineError(f"{label} has invalid replacement metadata")
            replacement_ids.add(_require_safe_component(replaced, "replacement_for_page_id"))
        pages[page_id] = dict(raw_page)
    missing_replacements = replacement_ids - set(pages)
    if missing_replacements:
        raise PipelineError(
            f"page inventory replacement targets are absent: {sorted(missing_replacements)}"
        )
    return pages, digest


def _validate_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise PipelineError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_configuration_inventory(
    path: Path,
) -> tuple[dict[str, dict[str, object]], str]:
    value, digest = _read_json_object(path, "configuration inventory")
    _require_exact_keys(
        value, ("schema_version", "configurations"), (), "configuration inventory"
    )
    if value["schema_version"] != CONFIGURATION_INVENTORY_VERSION:
        raise PipelineError(
            "configuration inventory schema_version must be "
            f"{CONFIGURATION_INVENTORY_VERSION!r}"
        )
    raw_configurations = value["configurations"]
    if not isinstance(raw_configurations, list) or not raw_configurations:
        raise PipelineError("configuration inventory configurations must be a non-empty array")
    configurations: dict[str, dict[str, object]] = {}
    for index, raw_configuration in enumerate(raw_configurations):
        label = f"configuration inventory configurations[{index}]"
        if not isinstance(raw_configuration, dict):
            raise PipelineError(f"{label} must be an object")
        _require_exact_keys(raw_configuration, CONFIGURATION_FIELDS, (), label)
        identifier_fields = ("configuration_id", "campaign", "os", "browser", "network")
        for field in identifier_fields:
            if not isinstance(raw_configuration[field], str):
                raise PipelineError(f"{label}.{field} must be a string")
            _require_safe_component(raw_configuration[field], field)
        configuration_id = str(raw_configuration["configuration_id"])
        if configuration_id in configurations:
            raise PipelineError(f"duplicate configuration_id: {configuration_id}")
        nonempty_fields = (
            "os_version",
            "browser_version",
            "capture_interface",
            "capture_binary",
            "capture_binary_version",
            "browser_binary",
            "driver_binary",
            "driver_version",
            "environment_image_digest",
        )
        for field in nonempty_fields:
            if not isinstance(raw_configuration[field], str) or not raw_configuration[field]:
                raise PipelineError(f"{label}.{field} must be a non-empty string")
        for field in ("capture_binary", "browser_binary", "driver_binary"):
            binary_path = Path(str(raw_configuration[field]))
            if binary_path.is_absolute() or ".." in binary_path.parts:
                raise PipelineError(f"{label}.{field} must be a portable name or contained path")
        _validate_sha256(
            raw_configuration["capture_binary_sha256"],
            f"{label}.capture_binary_sha256",
        )
        _validate_sha256(
            raw_configuration["browser_binary_sha256"],
            f"{label}.browser_binary_sha256",
        )
        _validate_sha256(raw_configuration["driver_binary_sha256"], f"{label}.driver_binary_sha256")
        image_digest = raw_configuration["environment_image_digest"]
        if not isinstance(image_digest, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", image_digest
        ):
            raise PipelineError(
                f"{label}.environment_image_digest must be sha256:<lowercase digest>"
            )
        if not isinstance(raw_configuration["enabled"], bool):
            raise PipelineError(f"{label}.enabled must be boolean")
        sessionizer_values = [
            raw_configuration[field]
            for field in (
                "sessionizer_binary",
                "sessionizer_version",
                "sessionizer_binary_sha256",
                "sessionizer_compatibility",
            )
        ]
        if not all(isinstance(item, str) for item in sessionizer_values):
            raise PipelineError(f"{label} sessionizer fields must be strings")
        if any(sessionizer_values):
            if not all(sessionizer_values):
                raise PipelineError(
                    f"{label} sessionizer fields must be all empty or all populated"
                )
            _validate_sha256(sessionizer_values[2], f"{label}.sessionizer_binary_sha256")
            if sessionizer_values[3] != "splitcap-compatible":
                raise PipelineError(
                    f"{label}.sessionizer_compatibility must be 'splitcap-compatible'"
                )
            sessionizer_path = Path(sessionizer_values[0])
            if sessionizer_path.is_absolute() or ".." in sessionizer_path.parts:
                raise PipelineError(
                    f"{label}.sessionizer_binary must be a portable name or contained path"
                )
        configurations[configuration_id] = dict(raw_configuration)
    return configurations, digest


def _read_schedule(path: Path) -> tuple[list[dict[str, str]], str]:
    if path.is_symlink():
        raise PipelineError(f"collection schedule must not be a symlink: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PipelineError("collection schedule must be UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if reader.fieldnames != list(COLLECTION_FIELDS):
        raise PipelineError(
            "collection schedule header must exactly equal the documented ordered fields"
        )
    rows = list(reader)
    if any(None in row for row in rows):
        raise PipelineError("collection schedule contains extra CSV fields")
    return rows, sha256_bytes(raw)


def _resolve_bound_tool(binary: str, expected_sha256: str, config_base: Path) -> Path:
    candidate = Path(binary)
    if candidate.is_absolute() or len(candidate.parts) > 1:
        if not candidate.is_absolute():
            candidate = config_base / candidate
        resolved_name = str(candidate)
    else:
        located = shutil.which(binary)
        if located is None:
            raise PipelineError(f"configured executable is not on PATH: {binary}")
        resolved_name = located
    try:
        resolved = Path(resolved_name).resolve(strict=True)
    except OSError as exc:
        raise PipelineError(f"configured executable is unavailable: {binary}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PipelineError(f"configured executable is not an executable file: {binary}")
    observed = sha256_file(resolved)
    if observed != expected_sha256:
        raise PipelineError(f"configured executable hash mismatch: {binary}")
    return resolved


def _validate_collection_authorities(
    config: Mapping[str, object], schedule: Path
) -> tuple[
    list[dict[str, str]],
    str,
    str,
    str,
    dict[str, dict[str, str]],
]:
    declared_schedule = _relative_config_path(config, "schedule")
    if declared_schedule != schedule.resolve():
        raise PipelineError(
            "--schedule does not match config.schedule: "
            f"{schedule.resolve()} != {declared_schedule}"
        )
    pages, pages_sha256 = _validate_page_inventory(
        _relative_config_path(config, "page_inventory")
    )
    configurations, configurations_sha256 = _validate_configuration_inventory(
        _relative_config_path(config, "configuration_inventory")
    )
    rows, schedule_sha256 = _read_schedule(schedule)
    if not rows:
        raise PipelineError("collection schedule is empty")
    allowlisted_classes = set(annotation_allowlist(config).values())
    repetitions = int(config["repetitions_per_page"])
    expected_keys = {
        (configuration_id, page_id, str(repetition))
        for configuration_id, configuration in configurations.items()
        if configuration["enabled"]
        for page_id in pages
        for repetition in range(repetitions)
    }
    observed_keys: set[tuple[str, str, str]] = set()
    visit_ids: set[str] = set()
    parent_ids: set[str] = set()
    for row in rows:
        visit_id = _require_safe_component(row["visit_id"], "visit_id")
        parent_id = _require_safe_component(row["parent_group_id"], "parent_group_id")
        if visit_id in visit_ids:
            raise PipelineError(f"duplicate visit_id: {visit_id}")
        if parent_id in parent_ids:
            raise PipelineError(f"duplicate parent_group_id: {parent_id}")
        visit_ids.add(visit_id)
        parent_ids.add(parent_id)
        configuration_id = _require_safe_component(row["configuration_id"], "configuration_id")
        page_id = _require_safe_component(row["page_id"], "page_id")
        configuration = configurations.get(configuration_id)
        page = pages.get(page_id)
        if configuration is None or not configuration["enabled"]:
            raise PipelineError(
                "schedule references absent or disabled configuration: "
                f"{configuration_id}"
            )
        if page is None:
            raise PipelineError(f"schedule references absent page: {page_id}")
        if row["class_name"] not in allowlisted_classes:
            raise PipelineError(
                f"scheduled class is not in annotation allowlist: {row['class_name']}"
            )
        for field in ("class_name", "url"):
            if row[field] != str(page[field]):
                raise PipelineError(f"schedule/page inventory mismatch for {visit_id}: {field}")
        for field in CONFIGURATION_FIELDS:
            if field == "enabled":
                continue
            if row[field] != str(configuration[field]):
                raise PipelineError(
                    f"schedule/configuration inventory mismatch for {visit_id}: {field}"
                )
        repetition_text = row["repetition"]
        try:
            repetition = int(repetition_text)
        except ValueError as exc:
            raise PipelineError("repetition must be a non-negative canonical integer") from exc
        if str(repetition) != repetition_text or not 0 <= repetition < repetitions:
            raise PipelineError("repetition must be a non-negative canonical integer in range")
        key = (configuration_id, page_id, repetition_text)
        if key in observed_keys:
            raise PipelineError(f"duplicate schedule configuration/page/repetition: {key}")
        observed_keys.add(key)
    if observed_keys != expected_keys:
        missing = len(expected_keys - observed_keys)
        unexpected = len(observed_keys - expected_keys)
        raise PipelineError(
            "schedule is not the exact enabled-configuration/page/repetition cross-product: "
            f"missing={missing}, unexpected={unexpected}"
        )

    source_path = getattr(config, "source_path", None)
    if not isinstance(source_path, Path):
        raise PipelineError("config source path is unavailable")
    resolved_tools: dict[str, dict[str, str]] = {}
    for configuration_id in sorted({row["configuration_id"] for row in rows}):
        configuration = configurations[configuration_id]
        binding: dict[str, str] = {}
        for prefix in ("capture", "browser", "driver"):
            name = str(configuration[f"{prefix}_binary"])
            expected_hash = str(configuration[f"{prefix}_binary_sha256"])
            binding[f"{prefix}_binary"] = str(
                _resolve_bound_tool(name, expected_hash, source_path.parent)
            )
        if configuration["sessionizer_binary"]:
            binding["sessionizer_binary"] = str(
                _resolve_bound_tool(
                    str(configuration["sessionizer_binary"]),
                    str(configuration["sessionizer_binary_sha256"]),
                    source_path.parent,
                )
            )
        resolved_tools[configuration_id] = binding
    return rows, schedule_sha256, pages_sha256, configurations_sha256, resolved_tools


def command_collect(
    config: Mapping[str, object], config_sha256: str, schedule: Path, destination: Path
) -> None:
    section = config.get("collection")
    if not isinstance(section, dict):
        raise PipelineError("config.collection must be an object")
    (
        rows,
        schedule_sha256,
        page_inventory_sha256,
        configuration_inventory_sha256,
        resolved_tools,
    ) = _validate_collection_authorities(config, schedule)
    ready_seconds = float(section["capture_ready_seconds"])
    post_seconds = float(section["post_visit_seconds"])
    visit_timeout = float(section["visit_timeout_seconds"])
    stop_timeout = float(section["capture_stop_timeout_seconds"])
    environment = section["environment"]
    assert isinstance(environment, dict)  # Validated by load_config.
    process_environment = dict(os.environ)
    process_environment.update(environment)
    retry_policy = section["retry_policy"]
    assert isinstance(retry_policy, dict)  # Validated by load_config.
    max_attempts = int(retry_policy["max_attempts"])
    backoff_seconds = float(retry_policy["backoff_seconds"])
    retryable_reasons = set(retry_policy["retryable_reasons"])

    attempt_fields = (
        *COLLECTION_FIELDS,
        "pipeline_version",
        "attempt_id",
        "attempt_index",
        "previous_attempt_id",
        "is_terminal_attempt",
        "status",
        "rejection_reason",
        "retryable",
        "retry_scheduled",
        "attempt_result_path",
        "pcap_path",
        "pcap_sha256",
        "capture_returncode",
        "visit_returncode",
        "capture_stdout_path",
        "capture_stderr_path",
        "visit_stdout_path",
        "visit_stderr_path",
    )
    parent_fields = (
        *COLLECTION_FIELDS,
        "pipeline_version",
        "status",
        "rejection_reason",
        "attempt_count",
        "terminal_attempt_id",
        "selected_attempt_id",
        "attempt_manifest_path",
        "pcap_path",
        "pcap_sha256",
        "capture_returncode",
        "visit_returncode",
        "capture_stdout_path",
        "capture_stderr_path",
        "visit_stdout_path",
        "visit_stderr_path",
    )

    with staged_directory(destination) as staging:
        attempt_rows: list[dict[str, object]] = []
        output_rows: list[dict[str, object]] = []
        for schedule_row in rows:
            visit_id = schedule_row["visit_id"]
            visit_attempt_rows: list[dict[str, object]] = []
            previous_attempt_id = ""
            for attempt_index in range(1, max_attempts + 1):
                attempt_id = f"{visit_id}.attempt-{attempt_index:03d}"
                attempt_relative = Path("attempts") / visit_id / f"attempt-{attempt_index:03d}"
                attempt_root = staging / attempt_relative
                attempt_root.mkdir(parents=True, exist_ok=False)
                pcap_relative = attempt_relative / "capture.pcap"
                capture_path = staging / pcap_relative
                log_relatives = {
                    "capture_stdout_path": attempt_relative / "capture.stdout.log",
                    "capture_stderr_path": attempt_relative / "capture.stderr.log",
                    "visit_stdout_path": attempt_relative / "visit.stdout.log",
                    "visit_stderr_path": attempt_relative / "visit.stderr.log",
                }
                tool_context = resolved_tools[schedule_row["configuration_id"]]
                context = {
                    **schedule_row,
                    **tool_context,
                    "capture_path": str(capture_path),
                }
                capture_command = _template_command(
                    section["capture_command"], context, "collection.capture_command"
                )
                visit_command = _template_command(
                    section["visit_command"], context, "collection.visit_command"
                )
                capture_returncode: int | None = None
                visit_returncode: int | None = None
                rejection_reason = ""
                capture_process: subprocess.Popen[bytes] | None = None
                stop_failed = False
                with (
                    (staging / log_relatives["capture_stdout_path"]).open("xb") as capture_out,
                    (staging / log_relatives["capture_stderr_path"]).open("xb") as capture_err,
                    (staging / log_relatives["visit_stdout_path"]).open("xb") as visit_out,
                    (staging / log_relatives["visit_stderr_path"]).open("xb") as visit_err,
                ):
                    try:
                        capture_process = subprocess.Popen(
                            capture_command,
                            stdout=capture_out,
                            stderr=capture_err,
                            env=process_environment,
                        )
                    except OSError:
                        rejection_reason = "capture_launch_failed"
                    if capture_process is not None:
                        if ready_seconds:
                            time.sleep(ready_seconds)
                        if capture_process.poll() is not None:
                            rejection_reason = "capture_exited_before_visit"
                        else:
                            try:
                                completed = subprocess.run(
                                    visit_command,
                                    stdout=visit_out,
                                    stderr=visit_err,
                                    timeout=visit_timeout,
                                    env=process_environment,
                                    check=False,
                                )
                                visit_returncode = completed.returncode
                                if visit_returncode != 0:
                                    rejection_reason = "visit_command_failed"
                            except subprocess.TimeoutExpired:
                                rejection_reason = "visit_timeout"
                            except OSError:
                                rejection_reason = "visit_launch_failed"
                        if post_seconds:
                            time.sleep(post_seconds)
                        try:
                            if capture_process.poll() is None:
                                capture_process.terminate()
                                try:
                                    capture_process.wait(timeout=stop_timeout)
                                except subprocess.TimeoutExpired:
                                    capture_process.kill()
                                    capture_process.wait(timeout=stop_timeout)
                        except (OSError, subprocess.TimeoutExpired):
                            stop_failed = True
                        capture_returncode = capture_process.returncode
                if stop_failed and not rejection_reason:
                    rejection_reason = "capture_stop_failed"
                pcap_hash = ""
                pcap_path = ""
                if capture_path.is_file() and capture_path.stat().st_size > 0:
                    pcap_hash = sha256_file(capture_path)
                    pcap_path = pcap_relative.as_posix()
                elif not rejection_reason:
                    rejection_reason = "capture_missing_or_empty"
                status = "accepted" if not rejection_reason else "rejected"
                retryable = bool(rejection_reason in retryable_reasons)
                retry_scheduled = bool(
                    status == "rejected" and retryable and attempt_index < max_attempts
                )
                attempt_row: dict[str, object] = {
                    **{field: schedule_row[field] for field in COLLECTION_FIELDS},
                    "pipeline_version": PIPELINE_VERSION,
                    "attempt_id": attempt_id,
                    "attempt_index": attempt_index,
                    "previous_attempt_id": previous_attempt_id,
                    "is_terminal_attempt": str(not retry_scheduled).lower(),
                    "status": status,
                    "rejection_reason": rejection_reason,
                    "retryable": str(retryable).lower(),
                    "retry_scheduled": str(retry_scheduled).lower(),
                    "attempt_result_path": (
                        attempt_relative / "attempt_result.json"
                    ).as_posix(),
                    "pcap_path": pcap_path,
                    "pcap_sha256": pcap_hash,
                    "capture_returncode": "" if capture_returncode is None else capture_returncode,
                    "visit_returncode": "" if visit_returncode is None else visit_returncode,
                    **{name: path.as_posix() for name, path in log_relatives.items()},
                }
                attempt_rows.append(attempt_row)
                visit_attempt_rows.append(attempt_row)
                write_json(attempt_root / "attempt_result.json", attempt_row)
                previous_attempt_id = attempt_id
                if not retry_scheduled:
                    break
                if backoff_seconds:
                    time.sleep(backoff_seconds)
            terminal = visit_attempt_rows[-1]
            output_rows.append(
                {
                    **{field: schedule_row[field] for field in COLLECTION_FIELDS},
                    "pipeline_version": PIPELINE_VERSION,
                    "status": terminal["status"],
                    "rejection_reason": terminal["rejection_reason"],
                    "attempt_count": len(visit_attempt_rows),
                    "terminal_attempt_id": terminal["attempt_id"],
                    "selected_attempt_id": (
                        terminal["attempt_id"] if terminal["status"] == "accepted" else ""
                    ),
                    "attempt_manifest_path": "collection_attempt_manifest.csv",
                    "pcap_path": terminal["pcap_path"],
                    "pcap_sha256": terminal["pcap_sha256"],
                    "capture_returncode": terminal["capture_returncode"],
                    "visit_returncode": terminal["visit_returncode"],
                    "capture_stdout_path": terminal["capture_stdout_path"],
                    "capture_stderr_path": terminal["capture_stderr_path"],
                    "visit_stdout_path": terminal["visit_stdout_path"],
                    "visit_stderr_path": terminal["visit_stderr_path"],
                }
            )
        write_csv(staging / "collection_attempt_manifest.csv", attempt_rows, attempt_fields)
        write_csv(staging / "parent_capture_manifest.csv", output_rows, parent_fields)
        tool_bindings = []
        for configuration_id in sorted({row["configuration_id"] for row in rows}):
            first = next(row for row in rows if row["configuration_id"] == configuration_id)
            tool_bindings.append(
                {
                    "configuration_id": configuration_id,
                    **{
                        field: first[field]
                        for field in COLLECTION_FIELDS
                        if field == "browser_version"
                        or field.startswith(
                            ("capture_binary", "browser_binary", "driver_", "sessionizer_")
                        )
                    },
                }
            )
        write_json(
            staging / "collection_report.json",
            {
                "pipeline_version": PIPELINE_VERSION,
                "config_sha256": config_sha256,
                "schedule_sha256": schedule_sha256,
                "page_inventory_sha256": page_inventory_sha256,
                "configuration_inventory_sha256": configuration_inventory_sha256,
                "scheduled_visits": len(rows),
                "accepted_visits": sum(row["status"] == "accepted" for row in output_rows),
                "rejected_visits": sum(row["status"] == "rejected" for row in output_rows),
                "attempts": len(attempt_rows),
                "retry_policy": {
                    "max_attempts": max_attempts,
                    "backoff_seconds": backoff_seconds,
                    "retryable_reasons": sorted(retryable_reasons),
                },
                "tool_bindings": tool_bindings,
                "binaries_redistributed": False,
                "source_inputs_deleted": 0,
            },
        )


def command_sessionize(
    config: Mapping[str, object],
    config_sha256: str,
    input_manifest: Path,
    destination: Path,
) -> None:
    del config  # Reserved for a future explicitly versioned sessionization policy.
    rows = read_csv(
        input_manifest,
        (*COLLECTION_FIELDS, "status", "pcap_path", "pcap_sha256"),
    )
    parent_ids = [row["parent_group_id"] for row in rows]
    if len(parent_ids) != len(set(parent_ids)):
        raise PipelineError("duplicate parent_group_id in capture manifest")
    with staged_directory(destination) as staging:
        sessions_output: list[dict[str, object]] = []
        parent_output: list[dict[str, object]] = []
        for row in rows:
            if row["status"] != "accepted":
                parent_output.append(
                    {
                        **{field: row[field] for field in COLLECTION_FIELDS},
                        "pipeline_version": PIPELINE_VERSION,
                        "status": "skipped_rejected_capture",
                        "sessions": 0,
                        "tcp_packets": 0,
                        "skipped_non_tcp_packets": 0,
                    }
                )
                continue
            source = _resolve_pcap(input_manifest, row)
            raw = source.read_bytes()
            global_header, sessions, skipped = sessionize_pcap(raw)
            tcp_packets = sum(len(session.records) for session in sessions)
            for ordinal, session in enumerate(sessions, start=1):
                token = sha256_bytes(
                    f"{PIPELINE_VERSION}\0{row['parent_group_id']}\0{ordinal}".encode()
                )[:24]
                session_id = f"session_{token}"
                relative = (
                    Path("sessions")
                    / row["configuration_id"]
                    / row["class_name"]
                    / f"{session_id}.pcap"
                )
                output_path = staging / relative
                output_path.parent.mkdir(parents=True, exist_ok=True)
                payload = _pcap_for_records(global_header, session.records)
                output_path.write_bytes(payload)
                sessions_output.append(
                    {
                        **{field: row[field] for field in COLLECTION_FIELDS},
                        "pipeline_version": PIPELINE_VERSION,
                        "session_id": session_id,
                        "session_ordinal": ordinal,
                        "packet_count": len(session.records),
                        "status": "accepted",
                        "pcap_path": relative.as_posix(),
                        "pcap_sha256": sha256_bytes(payload),
                    }
                )
            parent_output.append(
                {
                    **{field: row[field] for field in COLLECTION_FIELDS},
                    "pipeline_version": PIPELINE_VERSION,
                    "status": "accepted" if sessions else "rejected_no_tcp_sessions",
                    "sessions": len(sessions),
                    "tcp_packets": tcp_packets,
                    "skipped_non_tcp_packets": skipped,
                }
            )
        session_fields = (
            *COLLECTION_FIELDS,
            "pipeline_version",
            "session_id",
            "session_ordinal",
            "packet_count",
            "status",
            "pcap_path",
            "pcap_sha256",
        )
        parent_fields = (
            *COLLECTION_FIELDS,
            "pipeline_version",
            "status",
            "sessions",
            "tcp_packets",
            "skipped_non_tcp_packets",
        )
        write_csv(staging / "session_manifest.csv", sessions_output, session_fields)
        write_csv(
            staging / "sessionization_parent_summary.csv", parent_output, parent_fields
        )
        write_json(
            staging / "sessionization_report.json",
            {
                "pipeline_version": PIPELINE_VERSION,
                "config_sha256": config_sha256,
                "input_manifest_sha256": sha256_file(input_manifest),
                "parent_captures": len(rows),
                "sessions": len(sessions_output),
                "source_captures_deleted": 0,
                "endpoint_values_published": 0,
            },
        )


def _reassembled_tcp_chunks(segments: Sequence[tuple[int, int, bytes]]) -> list[bytes]:
    unique: dict[tuple[int, bytes], int] = {}
    for sequence, index, payload in segments:
        if payload:
            unique.setdefault((sequence, payload), index)
    ordered = sorted((sequence, index, payload) for (sequence, payload), index in unique.items())
    chunks: list[bytes] = []
    start: int | None = None
    assembled = bytearray()
    for sequence, _index, payload in ordered:
        if start is None:
            start = sequence
            assembled.extend(payload)
            continue
        end = start + len(assembled)
        if sequence > end:
            chunks.append(bytes(assembled))
            start = sequence
            assembled = bytearray(payload)
            continue
        overlap = end - sequence
        if overlap < len(payload):
            existing_start = sequence - start
            existing = assembled[existing_start : existing_start + min(overlap, len(payload))]
            if existing != payload[: len(existing)]:
                chunks.append(bytes(assembled))
                start = sequence
                assembled = bytearray(payload)
            else:
                assembled.extend(payload[overlap:])
    if assembled:
        chunks.append(bytes(assembled))
    return chunks


def _client_hello_snis(handshake: bytes) -> list[str]:
    if len(handshake) < 34:
        return []
    cursor = 34
    session_length = handshake[cursor]
    cursor += 1 + session_length
    if cursor + 2 > len(handshake):
        return []
    cipher_length = struct.unpack_from("!H", handshake, cursor)[0]
    cursor += 2 + cipher_length
    if cursor >= len(handshake):
        return []
    compression_length = handshake[cursor]
    cursor += 1 + compression_length
    if cursor + 2 > len(handshake):
        return []
    extensions_length = struct.unpack_from("!H", handshake, cursor)[0]
    cursor += 2
    extensions_end = cursor + extensions_length
    if extensions_end > len(handshake):
        return []
    names: list[str] = []
    while cursor + 4 <= extensions_end:
        extension_type, extension_length = struct.unpack_from("!HH", handshake, cursor)
        cursor += 4
        extension_end = cursor + extension_length
        if extension_end > extensions_end:
            return []
        if extension_type == 0 and extension_length >= 2:
            list_length = struct.unpack_from("!H", handshake, cursor)[0]
            name_cursor = cursor + 2
            list_end = name_cursor + list_length
            if list_end > extension_end:
                return []
            while name_cursor + 3 <= list_end:
                name_type = handshake[name_cursor]
                name_length = struct.unpack_from("!H", handshake, name_cursor + 1)[0]
                name_cursor += 3
                name_end = name_cursor + name_length
                if name_end > list_end:
                    return []
                if name_type == 0:
                    try:
                        names.append(handshake[name_cursor:name_end].decode("ascii"))
                    except UnicodeDecodeError:
                        pass
                name_cursor = name_end
        cursor = extension_end
    return names


def _tls_snis(stream: bytes) -> list[str]:
    names: list[str] = []
    offset = 0
    while offset + 5 <= len(stream):
        content_type = stream[offset]
        major = stream[offset + 1]
        minor = stream[offset + 2]
        length = struct.unpack_from("!H", stream, offset + 3)[0]
        record_end = offset + 5 + length
        if (
            content_type != 22
            or major != 3
            or minor > 4
            or length > 18_432
            or record_end > len(stream)
        ):
            offset += 1
            continue
        handshake_bytes = bytearray(stream[offset + 5 : record_end])
        next_offset = record_end
        while next_offset + 5 <= len(stream) and stream[next_offset] == 22:
            next_length = struct.unpack_from("!H", stream, next_offset + 3)[0]
            next_end = next_offset + 5 + next_length
            if next_length > 18_432 or next_end > len(stream):
                break
            handshake_bytes.extend(stream[next_offset + 5 : next_end])
            next_offset = next_end
        cursor = 0
        while cursor + 4 <= len(handshake_bytes):
            handshake_type = handshake_bytes[cursor]
            handshake_length = int.from_bytes(handshake_bytes[cursor + 1 : cursor + 4], "big")
            handshake_end = cursor + 4 + handshake_length
            if handshake_end > len(handshake_bytes):
                break
            if handshake_type == 1:
                names.extend(
                    _client_hello_snis(bytes(handshake_bytes[cursor + 4 : handshake_end]))
                )
            cursor = handshake_end
        offset = record_end
    return names


def extract_snis(raw: bytes) -> list[str]:
    parsed = parse_classic_pcap(raw)
    directions: defaultdict[
        tuple[bytes, int, bytes, int], list[tuple[int, int, bytes]]
    ] = defaultdict(list)
    for record in parsed.records:
        packet = parse_ipv4_tcp(record.frame)
        if packet is not None and packet.payload:
            directions[packet.direction_key].append(
                (packet.sequence, record.index, packet.payload)
            )
    names: list[str] = []
    for direction in sorted(directions):
        for chunk in _reassembled_tcp_chunks(directions[direction]):
            names.extend(_tls_snis(chunk))
    normalized: list[str] = []
    for name in names:
        try:
            normalized.append(_normalize_hostname(name))
        except PipelineError:
            continue
    return sorted(set(normalized))


def command_annotate(
    config: Mapping[str, object],
    config_sha256: str,
    input_manifest: Path,
    destination: Path,
) -> None:
    rows = read_csv(
        input_manifest,
        (
            *COLLECTION_FIELDS,
            "session_id",
            "status",
            "pcap_path",
            "pcap_sha256",
        ),
    )
    allowlist = annotation_allowlist(config)
    section = config["annotation"]
    assert isinstance(section, dict)
    raw_minimum_bytes = section.get("minimum_session_bytes", 0)
    if isinstance(raw_minimum_bytes, bool) or not isinstance(raw_minimum_bytes, int):
        raise PipelineError("minimum_session_bytes must be an integer")
    minimum_bytes = raw_minimum_bytes
    raw_scheduled_match = section.get("require_scheduled_class_match", True)
    if not isinstance(raw_scheduled_match, bool):
        raise PipelineError("require_scheduled_class_match must be boolean")
    require_scheduled_match = raw_scheduled_match
    if minimum_bytes < 0:
        raise PipelineError("minimum_session_bytes must be non-negative")
    with staged_directory(destination) as staging:
        output: list[dict[str, object]] = []
        for row in rows:
            source = _resolve_pcap(input_manifest, row)
            rejection = ""
            snis: list[str] = []
            annotated_class = ""
            if source.stat().st_size < minimum_bytes:
                rejection = "below_minimum_session_bytes"
            else:
                snis = extract_snis(source.read_bytes())
                if not snis:
                    rejection = "no_sni"
                elif len(snis) != 1:
                    rejection = "ambiguous_sni"
                elif snis[0] not in allowlist:
                    rejection = "sni_not_allowlisted"
                else:
                    annotated_class = allowlist[snis[0]]
                    if require_scheduled_match and annotated_class != row["class_name"]:
                        rejection = "scheduled_class_mismatch"
            output.append(
                {
                    **{field: row[field] for field in COLLECTION_FIELDS},
                    "pipeline_version": PIPELINE_VERSION,
                    "session_id": row["session_id"],
                    "sni": ";".join(snis),
                    "annotated_class_name": annotated_class,
                    "status": "accepted" if not rejection else "rejected",
                    "rejection_reason": rejection,
                    "pcap_path": _portable_path(source, destination),
                    "pcap_sha256": row["pcap_sha256"],
                }
            )
        fields = (
            *COLLECTION_FIELDS,
            "pipeline_version",
            "session_id",
            "sni",
            "annotated_class_name",
            "status",
            "rejection_reason",
            "pcap_path",
            "pcap_sha256",
        )
        write_csv(staging / "annotation_manifest.csv", output, fields)
        reasons: defaultdict[str, int] = defaultdict(int)
        for row in output:
            reasons[str(row["rejection_reason"] or "accepted")] += 1
        write_json(
            staging / "annotation_report.json",
            {
                "pipeline_version": PIPELINE_VERSION,
                "config_sha256": config_sha256,
                "input_manifest_sha256": sha256_file(input_manifest),
                "sessions": len(rows),
                "outcomes": dict(sorted(reasons.items())),
                "annotation_policy": "normalized full-SNI exact allowlist match",
                "registrable_domain_truncation": False,
            },
        )


def _digest(namespace: str, *parts: object) -> str:
    payload = "\0".join((namespace, *(str(part) for part in parts)))
    return sha256_bytes(payload.encode("utf-8"))


def _choose_groups_exact(
    groups: Mapping[str, Sequence[Mapping[str, str]]],
    target: int,
    namespace: str,
    *context: object,
) -> set[str]:
    if target < 0:
        raise PipelineError("negative selection target")
    ordered = sorted(groups, key=lambda item: (_digest(namespace, *context, item), item))
    reachable: dict[int, tuple[str, ...]] = {0: ()}
    for group_id in ordered:
        size = len(groups[group_id])
        for total in sorted(tuple(reachable), reverse=True):
            candidate = total + size
            if candidate <= target and candidate not in reachable:
                reachable[candidate] = (*reachable[total], group_id)
    if target not in reachable:
        raise PipelineError(
            f"leakage groups cannot satisfy exact selection target {target}"
        )
    return set(reachable[target])


def _assign_group_splits(
    groups: Mapping[str, Sequence[Mapping[str, str]]],
    validation_target: int,
    test_target: int,
    namespace: str,
    *context: object,
) -> dict[str, str]:
    ordered = sorted(groups, key=lambda item: (_digest(namespace, *context, item), item))
    # State values are compact role strings in the same order as ``ordered``.
    states: dict[tuple[int, int], bytes] = {(0, 0): b""}
    for group_id in ordered:
        size = len(groups[group_id])
        next_states: dict[tuple[int, int], bytes] = {}
        role_order = sorted(
            (("train", b"R"), ("validation", b"V"), ("test", b"T")),
            key=lambda item: _digest(namespace, *context, group_id, item[0]),
        )
        for (validation_count, test_count), roles in sorted(states.items()):
            for role, code in role_order:
                new_validation = validation_count + (size if role == "validation" else 0)
                new_test = test_count + (size if role == "test" else 0)
                state = (new_validation, new_test)
                if (
                    new_validation <= validation_target
                    and new_test <= test_target
                    and state not in next_states
                ):
                    next_states[state] = roles + code
        states = next_states
    target_state = (validation_target, test_target)
    if target_state not in states:
        raise PipelineError(
            "leakage groups cannot satisfy exact 70:15:15 quotas: "
            f"validation={validation_target}, test={test_target}"
        )
    code_to_role = {ord("R"): "train", ord("V"): "validation", ord("T"): "test"}
    return {
        group_id: code_to_role[code]
        for group_id, code in zip(ordered, states[target_state], strict=True)
    }


def _leakage_components(
    rows: Sequence[dict[str, str]],
) -> tuple[dict[str, str], dict[str, list[dict[str, str]]]]:
    """Union rows connected by either parent identity or exact PCAP bytes."""

    parents = list(range(len(rows)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    first_by_parent: dict[str, int] = {}
    first_by_hash: dict[str, int] = {}
    for index, row in enumerate(rows):
        for value, firsts in (
            (row["parent_group_id"], first_by_parent),
            (row["pcap_sha256"], first_by_hash),
        ):
            previous = firsts.setdefault(value, index)
            union(index, previous)

    by_root: defaultdict[int, list[dict[str, str]]] = defaultdict(list)
    for index, row in enumerate(rows):
        by_root[find(index)].append(row)
    membership: dict[str, str] = {}
    components: dict[str, list[dict[str, str]]] = {}
    for component_rows in by_root.values():
        cells = {
            (row["configuration_id"], row["class_name"])
            for row in component_rows
        }
        if len(cells) != 1:
            raise PipelineError(
                "a parent/hash-connected leakage group spans configuration/class cells"
            )
        tokens = sorted(
            {
                *(f"parent:{row['parent_group_id']}" for row in component_rows),
                *(f"sha256:{row['pcap_sha256']}" for row in component_rows),
                *(f"session:{row['session_id']}" for row in component_rows),
            }
        )
        component_id = "leakage_" + _digest(
            "driftbench-leakage-component-v1", *tokens
        )[:24]
        components[component_id] = component_rows
        for row in component_rows:
            membership[row["session_id"]] = component_id
    return membership, components


def command_select(
    config: Mapping[str, object],
    config_sha256: str,
    input_manifest: Path,
    destination: Path,
) -> None:
    rows = read_csv(
        input_manifest,
        (
            *COLLECTION_FIELDS,
            "session_id",
            "annotated_class_name",
            "status",
            "pcap_path",
            "pcap_sha256",
        ),
    )
    section = config.get("selection")
    if not isinstance(section, dict):
        raise PipelineError("config.selection must be an object")
    namespace = section.get("namespace")
    if not isinstance(namespace, str) or not namespace:
        raise PipelineError("selection.namespace must be a non-empty string")
    if section.get("ratios", [70, 15, 15]) != [70, 15, 15]:
        raise PipelineError("this version requires selection.ratios [70, 15, 15]")
    raw_limit = section.get("per_cell_limit")
    per_cell_limit: int | None
    if raw_limit is None:
        per_cell_limit = None
    elif isinstance(raw_limit, int) and not isinstance(raw_limit, bool) and raw_limit > 0:
        per_cell_limit = raw_limit
    else:
        raise PipelineError("selection.per_cell_limit must be null or a positive integer")

    accepted = [row for row in rows if row["status"] == "accepted"]
    if not accepted:
        raise PipelineError("annotation manifest has no accepted sessions")
    cells: defaultdict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    seen_sessions: set[str] = set()
    for row in accepted:
        if row["annotated_class_name"] != row["class_name"]:
            raise PipelineError("accepted annotation does not match scheduled class")
        if row["session_id"] in seen_sessions:
            raise PipelineError(f"duplicate session_id: {row['session_id']}")
        seen_sessions.add(row["session_id"])
        _resolve_pcap(input_manifest, row)
        cell = (row["configuration_id"], row["class_name"])
        cells[cell].append(row)
    leakage_membership, all_components = _leakage_components(accepted)

    class_names = sorted({row["class_name"] for row in accepted})
    label_ids = {name: index for index, name in enumerate(class_names)}
    selected_rows: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    for (configuration_id, class_name), cell_rows in sorted(cells.items()):
        all_groups: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
        for row in cell_rows:
            all_groups[leakage_membership[row["session_id"]]].append(row)
        target = len(cell_rows) if per_cell_limit is None else per_cell_limit
        if target > len(cell_rows):
            raise PipelineError(
                f"selection target {target} exceeds available {len(cell_rows)} for "
                f"{configuration_id}/{class_name}"
            )
        chosen_ids = _choose_groups_exact(
            all_groups,
            target,
            namespace,
            configuration_id,
            class_name,
            "cohort",
        )
        groups = {group_id: all_groups[group_id] for group_id in chosen_ids}
        validation_target = target * 15 // 100
        test_target = target * 15 // 100
        assignments = _assign_group_splits(
            groups,
            validation_target,
            test_target,
            namespace,
            configuration_id,
            class_name,
            "split",
        )
        split_counts: defaultdict[str, int] = defaultdict(int)
        ordered_cell_rows = sorted(
            (row for group in groups.values() for row in group),
            key=lambda row: (
                _digest(namespace, configuration_id, class_name, row["session_id"]),
                row["session_id"],
            ),
        )
        for rank, row in enumerate(ordered_cell_rows, start=1):
            leakage_group_id = leakage_membership[row["session_id"]]
            split = assignments[leakage_group_id]
            split_counts[split] += 1
            source = _resolve_pcap(input_manifest, row)
            selected_rows.append(
                {
                    "pipeline_version": PIPELINE_VERSION,
                    "split_version": SPLIT_VERSION,
                    **{field: row[field] for field in COLLECTION_FIELDS},
                    "session_id": row["session_id"],
                    "leakage_group_id": leakage_group_id,
                    "label_id": label_ids[class_name],
                    "split": split,
                    "selection_rank": rank,
                    "selection_key": _digest(
                        namespace, configuration_id, class_name, row["session_id"]
                    ),
                    "status": "selected",
                    "pcap_path": _portable_path(source, destination),
                    "pcap_sha256": row["pcap_sha256"],
                }
            )
        summaries.append(
            {
                "configuration_id": configuration_id,
                "class_name": class_name,
                "available": len(cell_rows),
                "selected": target,
                "parent_groups": len(
                    {row["parent_group_id"] for group in groups.values() for row in group}
                ),
                "leakage_groups": len(groups),
                "train": split_counts["train"],
                "validation": split_counts["validation"],
                "test": split_counts["test"],
            }
        )
    selected_rows.sort(
        key=lambda row: (
            str(row["configuration_id"]),
            str(row["class_name"]),
            str(row["split"]),
            int(row["selection_rank"]),
        )
    )
    fields = (
        "pipeline_version",
        "split_version",
        *COLLECTION_FIELDS,
        "session_id",
        "leakage_group_id",
        "label_id",
        "split",
        "selection_rank",
        "selection_key",
        "status",
        "pcap_path",
        "pcap_sha256",
    )
    with staged_directory(destination) as staging:
        write_csv(staging / "split_manifest.csv", selected_rows, fields)
        write_csv(
            staging / "selection_summary.csv",
            summaries,
            (
                "configuration_id",
                "class_name",
                "available",
                "selected",
                "parent_groups",
                "leakage_groups",
                "train",
                "validation",
                "test",
            ),
        )
        write_json(
            staging / "selection_report.json",
            {
                "pipeline_version": PIPELINE_VERSION,
                "split_version": SPLIT_VERSION,
                "config_sha256": config_sha256,
                "input_manifest_sha256": sha256_file(input_manifest),
                "namespace": namespace,
                "ratios": [70, 15, 15],
                "selected_sessions": len(selected_rows),
                "cells": len(summaries),
                "parent_group_atomic": True,
                "identical_pcap_atomic": True,
                "leakage_group_rule": "transitive union of parent_group_id and pcap_sha256",
                "available_leakage_groups": len(all_components),
            },
        )


_SANITIZER_V11_SOURCE = r'''#!/usr/bin/env python3
"""Build the canonical IPv4, handshake-filtered DriftBench v2 corpus.

The sanitizer intentionally removes only handshake traffic that can be
identified from the capture itself:

* every TCP SYN/SYN-ACK and the observable third ACK; and
* every packet overlapping a reassembled TLS record with outer content type
  20 (ChangeCipherSpec) or 22 (Handshake).

TLS 1.3 encrypts most handshake messages inside outer content type 23, which
is indistinguishable from application data without session secrets.  Those
records are retained rather than removed using an unverifiable heuristic.

Every retained packet is rebuilt as Ethernet/IPv4/TCP.  Endpoint identifiers
and absolute TCP sequence spaces are replaced deterministically from the raw
PCAP hash, malformed offload lengths are repaired by reconstruction, packet
timestamps are stable-sorted, and at most 50 packets are written.  For
analysis, every 2024 file starts at 2024-01-15T00:00:00Z and every 2026 file
(including temporal targets) starts at 2026-01-15T00:00:00Z; original
microsecond inter-arrival times are preserved exactly.  These fixed timestamps
are synthetic normalization anchors, not collection dates.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

SANITIZER_VERSION = "driftbench-sanitizer-1.1.0"
PSEUDONYM_KEY = b"driftbench-sanitizer-endpoints-v1"
MAX_TCP_STREAM = 20_000_000
MAX_TLS_RECORD = 18_432
PCAP_LINKTYPE_ETHERNET = 1
MICROSECONDS_PER_SECOND = 1_000_000

ANCHOR_2024_UTC = "2024-01-15T00:00:00Z"
ANCHOR_2026_UTC = "2026-01-15T00:00:00Z"
ANCHOR_2024_US = 1_705_276_800 * MICROSECONDS_PER_SECOND
ANCHOR_2026_US = 1_768_435_200 * MICROSECONDS_PER_SECOND

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


class SanitizationError(RuntimeError):
    """Raised when an input capture violates a required corpus invariant."""


@dataclass
class ParsedPacket:
    index: int
    timestamp_us: int
    family: int
    src_ip: bytes
    dst_ip: bytes
    src_mac: bytes
    dst_mac: bytes
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    urgent: int
    tcp_options: bytes
    payload: bytes
    tos: int
    ttl: int
    invalid_ip_length: bool
    direction: str = ""
    relative_stream_start: int | None = None

    @property
    def endpoint_source(self) -> tuple[int, bytes, int]:
        return self.family, self.src_ip, self.sport

    @property
    def endpoint_destination(self) -> tuple[int, bytes, int]:
        return self.family, self.dst_ip, self.dport


@dataclass
class StreamView:
    data: bytearray
    covered: bytearray
    segments: list[ParsedPacket]


@dataclass
class Pseudonyms:
    client_mac: bytes
    server_mac: bytes
    client_ip: bytes
    server_ip: bytes
    client_port: int
    server_port: int
    client_seq_target: int
    server_seq_target: int


@dataclass
class SanitizationResult:
    source_relative_path: str
    sanitized_relative_path: str
    source_sha256: str
    sanitized_sha256: str
    input_packets: int
    output_packets: int
    original_family: str
    invalid_ipv4_lengths: int
    invalid_ipv6_lengths: int
    timestamp_inversions: int
    source_first_retained_timestamp_us: int
    synthetic_anchor_timestamp_us: int
    synthetic_anchor_utc: str
    timestamp_shift_us: int
    dropped_tcp_handshake: int
    dropped_tls_handshake: int
    dropped_union: int
    plaintext_domain_bytes_removed_with_handshake: int
    masked_retained_domain_bytes: int
    handshake_not_observed: bool
    retained_source_indices: str
    dropped_source_indices: str

    def as_manifest_row(self) -> dict[str, object]:
        return {
            "sanitizer_version": SANITIZER_VERSION,
            **self.__dict__,
        }


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("!H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("!I", data, offset)[0]


def _timestamp_anchor(source_relative_path: str) -> tuple[int, str]:
    root = Path(source_relative_path).parts[0]
    if root == "2024":
        return ANCHOR_2024_US, ANCHOR_2024_UTC
    # Direct sanitize_one calls in unit tests use compact synthetic paths and
    # default to the 2026 anchor.  main() separately rejects unknown corpus
    # roots before processing a production tree.
    return ANCHOR_2026_US, ANCHOR_2026_UTC


def _parse_tcp_frame(index: int, timestamp_us: int, frame: bytes) -> ParsedPacket:
    if len(frame) < 14:
        raise SanitizationError(f"packet {index}: truncated Ethernet header")

    dst_mac = frame[0:6]
    src_mac = frame[6:12]
    ether_type = _u16(frame, 12)
    ip_start = 14
    while ether_type in VLAN_TYPES:
        if len(frame) < ip_start + 4:
            raise SanitizationError(f"packet {index}: truncated VLAN header")
        ether_type = _u16(frame, ip_start + 2)
        ip_start += 4

    family: int
    tcp_start: int
    ip_end: int
    tos: int
    ttl: int
    invalid_ip_length = False

    if ether_type == ETHERTYPE_IPV4:
        if len(frame) < ip_start + 20:
            raise SanitizationError(f"packet {index}: truncated IPv4 header")
        version_ihl = frame[ip_start]
        if version_ihl >> 4 != 4:
            raise SanitizationError(f"packet {index}: invalid IPv4 version")
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(frame) < ip_start + ihl:
            raise SanitizationError(f"packet {index}: invalid IPv4 IHL")
        if frame[ip_start + 9] != socket.IPPROTO_TCP:
            raise SanitizationError(f"packet {index}: non-TCP IPv4 packet")
        total_length = _u16(frame, ip_start + 2)
        captured_l3 = len(frame) - ip_start
        if ihl + 20 <= total_length <= captured_l3:
            ip_end = ip_start + total_length
        else:
            ip_end = len(frame)
            invalid_ip_length = True
        family = 4
        src_ip = frame[ip_start + 12 : ip_start + 16]
        dst_ip = frame[ip_start + 16 : ip_start + 20]
        tos = frame[ip_start + 1]
        ttl = frame[ip_start + 8]
        tcp_start = ip_start + ihl

    elif ether_type == ETHERTYPE_IPV6:
        if len(frame) < ip_start + 40:
            raise SanitizationError(f"packet {index}: truncated IPv6 header")
        if frame[ip_start] >> 4 != 6:
            raise SanitizationError(f"packet {index}: invalid IPv6 version")
        family = 6
        src_ip = frame[ip_start + 8 : ip_start + 24]
        dst_ip = frame[ip_start + 24 : ip_start + 40]
        tos = ((frame[ip_start] & 0x0F) << 4) | (frame[ip_start + 1] >> 4)
        ttl = frame[ip_start + 7]
        payload_length = _u16(frame, ip_start + 4)
        captured_l3 = len(frame) - ip_start
        if 0 < payload_length and 40 + payload_length <= captured_l3:
            ip_end = ip_start + 40 + payload_length
        else:
            ip_end = len(frame)
            invalid_ip_length = True

        next_header = frame[ip_start + 6]
        cursor = ip_start + 40
        while next_header in {0, 43, 44, 51, 60}:
            if next_header == 44:
                if cursor + 8 > ip_end:
                    raise SanitizationError(f"packet {index}: truncated IPv6 fragment header")
                next_header = frame[cursor]
                cursor += 8
            elif next_header == 51:
                if cursor + 2 > ip_end:
                    raise SanitizationError(f"packet {index}: truncated IPv6 AH header")
                extension_length = (frame[cursor + 1] + 2) * 4
                next_header = frame[cursor]
                cursor += extension_length
            else:
                if cursor + 2 > ip_end:
                    raise SanitizationError(f"packet {index}: truncated IPv6 extension header")
                extension_length = (frame[cursor + 1] + 1) * 8
                next_header = frame[cursor]
                cursor += extension_length
            if cursor > ip_end:
                raise SanitizationError(f"packet {index}: invalid IPv6 extension length")
        if next_header != socket.IPPROTO_TCP:
            raise SanitizationError(f"packet {index}: non-TCP IPv6 packet")
        tcp_start = cursor
    else:
        raise SanitizationError(f"packet {index}: unsupported EtherType 0x{ether_type:04x}")

    if tcp_start + 20 > ip_end:
        raise SanitizationError(f"packet {index}: truncated TCP header")
    sport = _u16(frame, tcp_start)
    dport = _u16(frame, tcp_start + 2)
    seq = _u32(frame, tcp_start + 4)
    ack = _u32(frame, tcp_start + 8)
    tcp_header_length = (frame[tcp_start + 12] >> 4) * 4
    if tcp_header_length < 20 or tcp_start + tcp_header_length > ip_end:
        raise SanitizationError(f"packet {index}: invalid TCP data offset")
    flags = frame[tcp_start + 13]
    window = _u16(frame, tcp_start + 14)
    urgent = _u16(frame, tcp_start + 18)
    tcp_options = frame[tcp_start + 20 : tcp_start + tcp_header_length]
    payload = frame[tcp_start + tcp_header_length : ip_end]

    return ParsedPacket(
        index=index,
        timestamp_us=timestamp_us,
        family=family,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=src_mac,
        dst_mac=dst_mac,
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
        urgent=urgent,
        tcp_options=tcp_options,
        payload=payload,
        tos=tos,
        ttl=ttl,
        invalid_ip_length=invalid_ip_length,
    )


def _pcap_records(raw_pcap: bytes) -> list[tuple[int, bytes]]:
    """Read classic microsecond PCAP records without float timestamp loss."""
    if len(raw_pcap) < 24:
        raise SanitizationError("truncated classic PCAP global header")
    magic = raw_pcap[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic in {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
        raise SanitizationError("nanosecond PCAP input is unsupported")
    else:
        raise SanitizationError("invalid classic PCAP magic")
    _, major, minor, _, _, _, linktype = struct.unpack_from(
        f"{endian}IHHIIII", raw_pcap, 0
    )
    if (major, minor) != (2, 4):
        raise SanitizationError(f"unsupported PCAP version {major}.{minor}")
    if linktype != PCAP_LINKTYPE_ETHERNET:
        raise SanitizationError(f"unsupported PCAP link type {linktype}")

    records: list[tuple[int, bytes]] = []
    cursor = 24
    while cursor < len(raw_pcap):
        if cursor + 16 > len(raw_pcap):
            raise SanitizationError("truncated PCAP record header")
        seconds, microseconds, captured_length, _ = struct.unpack_from(
            f"{endian}IIII", raw_pcap, cursor
        )
        cursor += 16
        if microseconds >= MICROSECONDS_PER_SECOND:
            raise SanitizationError("invalid PCAP microsecond field")
        end = cursor + captured_length
        if end > len(raw_pcap):
            raise SanitizationError("truncated PCAP packet data")
        records.append(
            (
                seconds * MICROSECONDS_PER_SECOND + microseconds,
                raw_pcap[cursor:end],
            )
        )
        cursor = end
    return records


def _read_capture(raw_pcap: bytes) -> list[ParsedPacket]:
    packets = [
        _parse_tcp_frame(index, timestamp_us, frame)
        for index, (timestamp_us, frame) in enumerate(_pcap_records(raw_pcap))
    ]
    if not packets:
        raise SanitizationError("empty input PCAP")
    return packets


def _identify_client(packets: Sequence[ParsedPacket]) -> tuple[int, bytes, int]:
    for packet in packets:
        if packet.flags & TCP_SYN and not packet.flags & TCP_ACK:
            return packet.endpoint_source

    endpoint_443: set[tuple[int, bytes, int]] = set()
    all_endpoints: set[tuple[int, bytes, int]] = set()
    for packet in packets:
        src = packet.endpoint_source
        dst = packet.endpoint_destination
        all_endpoints.update((src, dst))
        if packet.sport == 443:
            endpoint_443.add(src)
        if packet.dport == 443:
            endpoint_443.add(dst)
    server = next(iter(endpoint_443)) if len(endpoint_443) == 1 else None
    if server is not None and len(all_endpoints) == 2:
        return next(endpoint for endpoint in all_endpoints if endpoint != server)
    return packets[0].endpoint_source


def _assign_directions(
    packets: Sequence[ParsedPacket], client: tuple[int, bytes, int]
) -> None:
    for packet in packets:
        if packet.endpoint_source == client:
            packet.direction = "client"
        elif packet.endpoint_destination == client:
            packet.direction = "server"
        else:
            raise SanitizationError(f"packet {packet.index}: more than one TCP flow")


def _directional_base(packets: Sequence[ParsedPacket], direction: str) -> int | None:
    for packet in packets:
        if packet.direction == direction and packet.flags & TCP_SYN and not packet.flags & TCP_ACK:
            return (packet.seq + 1) & 0xFFFFFFFF
    for packet in packets:
        if packet.direction == direction and packet.payload:
            return packet.seq
    return None


def _build_stream(packets: Sequence[ParsedPacket], direction: str) -> StreamView:
    base = _directional_base(packets, direction)
    segments: list[ParsedPacket] = []
    if base is None:
        return StreamView(bytearray(), bytearray(), segments)

    max_end = 0
    for packet in packets:
        if packet.direction != direction or not packet.payload:
            continue
        relative = (packet.seq - base) & 0xFFFFFFFF
        if relative >= MAX_TCP_STREAM:
            continue
        packet.relative_stream_start = relative
        segments.append(packet)
        max_end = max(max_end, relative + len(packet.payload))

    data = bytearray(max_end)
    covered = bytearray(max_end)
    for packet in sorted(segments, key=lambda item: (item.relative_stream_start or 0, item.index)):
        start = packet.relative_stream_start or 0
        end = start + len(packet.payload)
        data[start:end] = packet.payload
        covered[start:end] = b"\x01" * len(packet.payload)
    return StreamView(data, covered, segments)


def _tls_records(stream: StreamView) -> list[tuple[int, int, int]]:
    if not stream.segments:
        return []
    first_covered = next((index for index, value in enumerate(stream.covered) if value), None)
    if first_covered is None:
        return []
    cursor = first_covered
    records: list[tuple[int, int, int]] = []
    while cursor + 5 <= len(stream.data):
        if not all(stream.covered[cursor : cursor + 5]):
            break
        content_type = stream.data[cursor]
        major = stream.data[cursor + 1]
        minor = stream.data[cursor + 2]
        record_length = int.from_bytes(stream.data[cursor + 3 : cursor + 5], "big")
        if not (
            20 <= content_type <= 24
            and major == 3
            and minor <= 4
            and record_length <= MAX_TLS_RECORD
        ):
            break
        record_end = cursor + 5 + record_length
        records.append((cursor, record_end, content_type))
        if record_end > len(stream.data) or not all(stream.covered[cursor:record_end]):
            break
        cursor = record_end
    return records


def _overlapping_packet_indices(
    stream: StreamView, start: int, end: int
) -> set[int]:
    overlapping: set[int] = set()
    for packet in stream.segments:
        segment_start = packet.relative_stream_start or 0
        segment_end = segment_start + len(packet.payload)
        if segment_start < end and segment_end > start:
            overlapping.add(packet.index)
    return overlapping


def _handshake_removals(
    packets: Sequence[ParsedPacket], streams: dict[str, StreamView]
) -> tuple[dict[int, set[str]], set[int], set[int], bool]:
    reasons: dict[int, set[str]] = {}

    def mark(index: int, reason: str) -> None:
        reasons.setdefault(index, set()).add(reason)

    tcp_indices: set[int] = set()
    tls_indices: set[int] = set()
    for packet in packets:
        if packet.flags & TCP_SYN:
            tcp_indices.add(packet.index)
            mark(packet.index, "tcp_syn")

    synack = next(
        (
            packet
            for packet in packets
            if packet.direction == "server"
            and packet.flags & TCP_SYN
            and packet.flags & TCP_ACK
        ),
        None,
    )
    if synack is not None:
        expected_ack = (synack.seq + 1) & 0xFFFFFFFF
        third_ack = next(
            (
                packet
                for packet in packets
                if packet.index > synack.index
                and packet.direction == "client"
                and packet.flags & TCP_ACK
                and not packet.flags & TCP_SYN
                and packet.ack == expected_ack
            ),
            None,
        )
        if third_ack is not None:
            tcp_indices.add(third_ack.index)
            mark(third_ack.index, "tcp_third_ack")

    observed_tls_setup = False
    for stream in streams.values():
        for start, end, content_type in _tls_records(stream):
            if content_type not in {20, 22}:
                continue
            observed_tls_setup = True
            for index in _overlapping_packet_indices(stream, start, end):
                tls_indices.add(index)
                mark(index, "tls_ccs" if content_type == 20 else "tls_handshake")

    return reasons, tcp_indices, tls_indices, not observed_tls_setup


def _mask_domain_ranges(
    streams: dict[str, StreamView],
    packets: Sequence[ParsedPacket],
    label: str,
    eligible_indices: set[int],
) -> int:
    needle = label.encode("ascii", errors="ignore").lower()
    if not needle:
        return 0
    masked = 0
    for stream in streams.values():
        lower_stream = bytes(stream.data).lower()
        ranges: list[tuple[int, int]] = []
        cursor = 0
        while True:
            found = lower_stream.find(needle, cursor)
            if found < 0:
                break
            end = found + len(needle)
            if all(stream.covered[found:end]):
                ranges.append((found, end))
            cursor = found + 1

        for packet in stream.segments:
            if packet.index not in eligible_indices:
                continue
            segment_start = packet.relative_stream_start or 0
            segment_end = segment_start + len(packet.payload)
            changed = bytearray(packet.payload)
            packet_masked = 0
            for start, end in ranges:
                overlap_start = max(start, segment_start)
                overlap_end = min(end, segment_end)
                if overlap_start >= overlap_end:
                    continue
                local_start = overlap_start - segment_start
                local_end = overlap_end - segment_start
                changed[local_start:local_end] = b"x" * (local_end - local_start)
                packet_masked += local_end - local_start
            if packet_masked:
                packet.payload = bytes(changed)
                masked += packet_masked
    return masked


def _pseudonyms(
    source_sha256: str,
    *,
    original_client_mac: bytes | None = None,
    original_server_mac: bytes | None = None,
    original_client_ip: bytes | None = None,
    original_server_ip: bytes | None = None,
    original_client_port: int | None = None,
    original_server_port: int | None = None,
) -> Pseudonyms:
    digest = hmac.new(
        PSEUDONYM_KEY, bytes.fromhex(source_sha256), hashlib.sha256
    ).digest()
    client_mac = bytes([0x02]) + digest[0:5]
    server_mac = bytes([0x06]) + digest[5:10]
    client_ip = bytes([10, digest[10], digest[11], 1 + digest[12] % 254])
    server_ip = bytes([172, 16 + digest[13] % 16, digest[14], 1 + digest[15] % 254])
    client_port = 49_152 + int.from_bytes(digest[16:18], "big") % 16_384
    server_port = 32_768 + int.from_bytes(digest[26:28], "big") % 16_384

    # A pseudorandom draw can very rarely equal the original identifier.  A
    # deterministic one-step cycle makes replacement an explicit invariant.
    if client_mac == original_client_mac:
        client_mac = client_mac[:-1] + bytes([(client_mac[-1] + 1) & 0xFF])
    if server_mac == original_server_mac:
        server_mac = server_mac[:-1] + bytes([(server_mac[-1] + 1) & 0xFF])
    if client_ip == original_client_ip:
        client_ip = client_ip[:-1] + bytes([1 + client_ip[-1] % 254])
    if server_ip == original_server_ip:
        server_ip = server_ip[:-1] + bytes([1 + server_ip[-1] % 254])
    if client_port == original_client_port:
        client_port = 49_152 + (client_port - 49_152 + 1) % 16_384
    if server_port == original_server_port:
        server_port = 32_768 + (server_port - 32_768 + 1) % 16_384
    return Pseudonyms(
        client_mac=client_mac,
        server_mac=server_mac,
        client_ip=client_ip,
        server_ip=server_ip,
        client_port=client_port,
        server_port=server_port,
        client_seq_target=int.from_bytes(digest[18:22], "big"),
        server_seq_target=int.from_bytes(digest[22:26], "big"),
    )


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_ipv4_frame(
    packet: ParsedPacket,
    aliases: Pseudonyms,
    sequence_deltas: dict[str, int],
) -> bytes:
    if packet.direction == "client":
        src_mac, dst_mac = aliases.client_mac, aliases.server_mac
        src_ip, dst_ip = aliases.client_ip, aliases.server_ip
        sport, dport = aliases.client_port, aliases.server_port
        opposite = "server"
    else:
        src_mac, dst_mac = aliases.server_mac, aliases.client_mac
        src_ip, dst_ip = aliases.server_ip, aliases.client_ip
        sport, dport = aliases.server_port, aliases.client_port
        opposite = "client"

    options = packet.tcp_options
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    tcp_header_length = 20 + len(options)
    data_offset = tcp_header_length // 4
    seq = (packet.seq + sequence_deltas[packet.direction]) & 0xFFFFFFFF
    ack = packet.ack
    if packet.flags & TCP_ACK:
        ack = (ack + sequence_deltas[opposite]) & 0xFFFFFFFF

    tcp_without_checksum = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        data_offset << 4,
        packet.flags,
        packet.window,
        0,
        packet.urgent,
    ) + options + packet.payload
    pseudo_header = src_ip + dst_ip + struct.pack(
        "!BBH", 0, socket.IPPROTO_TCP, len(tcp_without_checksum)
    )
    tcp_checksum = _checksum(pseudo_header + tcp_without_checksum)
    tcp_segment = bytearray(tcp_without_checksum)
    struct.pack_into("!H", tcp_segment, 16, tcp_checksum)

    total_length = 20 + len(tcp_segment)
    if total_length > 65_535:
        raise SanitizationError(
            f"packet {packet.index}: rebuilt IPv4 packet exceeds 65535 bytes"
        )
    ipv4_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        packet.tos,
        total_length,
        0,
        0x4000,
        max(1, packet.ttl),
        socket.IPPROTO_TCP,
        0,
        src_ip,
        dst_ip,
    )
    ipv4_checksum = _checksum(ipv4_without_checksum)
    ipv4_header = bytearray(ipv4_without_checksum)
    struct.pack_into("!H", ipv4_header, 10, ipv4_checksum)

    frame = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4)
    frame += bytes(ipv4_header) + bytes(tcp_segment)
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def _sequence_deltas(
    retained: Sequence[ParsedPacket], aliases: Pseudonyms
) -> dict[str, int]:
    first: dict[str, int] = {}
    for packet in retained:
        first.setdefault(packet.direction, packet.seq)
    if set(first) != {"client", "server"}:
        # An ACK-only direction is still represented in every audited capture,
        # but retain a deterministic fallback for defensive use.
        for direction in ("client", "server"):
            first.setdefault(direction, 0)
    return {
        "client": (aliases.client_seq_target - first["client"]) & 0xFFFFFFFF,
        "server": (aliases.server_seq_target - first["server"]) & 0xFFFFFFFF,
    }


def _neutral_relative_path(source_relative_path: str) -> str:
    source = Path(source_relative_path)
    sample_id = hashlib.sha256(source_relative_path.encode("utf-8")).hexdigest()[:24]
    return str(source.parent / f"sample_{sample_id}.pcap")


def _format_drop_reasons(reasons: dict[int, set[str]]) -> str:
    return ";".join(
        f"{index}:{'+'.join(sorted(values))}"
        for index, values in sorted(reasons.items())
    )


def sanitize_one(
    source_root: str,
    destination_root: str | None,
    source_relative_path: str,
    max_packets: int,
    dry_run: bool,
) -> SanitizationResult:
    source_path = Path(source_root) / source_relative_path
    raw_pcap = source_path.read_bytes()
    source_sha256 = hashlib.sha256(raw_pcap).hexdigest()
    packets = _read_capture(raw_pcap)
    original_family = "ipv6" if packets[0].family == 6 else "ipv4"
    if any(packet.family != packets[0].family for packet in packets):
        raise SanitizationError("mixed IP families within one capture")

    inversions = sum(
        packets[index].timestamp_us < packets[index - 1].timestamp_us
        for index in range(1, len(packets))
    )
    invalid_v4 = sum(packet.family == 4 and packet.invalid_ip_length for packet in packets)
    invalid_v6 = sum(packet.family == 6 and packet.invalid_ip_length for packet in packets)

    client = _identify_client(packets)
    _assign_directions(packets, client)
    streams = {
        "client": _build_stream(packets, "client"),
        "server": _build_stream(packets, "server"),
    }
    reasons, tcp_indices, tls_indices, handshake_not_observed = _handshake_removals(
        packets, streams
    )

    dropped = set(reasons)
    label = Path(source_relative_path).parent.name
    plaintext_domain_bytes_removed = _mask_domain_ranges(
        streams, packets, label, dropped
    )
    retained_index_set = {packet.index for packet in packets} - dropped
    masked_retained_domain_bytes = _mask_domain_ranges(
        streams, packets, label, retained_index_set
    )

    retained = [packet for packet in packets if packet.index not in dropped]
    retained.sort(key=lambda packet: (packet.timestamp_us, packet.index))
    retained = retained[:max_packets]
    if not retained:
        raise SanitizationError("sanitization removed every packet")
    if not any(packet.payload for packet in retained):
        raise SanitizationError("sanitization left no encrypted TCP payload")

    first_client_packet = next(packet for packet in packets if packet.direction == "client")
    first_server_packet = next(
        (packet for packet in packets if packet.direction == "server"), None
    )
    aliases = _pseudonyms(
        source_sha256,
        original_client_mac=first_client_packet.src_mac,
        original_server_mac=(
            first_server_packet.src_mac
            if first_server_packet is not None
            else first_client_packet.dst_mac
        ),
        original_client_ip=client[1],
        original_server_ip=(
            first_server_packet.src_ip
            if first_server_packet is not None
            else first_client_packet.dst_ip
        ),
        original_client_port=client[2],
        original_server_port=(
            first_server_packet.sport
            if first_server_packet is not None
            else first_client_packet.dport
        ),
    )
    deltas = _sequence_deltas(retained, aliases)
    source_first_retained_timestamp_us = retained[0].timestamp_us
    synthetic_anchor_timestamp_us, synthetic_anchor_utc = _timestamp_anchor(
        source_relative_path
    )
    timestamp_shift_us = (
        synthetic_anchor_timestamp_us - source_first_retained_timestamp_us
    )
    output_frames: list[tuple[int, bytes]] = [
        (
            synthetic_anchor_timestamp_us
            + packet.timestamp_us
            - source_first_retained_timestamp_us,
            _build_ipv4_frame(packet, aliases, deltas),
        )
        for packet in retained
    ]

    sanitized_relative_path = _neutral_relative_path(source_relative_path)
    sanitized_sha256 = ""
    if not dry_run:
        if destination_root is None:
            raise SanitizationError("destination root is required outside dry-run mode")
        destination_path = Path(destination_root) / sanitized_relative_path
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if destination_path.exists():
            raise SanitizationError(f"refusing to overwrite {destination_path}")
        output = bytearray(
            struct.pack(
                "<IHHIIII",
                0xA1B2C3D4,
                2,
                4,
                0,
                0,
                65_535,
                PCAP_LINKTYPE_ETHERNET,
            )
        )
        for timestamp_us, frame in output_frames:
            seconds, microseconds = divmod(timestamp_us, MICROSECONDS_PER_SECOND)
            output.extend(
                struct.pack("<IIII", seconds, microseconds, len(frame), len(frame))
            )
            output.extend(frame)
        output_bytes = bytes(output)
        destination_path.write_bytes(output_bytes)
        sanitized_sha256 = hashlib.sha256(output_bytes).hexdigest()

    retained_indices = ",".join(str(packet.index) for packet in retained)
    return SanitizationResult(
        source_relative_path=source_relative_path,
        sanitized_relative_path=sanitized_relative_path,
        source_sha256=source_sha256,
        sanitized_sha256=sanitized_sha256,
        input_packets=len(packets),
        output_packets=len(retained),
        original_family=original_family,
        invalid_ipv4_lengths=invalid_v4,
        invalid_ipv6_lengths=invalid_v6,
        timestamp_inversions=inversions,
        source_first_retained_timestamp_us=source_first_retained_timestamp_us,
        synthetic_anchor_timestamp_us=synthetic_anchor_timestamp_us,
        synthetic_anchor_utc=synthetic_anchor_utc,
        timestamp_shift_us=timestamp_shift_us,
        dropped_tcp_handshake=len(tcp_indices),
        dropped_tls_handshake=len(tls_indices),
        dropped_union=len(dropped),
        plaintext_domain_bytes_removed_with_handshake=plaintext_domain_bytes_removed,
        masked_retained_domain_bytes=masked_retained_domain_bytes,
        handshake_not_observed=handshake_not_observed,
        retained_source_indices=retained_indices,
        dropped_source_indices=_format_drop_reasons(reasons),
    )


def _worker(arguments: tuple[str, str | None, str, int, bool]) -> SanitizationResult:
    return sanitize_one(*arguments)


def _source_files(source_root: Path) -> list[str]:
    return sorted(
        str(path.relative_to(source_root))
        for path in source_root.rglob("*.pcap")
        if path.is_file() and not path.name.startswith("._")
    )


def _write_manifest(path: Path, results: Sequence[SanitizationResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(results[0].as_manifest_row())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result.as_manifest_row())


def _aggregate(results: Sequence[SanitizationResult], source_root: Path) -> dict[str, object]:
    return {
        "sanitizer_version": SANITIZER_VERSION,
        "source_root": str(source_root),
        "files": len(results),
        "input_packets": sum(result.input_packets for result in results),
        "output_packets": sum(result.output_packets for result in results),
        "dropped_tcp_handshake_memberships": sum(
            result.dropped_tcp_handshake for result in results
        ),
        "dropped_tls_handshake_memberships": sum(
            result.dropped_tls_handshake for result in results
        ),
        "dropped_union": sum(result.dropped_union for result in results),
        "minimum_output_packets": min(result.output_packets for result in results),
        "maximum_output_packets": max(result.output_packets for result in results),
        "ipv6_input_files": sum(result.original_family == "ipv6" for result in results),
        "invalid_ipv4_lengths": sum(result.invalid_ipv4_lengths for result in results),
        "invalid_ipv6_lengths": sum(result.invalid_ipv6_lengths for result in results),
        "timestamp_inversions": sum(result.timestamp_inversions for result in results),
        "timestamp_normalization": {
            "policy": (
                "Each PCAP starts at its campaign's fixed synthetic UTC anchor; "
                "per-packet microsecond offsets from the first retained packet are "
                "preserved exactly. These are analysis timestamps, not collection dates."
            ),
            "2024": ANCHOR_2024_UTC,
            "2026_and_temporal_targets": ANCHOR_2026_UTC,
            "files_at_2024_anchor": sum(
                result.synthetic_anchor_timestamp_us == ANCHOR_2024_US
                for result in results
            ),
            "files_at_2026_anchor": sum(
                result.synthetic_anchor_timestamp_us == ANCHOR_2026_US
                for result in results
            ),
        },
        "plaintext_domain_bytes_removed_with_handshake": sum(
            result.plaintext_domain_bytes_removed_with_handshake for result in results
        ),
        "masked_retained_domain_bytes": sum(
            result.masked_retained_domain_bytes for result in results
        ),
        "handshake_not_observed_files": sum(
            result.handshake_not_observed for result in results
        ),
        "tls13_encrypted_handshake_limitation": (
            "TLS 1.3 handshake records carried as outer content type 23 cannot be "
            "distinguished from application data without session secrets and are retained."
        ),
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--workers", type=int, default=max(1, min(16, os.cpu_count() or 1)))
    parser.add_argument("--max-packets", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    source = args.source.resolve()
    if not source.is_dir():
        raise SanitizationError(f"source directory does not exist: {source}")
    if args.max_packets <= 0:
        raise SanitizationError("--max-packets must be positive")
    if not args.dry_run:
        if args.destination is None:
            raise SanitizationError("--destination is required unless --dry-run is used")
        destination = args.destination.resolve()
        if destination.exists() and any(destination.iterdir()):
            raise SanitizationError(f"destination must be absent or empty: {destination}")
        destination.mkdir(parents=True, exist_ok=True)
    else:
        destination = args.destination.resolve() if args.destination else None

    source_files = _source_files(source)
    if not source_files:
        raise SanitizationError("source contains no PCAP files")
    allowed_roots = {"2024", "2026", "2024-2026_test_samples"}
    observed_roots = {Path(path).parts[0] for path in source_files}
    if not observed_roots <= allowed_roots:
        raise SanitizationError(
            "unexpected top-level corpus roots: "
            + ", ".join(sorted(observed_roots - allowed_roots))
        )
    neutral_paths = [_neutral_relative_path(path) for path in source_files]
    if len(neutral_paths) != len(set(neutral_paths)):
        raise SanitizationError("neutral output filename collision")

    tasks = [
        (str(source), str(destination) if destination else None, path, args.max_packets, args.dry_run)
        for path in source_files
    ]
    results: list[SanitizationResult] = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for completed, result in enumerate(executor.map(_worker, tasks, chunksize=32), start=1):
            results.append(result)
            if completed % 2_000 == 0 or completed == len(tasks):
                print(f"processed {completed}/{len(tasks)}", file=sys.stderr, flush=True)

    results.sort(key=lambda result: result.source_relative_path)
    aggregate = _aggregate(results, source)
    if args.manifest:
        _write_manifest(args.manifest, results)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(aggregate, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SanitizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
'''
_PAYLOAD_START_V12_SOURCE = r'''#!/usr/bin/env python3
"""Build sanitizer v1.2 by trimming each v1.1 PCAP to its first TCP payload.

This is a deliberately narrow second sanitization pass.  It accepts only the
canonical Ethernet/IPv4/TCP output of ``sanitize_driftbench_v2.py`` v1.1,
removes the contiguous prefix of pure ACK packets before the first non-empty
TCP payload, and leaves every surviving frame byte unchanged.  The first
surviving packet is rebased to the campaign's fixed synthetic epoch while all
surviving inter-arrival times are preserved exactly in integer microseconds.

"Encrypted payload" is operationally defined here as non-empty TCP payload in
the already handshake-filtered v1.1 corpus.  TLS 1.3 encrypted handshake data
(outer record type 23) cannot be distinguished from application data without
TLS secrets and may therefore be the first retained payload.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import struct
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence


SANITIZER_VERSION = "driftbench-sanitizer-1.2.0"
INPUT_SANITIZER_VERSION = "driftbench-sanitizer-1.1.0"
MICROSECONDS_PER_SECOND = 1_000_000
ANCHOR_2024_US = 1_705_276_800 * MICROSECONDS_PER_SECOND
ANCHOR_2026_US = 1_768_435_200 * MICROSECONDS_PER_SECOND
ANCHOR_2024_UTC = "2024-01-15T00:00:00Z"
ANCHOR_2026_UTC = "2026-01-15T00:00:00Z"
PCAP_MAGIC_LE_US = b"\xd4\xc3\xb2\xa1"
PCAP_GLOBAL_HEADER_BYTES = 24
PCAP_RECORD_HEADER_BYTES = 16
LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6
TCP_ACK = 0x10


class PayloadStartError(RuntimeError):
    """Raised when an input or output violates the v1.2 contract."""


@dataclass(frozen=True)
class Record:
    timestamp_us: int
    captured_length: int
    original_length: int
    frame: bytes
    tcp_flags: int
    tcp_payload_length: int


@dataclass(frozen=True)
class Result:
    sanitizer_version: str
    input_sanitizer_version: str
    sanitized_relative_path: str
    source_relative_path: str
    source_sha256: str
    input_sanitized_sha256: str
    output_sanitized_sha256: str
    input_packets: int
    output_packets: int
    leading_ack_packets_removed: int
    input_first_payload_position: int
    input_first_payload_timestamp_us: int
    synthetic_anchor_timestamp_us: int
    synthetic_anchor_utc: str
    timestamp_shift_us: int
    input_retained_source_indices: str
    output_retained_source_indices: str
    removed_leading_source_indices: str


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _anchor(relative_path: str) -> tuple[int, str]:
    root = Path(relative_path).parts[0]
    if root == "2024":
        return ANCHOR_2024_US, ANCHOR_2024_UTC
    if root in {"2026", "2024-2026_test_samples"}:
        return ANCHOR_2026_US, ANCHOR_2026_UTC
    raise PayloadStartError(f"unexpected top-level panel: {root}")


def _parse_frame(frame: bytes, record_index: int) -> tuple[int, int]:
    if len(frame) < 14 + 20 + 20:
        raise PayloadStartError(f"record {record_index}: truncated Ethernet/IPv4/TCP")
    if struct.unpack_from("!H", frame, 12)[0] != ETHERTYPE_IPV4:
        raise PayloadStartError(f"record {record_index}: expected canonical IPv4")
    ip_start = 14
    version_ihl = frame[ip_start]
    if version_ihl >> 4 != 4:
        raise PayloadStartError(f"record {record_index}: invalid IPv4 version")
    ihl = (version_ihl & 0x0F) * 4
    if ihl != 20:
        raise PayloadStartError(f"record {record_index}: expected IPv4 IHL 5")
    if frame[ip_start + 9] != IPPROTO_TCP:
        raise PayloadStartError(f"record {record_index}: expected TCP")
    total_length = struct.unpack_from("!H", frame, ip_start + 2)[0]
    if total_length < ihl + 20 or ip_start + total_length > len(frame):
        raise PayloadStartError(f"record {record_index}: invalid IPv4 total length")
    tcp_start = ip_start + ihl
    tcp_header_length = (frame[tcp_start + 12] >> 4) * 4
    if tcp_header_length < 20 or tcp_start + tcp_header_length > ip_start + total_length:
        raise PayloadStartError(f"record {record_index}: invalid TCP data offset")
    flags = frame[tcp_start + 13]
    payload_length = total_length - ihl - tcp_header_length
    return flags, payload_length


def parse_pcap(raw: bytes) -> tuple[bytes, list[Record]]:
    if len(raw) < PCAP_GLOBAL_HEADER_BYTES or raw[:4] != PCAP_MAGIC_LE_US:
        raise PayloadStartError("expected little-endian microsecond classic PCAP")
    if struct.unpack_from("<I", raw, 20)[0] != LINKTYPE_ETHERNET:
        raise PayloadStartError("expected Ethernet link type")
    global_header = raw[:PCAP_GLOBAL_HEADER_BYTES]
    records: list[Record] = []
    cursor = PCAP_GLOBAL_HEADER_BYTES
    while cursor < len(raw):
        if cursor + PCAP_RECORD_HEADER_BYTES > len(raw):
            raise PayloadStartError("truncated PCAP record header")
        seconds, microseconds, captured_length, original_length = struct.unpack_from(
            "<IIII", raw, cursor
        )
        if microseconds >= MICROSECONDS_PER_SECOND:
            raise PayloadStartError("invalid PCAP microsecond field")
        frame_start = cursor + PCAP_RECORD_HEADER_BYTES
        frame_end = frame_start + captured_length
        if frame_end > len(raw):
            raise PayloadStartError("truncated PCAP frame")
        frame = raw[frame_start:frame_end]
        flags, payload_length = _parse_frame(frame, len(records))
        records.append(
            Record(
                timestamp_us=seconds * MICROSECONDS_PER_SECOND + microseconds,
                captured_length=captured_length,
                original_length=original_length,
                frame=frame,
                tcp_flags=flags,
                tcp_payload_length=payload_length,
            )
        )
        cursor = frame_end
    if not records:
        raise PayloadStartError("empty PCAP")
    if any(
        records[index].timestamp_us < records[index - 1].timestamp_us
        for index in range(1, len(records))
    ):
        raise PayloadStartError("input timestamps are not nondecreasing")
    return global_header, records


def _write_pcap(global_header: bytes, records: Sequence[Record], anchor_us: int) -> bytes:
    first_timestamp = records[0].timestamp_us
    output = bytearray(global_header)
    for record in records:
        timestamp_us = anchor_us + record.timestamp_us - first_timestamp
        seconds, microseconds = divmod(timestamp_us, MICROSECONDS_PER_SECOND)
        output.extend(
            struct.pack(
                "<IIII",
                seconds,
                microseconds,
                record.captured_length,
                record.original_length,
            )
        )
        output.extend(record.frame)
    return bytes(output)


def _split_indices(value: str, expected: int) -> list[str]:
    indices = [] if not value else value.split(",")
    if len(indices) != expected:
        raise PayloadStartError(
            f"input retained-source-index count {len(indices)} != packet count {expected}"
        )
    if any(not item.isdigit() for item in indices):
        raise PayloadStartError("invalid retained source index list")
    return indices


def trim_one(
    source_root: str,
    destination_root: str | None,
    input_row: Mapping[str, str],
    dry_run: bool,
) -> Result:
    relative_path = input_row["sanitized_relative_path"]
    source_path = Path(source_root) / relative_path
    raw = source_path.read_bytes()
    input_hash = sha256_bytes(raw)
    if input_hash != input_row["sanitized_sha256"]:
        raise PayloadStartError(f"input hash mismatch: {relative_path}")
    if input_row["sanitizer_version"] != INPUT_SANITIZER_VERSION:
        raise PayloadStartError(f"unexpected input sanitizer version: {relative_path}")

    global_header, records = parse_pcap(raw)
    try:
        first_payload = next(
            index for index, record in enumerate(records) if record.tcp_payload_length > 0
        )
    except StopIteration as exc:
        raise PayloadStartError(f"no TCP payload: {relative_path}") from exc

    for index, record in enumerate(records[:first_payload]):
        if record.tcp_payload_length != 0 or record.tcp_flags != TCP_ACK:
            raise PayloadStartError(
                f"record {index}: leading prefix is not a pure ACK in {relative_path}"
            )
    retained = records[first_payload:]
    if not retained or retained[0].tcp_payload_length <= 0:
        raise PayloadStartError(f"payload-start invariant failed: {relative_path}")

    anchor_us, anchor_utc = _anchor(relative_path)
    output = _write_pcap(global_header, retained, anchor_us)
    output_hash = sha256_bytes(output)
    if not dry_run:
        if destination_root is None:
            raise PayloadStartError("destination root is required outside dry-run mode")
        output_path = Path(destination_root) / relative_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            raise PayloadStartError(f"refusing to overwrite {output_path}")
        temporary_path = output_path.with_name(output_path.name + ".tmp")
        temporary_path.write_bytes(output)
        os.replace(temporary_path, output_path)

    input_indices = _split_indices(input_row["retained_source_indices"], len(records))
    return Result(
        sanitizer_version=SANITIZER_VERSION,
        input_sanitizer_version=INPUT_SANITIZER_VERSION,
        sanitized_relative_path=relative_path,
        source_relative_path=input_row["source_relative_path"],
        source_sha256=input_row["source_sha256"],
        input_sanitized_sha256=input_hash,
        output_sanitized_sha256=output_hash,
        input_packets=len(records),
        output_packets=len(retained),
        leading_ack_packets_removed=first_payload,
        input_first_payload_position=first_payload,
        input_first_payload_timestamp_us=retained[0].timestamp_us,
        synthetic_anchor_timestamp_us=anchor_us,
        synthetic_anchor_utc=anchor_utc,
        timestamp_shift_us=anchor_us - retained[0].timestamp_us,
        input_retained_source_indices=",".join(input_indices),
        output_retained_source_indices=",".join(input_indices[first_payload:]),
        removed_leading_source_indices=",".join(input_indices[:first_payload]),
    )


def _worker(arguments: tuple[str, str | None, dict[str, str], bool]) -> Result:
    return trim_one(*arguments)


def read_input_manifest(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise PayloadStartError("input manifest is empty")
    required = {
        "sanitizer_version",
        "sanitized_relative_path",
        "source_relative_path",
        "source_sha256",
        "sanitized_sha256",
        "retained_source_indices",
    }
    missing = required - set(rows[0])
    if missing:
        raise PayloadStartError(f"input manifest missing fields: {sorted(missing)}")
    paths = [row["sanitized_relative_path"] for row in rows]
    if len(paths) != len(set(paths)):
        raise PayloadStartError("duplicate path in input manifest")
    return rows


def write_manifest(path: Path, results: Sequence[Result]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(asdict(results[0]))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))


def aggregate(results: Sequence[Result], source_root: Path) -> dict[str, object]:
    positions: dict[str, int] = {}
    for result in results:
        key = str(result.input_first_payload_position)
        positions[key] = positions.get(key, 0) + 1
    return {
        "sanitizer_version": SANITIZER_VERSION,
        "input_sanitizer_version": INPUT_SANITIZER_VERSION,
        "source_root": str(source_root),
        "files": len(results),
        "input_packets": sum(result.input_packets for result in results),
        "output_packets": sum(result.output_packets for result in results),
        "leading_ack_packets_removed": sum(
            result.leading_ack_packets_removed for result in results
        ),
        "first_payload_position_histogram": dict(
            sorted(positions.items(), key=lambda item: int(item[0]))
        ),
        "minimum_output_packets": min(result.output_packets for result in results),
        "maximum_output_packets": max(result.output_packets for result in results),
        "files_at_2024_anchor": sum(
            result.synthetic_anchor_timestamp_us == ANCHOR_2024_US for result in results
        ),
        "files_at_2026_anchor": sum(
            result.synthetic_anchor_timestamp_us == ANCHOR_2026_US for result in results
        ),
        "frame_policy": "All surviving frame bytes and record lengths are byte-identical to v1.1.",
        "timestamp_policy": (
            "The first surviving payload packet is placed at the fixed campaign anchor; "
            "all surviving integer-microsecond IATs are preserved exactly."
        ),
        "encrypted_payload_definition": (
            "Non-empty TCP payload after v1.1 observable TCP/TLS handshake removal. "
            "TLS 1.3 encrypted handshake and application data cannot be distinguished "
            "without session secrets."
        ),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--workers", type=int, default=max(1, min(16, os.cpu_count() or 1)))
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    source = args.source.resolve()
    if not source.is_dir():
        raise PayloadStartError(f"source root does not exist: {source}")
    rows = read_input_manifest(args.input_manifest.resolve())
    on_disk = sorted(str(path.relative_to(source)) for path in source.rglob("*.pcap"))
    declared = sorted(row["sanitized_relative_path"] for row in rows)
    if on_disk != declared:
        raise PayloadStartError("input PCAP inventory does not exactly match input manifest")

    destination: Path | None = None
    if not args.dry_run:
        if args.destination is None:
            raise PayloadStartError("--destination is required unless --dry-run is used")
        destination = args.destination.resolve()
        if destination.exists() and any(destination.iterdir()):
            raise PayloadStartError(f"destination must be absent or empty: {destination}")
        destination.mkdir(parents=True, exist_ok=True)

    tasks = [
        (str(source), str(destination) if destination else None, row, args.dry_run)
        for row in rows
    ]
    results: list[Result] = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for completed, result in enumerate(executor.map(_worker, tasks, chunksize=32), 1):
            results.append(result)
            if completed % 2_000 == 0 or completed == len(tasks):
                print(f"processed {completed}/{len(tasks)}", file=sys.stderr, flush=True)
    results.sort(key=lambda result: result.sanitized_relative_path)
    report = aggregate(results, source)
    if args.manifest:
        write_manifest(args.manifest, results)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PayloadStartError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
'''
_SANITIZER_MODULES = None


def _load_embedded_module(name: str, source: str):
    module = types.ModuleType(name)
    module.__file__ = f"<embedded:{name}>"
    sys.modules[name] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def _import_canonical_sanitizers():
    global _SANITIZER_MODULES
    if _SANITIZER_MODULES is None:
        _SANITIZER_MODULES = (
            _load_embedded_module(
                "_driftbench_public_sanitizer_v11", _SANITIZER_V11_SOURCE
            ),
            _load_embedded_module(
                "_driftbench_public_payload_start_v12", _PAYLOAD_START_V12_SOURCE
            ),
        )
    return _SANITIZER_MODULES


def command_sanitize(
    config: Mapping[str, object],
    config_sha256: str,
    input_manifest: Path,
    destination: Path,
) -> None:
    rows = read_csv(
        input_manifest,
        (
            *COLLECTION_FIELDS,
            "session_id",
            "label_id",
            "split",
            "status",
            "pcap_path",
            "pcap_sha256",
        ),
    )
    if not rows or any(row["status"] != "selected" for row in rows):
        raise PipelineError("sanitize requires a non-empty selected split manifest")
    section = config.get("sanitization", {})
    if not isinstance(section, dict):
        raise PipelineError("config.sanitization must be an object")
    raw_max_packets = section.get("max_packets", 50)
    if isinstance(raw_max_packets, bool) or not isinstance(raw_max_packets, int):
        raise PipelineError("sanitization.max_packets must be an integer")
    max_packets = raw_max_packets
    if max_packets <= 0:
        raise PipelineError("sanitization.max_packets must be positive")
    sanitizer_v11, sanitizer_v12 = _import_canonical_sanitizers()

    with staged_directory(destination) as staging:
        output_rows: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory(prefix="driftbench-reference-sanitize-") as temporary:
            temporary_root = Path(temporary)
            raw_root = temporary_root / "raw"
            v11_root = temporary_root / "v1_1"
            for row in rows:
                source = _resolve_pcap(input_manifest, row)
                campaign = row["campaign"]
                if campaign not in {"2024", "2026", "2024-2026_test_samples"}:
                    raise PipelineError(f"unsupported sanitizer campaign: {campaign}")
                relative = (
                    Path(campaign)
                    / _require_safe_component(row["configuration_id"], "configuration_id")
                    / _require_safe_component(row["class_name"], "class_name")
                    / f"{_require_safe_component(row['session_id'], 'session_id')}.pcap"
                )
                temporary_input = raw_root / relative
                temporary_input.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, temporary_input)
                try:
                    first = sanitizer_v11.sanitize_one(
                        str(raw_root), str(v11_root), relative.as_posix(), max_packets, False
                    )
                    first_row = first.as_manifest_row()
                    second = sanitizer_v12.trim_one(
                        str(v11_root),
                        str(staging / "pcaps"),
                        first_row,
                        False,
                    )
                except (sanitizer_v11.SanitizationError, sanitizer_v12.PayloadStartError) as exc:
                    raise PipelineError(
                        f"canonical sanitization failed for {row['session_id']}: {exc}"
                    ) from exc
                second_values = dataclasses.asdict(second)
                output_path = staging / "pcaps" / second.sanitized_relative_path
                output_rows.append(
                    {
                        "pipeline_version": PIPELINE_VERSION,
                        **{field: row[field] for field in COLLECTION_FIELDS},
                        "session_id": row["session_id"],
                        "label_id": row["label_id"],
                        "split": row["split"],
                        "status": "sanitized",
                        "source_pcap_path": _portable_path(source, destination),
                        "source_pcap_sha256": row["pcap_sha256"],
                        "pcap_path": (Path("pcaps") / second.sanitized_relative_path).as_posix(),
                        "pcap_sha256": sha256_file(output_path),
                        **second_values,
                    }
                )
        output_rows.sort(
            key=lambda row: (
                str(row["configuration_id"]),
                str(row["class_name"]),
                str(row["split"]),
                str(row["session_id"]),
            )
        )
        fieldnames = tuple(output_rows[0])
        write_csv(staging / "sanitized_manifest.csv", output_rows, fieldnames)
        write_json(
            staging / "sanitization_report.json",
            {
                "pipeline_version": PIPELINE_VERSION,
                "config_sha256": config_sha256,
                "input_manifest_sha256": sha256_file(input_manifest),
                "sanitizer_version": sanitizer_v12.SANITIZER_VERSION,
                "input_sanitizer_version": sanitizer_v11.SANITIZER_VERSION,
                "sessions": len(output_rows),
                "source_pcaps_deleted": 0,
            },
        )


def _verify_split(rows: Sequence[Mapping[str, str]]) -> dict[str, object]:
    parent_bindings: dict[str, tuple[str, str, str]] = {}
    hash_bindings: dict[str, tuple[str, str, str]] = {}
    leakage_bindings: dict[str, tuple[str, str, str]] = {}
    parent_leakage: dict[str, str] = {}
    hash_leakage: dict[str, str] = {}
    cells: defaultdict[tuple[str, str], list[Mapping[str, str]]] = defaultdict(list)
    for row in rows:
        split = row["split"]
        if split not in {"train", "validation", "test"}:
            raise PipelineError(f"invalid split: {split}")
        binding = (row["configuration_id"], row["class_name"], split)
        existing = parent_bindings.setdefault(row["parent_group_id"], binding)
        if existing != binding:
            raise PipelineError(
                "parent group crosses a configuration, class, or split boundary: "
                f"{row['parent_group_id']}"
            )
        existing = hash_bindings.setdefault(row["pcap_sha256"], binding)
        if existing != binding:
            raise PipelineError(
                "identical PCAP content crosses a configuration, class, or split boundary: "
                f"{row['pcap_sha256']}"
            )
        leakage_group_id = row.get("leakage_group_id", "")
        if "leakage_group_id" in row:
            if not leakage_group_id:
                raise PipelineError("split manifest has an empty leakage_group_id")
            existing = leakage_bindings.setdefault(leakage_group_id, binding)
            if existing != binding:
                raise PipelineError(
                    f"leakage group crosses a boundary: {leakage_group_id}"
                )
            parent_component = parent_leakage.setdefault(
                row["parent_group_id"], leakage_group_id
            )
            hash_component = hash_leakage.setdefault(row["pcap_sha256"], leakage_group_id)
            if parent_component != leakage_group_id or hash_component != leakage_group_id:
                raise PipelineError(
                    "declared leakage_group_id does not equal the parent/hash union"
                )
        cells[(row["configuration_id"], row["class_name"])].append(row)
    for (configuration_id, class_name), cell_rows in cells.items():
        total = len(cell_rows)
        expected_validation = total * 15 // 100
        expected_test = total * 15 // 100
        observed: defaultdict[str, int] = defaultdict(int)
        for row in cell_rows:
            observed[row["split"]] += 1
        expected = {
            "train": total - expected_validation - expected_test,
            "validation": expected_validation,
            "test": expected_test,
        }
        observed_complete = {
            name: observed[name] for name in ("train", "validation", "test")
        }
        if observed_complete != expected:
            raise PipelineError(
                f"split quota mismatch for {configuration_id}/{class_name}: "
                f"{observed_complete} != {expected}"
            )
    return {
        "parent_groups": len(parent_bindings),
        "content_hash_groups": len(hash_bindings),
        "leakage_groups": len(leakage_bindings) if leakage_bindings else None,
        "split_cells": len(cells),
    }


def command_verify(
    config: Mapping[str, object],
    config_sha256: str,
    manifests: Sequence[Path],
    destination: Path,
) -> None:
    del config
    if not manifests:
        raise PipelineError("verify requires at least one input manifest")
    manifest_reports: list[dict[str, object]] = []
    for manifest in manifests:
        rows = read_csv(manifest)
        if not rows:
            raise PipelineError(f"manifest is empty: {manifest}")
        if "pcap_path" not in rows[0] or "pcap_sha256" not in rows[0]:
            raise PipelineError(f"manifest lacks PCAP binding fields: {manifest}")
        paths: set[str] = set()
        sessions: set[str] = set()
        verified = 0
        for row in rows:
            path = row.get("pcap_path", "")
            digest = row.get("pcap_sha256", "")
            if not path and not digest:
                continue
            if not path or not digest:
                raise PipelineError(f"partial PCAP binding in {manifest}")
            if path in paths:
                raise PipelineError(f"duplicate PCAP path in {manifest}: {path}")
            paths.add(path)
            session_id = row.get("session_id", "")
            if session_id:
                if session_id in sessions:
                    raise PipelineError(
                        f"duplicate session_id in {manifest}: {session_id}"
                    )
                sessions.add(session_id)
            _resolve_pcap(manifest, row)
            verified += 1
        extra: dict[str, object] = {}
        if "split" in rows[0]:
            extra = _verify_split(rows)
        manifest_reports.append(
            {
                "manifest": str(manifest.resolve()),
                "manifest_sha256": sha256_file(manifest),
                "rows": len(rows),
                "verified_pcaps": verified,
                **extra,
            }
        )
    with staged_directory(destination) as staging:
        write_json(
            staging / "verification.json",
            {
                "pipeline_version": PIPELINE_VERSION,
                "status": "passed",
                "config_sha256": config_sha256,
                "manifests": manifest_reports,
            },
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect = subparsers.add_parser("collect")
    collect.add_argument("--schedule", type=Path, required=True)
    collect.add_argument("--output", type=Path, required=True)

    for name in ("sessionize", "annotate", "select", "sanitize"):
        command = subparsers.add_parser(name)
        command.add_argument("--input-manifest", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument(
        "--input-manifest", type=Path, action="append", required=True
    )
    verify.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config, config_sha256 = load_config(args.config.resolve())
    if args.command == "collect":
        command_collect(
            config, config_sha256, args.schedule.resolve(), args.output
        )
    elif args.command == "sessionize":
        command_sessionize(
            config, config_sha256, args.input_manifest.resolve(), args.output
        )
    elif args.command == "annotate":
        command_annotate(
            config, config_sha256, args.input_manifest.resolve(), args.output
        )
    elif args.command == "select":
        command_select(
            config, config_sha256, args.input_manifest.resolve(), args.output
        )
    elif args.command == "sanitize":
        command_sanitize(
            config, config_sha256, args.input_manifest.resolve(), args.output
        )
    elif args.command == "verify":
        command_verify(
            config,
            config_sha256,
            [path.resolve() for path in args.input_manifest],
            args.output,
        )
    else:  # pragma: no cover - argparse enforces the choices.
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PipelineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
