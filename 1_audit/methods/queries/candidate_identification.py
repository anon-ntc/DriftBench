#!/usr/bin/env python3
"""Reconstruct and validate the three candidate-identification routes."""

from __future__ import annotations

import csv
import gzip
import json
import re
import sys
import unicodedata
from pathlib import Path


HERE = Path(__file__).resolve().parent
METHODS = HERE.parent
PACKAGE = METHODS.parent
CORPUS = PACKAGE / "corpus"


def read_csv(path: Path) -> list[dict[str, str]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def truth(value: object) -> bool:
    return str(value).strip().lower() == "true"


def normalize(value: str) -> str:
    text = re.sub(r"https?\s*:\s*//[\w./?=&%#~:+-]+", " ", str(value or ""), flags=re.I)
    text = re.sub(r"\bwww\.[\w./?=&%#~:+-]+", " ", text, flags=re.I)
    text = unicodedata.normalize("NFKD", text).lower()
    text = re.sub(r"[^a-z0-9+.-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def compiled(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(pattern, re.I) for pattern in patterns]


def route_memberships() -> tuple[set[str], set[str], set[str]]:
    specification = json.loads((METHODS / "candidate_queries.json").read_text(encoding="utf-8"))
    records = read_csv(CORPUS / "publication_records.csv.gz")
    retained = [row for row in records if truth(row["retained_for_candidate_identification"])]

    general_rows = read_csv(CORPUS / "general_route_components.csv")
    route_g = {row["record_id"] for row in general_rows}

    grouped = specification["routes"]["R"]
    traffic_patterns = compiled(grouped["traffic_patterns"])
    task_patterns = compiled(grouped["task_patterns"])
    route_r: set[str] = set()
    for row in retained:
        combined = normalize(row["title"] + " " + row.get("abstract", ""))
        if any(pattern.search(combined) for pattern in traffic_patterns) and any(
            pattern.search(combined) for pattern in task_patterns
        ):
            route_r.add(row["record_id"])

    protocol = specification["routes"]["P"]
    traffic_pattern = re.compile(protocol["traffic_pattern"], re.I)
    task_pattern = re.compile(protocol["task_pattern"], re.I)
    exclusion_pattern = re.compile(protocol["route_local_exclusion_pattern"], re.I)
    route_p = {
        row["record_id"]
        for row in retained
        if traffic_pattern.search(row["title"])
        and task_pattern.search(row["title"])
        and not exclusion_pattern.search(row["title"])
    }

    return route_g, route_r, route_p


def exact_cells(route_g: set[str], route_r: set[str], route_p: set[str]) -> dict[str, int]:
    return {
        "G_only": len(route_g - route_r - route_p),
        "R_only": len(route_r - route_g - route_p),
        "P_only": len(route_p - route_g - route_r),
        "G_R_only": len((route_g & route_r) - route_p),
        "G_P_only": len((route_g & route_p) - route_r),
        "R_P_only": len((route_r & route_p) - route_g),
        "G_R_P": len(route_g & route_r & route_p),
        "union": len(route_g | route_r | route_p),
    }


def main() -> int:
    specification = json.loads((METHODS / "candidate_queries.json").read_text(encoding="utf-8"))
    route_g, route_r, route_p = route_memberships()
    cells = exact_cells(route_g, route_r, route_p)
    observed = {
        "route_G": len(route_g),
        "route_R": len(route_r),
        "route_P": len(route_p),
        "overlap": cells,
    }
    expected = {
        "route_G": specification["routes"]["G"]["expected_records"],
        "route_R": specification["routes"]["R"]["expected_records"],
        "route_P": specification["routes"]["P"]["expected_records"],
        "overlap": specification["expected_overlap"],
    }
    valid = observed == expected
    print(json.dumps({"valid": valid, "observed": observed}, indent=2, sort_keys=True))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())

