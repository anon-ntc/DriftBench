#!/usr/bin/env python3
"""Validate the publication-ready methods and corpus package."""

from __future__ import annotations

import csv
import gzip
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path


METHODS = Path(__file__).resolve().parent
PACKAGE = METHODS.parent
CORPUS = PACKAGE / "corpus"


def read_csv(path: Path) -> list[dict[str, str]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def truth(value: object) -> bool:
    return str(value).strip().lower() == "true"


def check(name: str, condition: bool, observed: object, expected: object) -> dict[str, object]:
    return {
        "check": name,
        "pass": bool(condition),
        "observed": observed,
        "expected": expected,
    }


def main() -> int:
    publications = read_csv(CORPUS / "publication_records.csv.gz")
    candidates = read_csv(CORPUS / "candidate_records.csv")
    decisions = read_csv(CORPUS / "selection_decisions.csv")
    papers = read_csv(CORPUS / "included_papers.csv")
    general = read_csv(CORPUS / "general_route_components.csv")
    coverage = read_csv(METHODS / "venue_year_coverage.csv")
    rules = read_csv(METHODS / "publication_filter_rules.csv")

    publication_ids = {row["record_id"] for row in publications}
    candidate_ids = {row["record_id"] for row in candidates}
    paper_ids = {row["paper_id"] for row in papers}
    retained_ids = {row["record_id"] for row in publications if truth(row["retained_for_candidate_identification"])}
    included_candidates = {row["record_id"] for row in candidates if row["eligibility_decision"] == "Included"}
    excluded_candidates = {row["record_id"] for row in candidates if row["eligibility_decision"] == "Excluded"}

    route_counts = {
        "G": sum(truth(row["route_G"]) for row in candidates),
        "R": sum(truth(row["route_R"]) for row in candidates),
        "P": sum(truth(row["route_P"]) for row in candidates),
    }
    membership_counts = Counter(row["route_membership"] for row in candidates)
    expected_membership = {
        "G": 827,
        "R": 204,
        "P": 82,
        "G | R": 138,
        "G | P": 186,
        "R | P": 5,
        "G | R | P": 129,
    }
    family_counts = Counter(row["venue_family"] for row in candidates)
    expected_families = {
        "Security and privacy": 671,
        "Networking": 174,
        "Measurement": 108,
        "Artificial intelligence": 526,
        "Web": 92,
    }

    query_run = subprocess.run(
        [sys.executable, str(METHODS / "queries" / "candidate_identification.py")],
        capture_output=True,
        text=True,
        check=False,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    query_result = json.loads(query_run.stdout) if query_run.stdout else {"valid": False}

    forbidden = [
        "/Users" + "/",
        "broad_ntc" + "_audit",
        "tls" + "_audit",
        "audit" + "/work",
        "audit" + "/ledger",
        "re" + "coding",
        "first" + "-coder",
        "second" + "-coder",
        "manual" + "_batch",
    ]
    text_files = [
        path
        for path in [*METHODS.rglob("*"), *CORPUS.rglob("*")]
        if path.is_file() and path.suffix not in {".gz", ".pyc"}
    ]
    forbidden_hits = []
    for path in text_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in forbidden:
            if token.lower() in text.lower():
                forbidden_hits.append({"file": str(path.relative_to(PACKAGE)), "token": token})

    checks = [
        check("publication row count", len(publications) == 48876, len(publications), 48876),
        check("unique publication identifiers", len(publication_ids) == 48876, len(publication_ids), 48876),
        check("retained publication count", len(retained_ids) == 43463, len(retained_ids), 43463),
        check("candidate count", len(candidates) == 1571, len(candidates), 1571),
        check("candidate identifiers unique", len(candidate_ids) == 1571, len(candidate_ids), 1571),
        check("outside candidate count", len(retained_ids - candidate_ids) == 41892, len(retained_ids - candidate_ids), 41892),
        check("candidate exclusions", len(excluded_candidates) == 1462, len(excluded_candidates), 1462),
        check("candidate inclusions", len(included_candidates) == 109, len(included_candidates), 109),
        check("included-paper table", len(papers) == 109, len(papers), 109),
        check("included papers match candidate decisions", paper_ids == included_candidates, len(paper_ids ^ included_candidates), 0),
        check("all candidates retained", candidate_ids <= retained_ids, len(candidate_ids - retained_ids), 0),
        check("selection decision rows", len(decisions) == 48876, len(decisions), 48876),
        check("general route component rows", len(general) == 1280, len(general), 1280),
        check("route totals", route_counts == {"G": 1280, "R": 476, "P": 402}, route_counts, {"G": 1280, "R": 476, "P": 402}),
        check("route membership cells", dict(membership_counts) == expected_membership, dict(membership_counts), expected_membership),
        check("candidate venue families", dict(family_counts) == expected_families, dict(family_counts), expected_families),
        check("venue-year cells", len(coverage) == 96, len(coverage), 96),
        check("venue-year coverage complete", all(row["coverage_status"] == "Complete" for row in coverage), sum(row["coverage_status"] == "Complete" for row in coverage), 96),
        check("filter rule records", sum(int(row["matched_records"]) for row in rules) == 48876, sum(int(row["matched_records"]) for row in rules), 48876),
        check(
            "filter rule retained records",
            sum(int(row["matched_records"]) for row in rules if truth(row["retained_for_candidate_identification"])) == 43463,
            sum(int(row["matched_records"]) for row in rules if truth(row["retained_for_candidate_identification"])),
            43463,
        ),
        check("candidate query replay", query_run.returncode == 0 and query_result.get("valid") is True, query_result.get("valid"), True),
        check("forbidden provenance strings", not forbidden_hits, forbidden_hits, []),
    ]
    valid = all(item["pass"] for item in checks)
    print(json.dumps({"valid": valid, "checks": checks}, indent=2, sort_keys=True))
    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
