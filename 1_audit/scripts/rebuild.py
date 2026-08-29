#!/usr/bin/env python3
"""Rebuild candidate membership and all publication-facing summaries offline."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

sys.dont_write_bytecode = True

from common import read_csv, write_csv


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DIMENSIONS = ("client", "network", "temporal")


def load_candidate_module() -> ModuleType:
    path = PACKAGE_ROOT / "methods" / "queries" / "candidate_identification.py"
    specification = importlib.util.spec_from_file_location("candidate_identification", path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"Could not import {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def boolean(value: bool) -> str:
    return "true" if value else "false"


def rebuild_candidates(output_root: Path) -> tuple[list[dict[str, str]], dict[str, set[str]]]:
    module = load_candidate_module()
    route_g, route_r, route_p = module.route_memberships()
    route_sets = {"G": route_g, "R": route_r, "P": route_p}
    candidate_ids = route_g | route_r | route_p

    publications = {
        row["record_id"]: row
        for row in read_csv(PACKAGE_ROOT / "corpus" / "publication_records.csv.gz")
    }
    decisions = {
        row["record_id"]: row
        for row in read_csv(PACKAGE_ROOT / "corpus" / "selection_decisions.csv")
    }

    fields = [
        "record_id",
        "title",
        "venue",
        "venue_family",
        "year",
        "route_G",
        "route_R",
        "route_P",
        "route_membership",
        "abstract_available",
        "eligibility_decision",
        "reason_code",
        "reason_label",
        "decision_evidence",
    ]
    rows: list[dict[str, str]] = []
    for record_id in sorted(candidate_ids):
        publication = publications[record_id]
        decision = decisions[record_id]
        memberships = [name for name in ("G", "R", "P") if record_id in route_sets[name]]
        rows.append(
            {
                "record_id": record_id,
                "title": publication["title"],
                "venue": publication["venue"],
                "venue_family": publication["venue_family"],
                "year": publication["year"],
                "route_G": boolean(record_id in route_g),
                "route_R": boolean(record_id in route_r),
                "route_P": boolean(record_id in route_p),
                "route_membership": " | ".join(memberships),
                "abstract_available": boolean(bool(publication.get("abstract", "").strip())),
                "eligibility_decision": decision["eligibility_decision"],
                "reason_code": decision["reason_code"],
                "reason_label": decision["reason_label"],
                "decision_evidence": decision["decision_evidence"],
            }
        )
    write_csv(output_root / "corpus" / "candidate_records.csv", fields, rows)
    return rows, route_sets


def outcome_summary(
    rows: list[dict[str, str]],
    unit_name: str,
    positive: str,
    negative: str,
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for dimension in DIMENSIONS:
        counts = Counter(row["outcome"] for row in rows if row["dimension"] == dimension)
        output.append(
            {
                "dimension": dimension,
                unit_name: sum(counts.values()),
                positive: counts[positive],
                negative: counts[negative],
                "not_documented": counts["not_documented"],
            }
        )
    return output


def rebuild_results(
    output_root: Path,
    candidates: list[dict[str, str]],
    route_sets: dict[str, set[str]],
) -> None:
    publications = read_csv(PACKAGE_ROOT / "corpus" / "publication_records.csv.gz")
    included = read_csv(PACKAGE_ROOT / "corpus" / "included_papers.csv")
    schemes = read_csv(PACKAGE_ROOT / "coding" / "class_schemes.csv")
    designs = read_csv(PACKAGE_ROOT / "coding" / "evaluation_designs.csv")
    datasets = read_csv(PACKAGE_ROOT / "coding" / "canonical_datasets.csv")
    uses = read_csv(PACKAGE_ROOT / "coding" / "paper_dataset_uses.csv")
    rq1_scheme = read_csv(PACKAGE_ROOT / "coding" / "rq1_scheme_decisions.csv")
    rq1_dataset = read_csv(PACKAGE_ROOT / "coding" / "rq1_dataset_summary.csv")
    rq2_design = read_csv(PACKAGE_ROOT / "coding" / "rq2_design_decisions.csv")
    rq2_paper = read_csv(PACKAGE_ROOT / "coding" / "rq2_paper_summary.csv")
    evidence = read_csv(PACKAGE_ROOT / "coding" / "evidence.csv")

    retained = [row for row in publications if row["retained_for_candidate_identification"] == "true"]
    candidate_exclusions = [row for row in candidates if row["eligibility_decision"] == "Excluded"]
    screening = [
        {"stage": "Publication records enumerated", "records": len(publications)},
        {"stage": "Records removed by publication filtering", "records": len(publications) - len(retained)},
        {"stage": "Records retained after publication filtering", "records": len(retained)},
        {"stage": "Retained records outside candidate review", "records": len(retained) - len(candidates)},
        {"stage": "Candidate records reviewed", "records": len(candidates)},
        {"stage": "Candidate records excluded", "records": len(candidate_exclusions)},
        {"stage": "Papers included", "records": len(included)},
    ]
    write_csv(output_root / "results" / "screening_flow.csv", ["stage", "records"], screening)

    family_names = (
        "Security and privacy",
        "Networking",
        "Measurement",
        "Artificial intelligence",
        "Web",
    )
    family_rows: list[dict[str, object]] = []
    for family in family_names:
        family_rows.append(
            {
                "venue_family": family,
                "retained_records": sum(row["venue_family"] == family for row in retained),
                "candidate_records": sum(row["venue_family"] == family for row in candidates),
                "included_papers": sum(row["venue_family"] == family for row in included),
            }
        )
    family_rows.append(
        {
            "venue_family": "Total",
            "retained_records": len(retained),
            "candidate_records": len(candidates),
            "included_papers": len(included),
        }
    )
    write_csv(
        output_root / "results" / "venue_family_summary.csv",
        ["venue_family", "retained_records", "candidate_records", "included_papers"],
        family_rows,
    )

    cells = load_candidate_module().exact_cells(route_sets["G"], route_sets["R"], route_sets["P"])
    overlap_rows = [
        {"membership": name, "records": cells[name]}
        for name in ("G_only", "R_only", "P_only", "G_R_only", "G_P_only", "R_P_only", "G_R_P", "union")
    ]
    write_csv(output_root / "results" / "candidate_overlap.csv", ["membership", "records"], overlap_rows)

    complete_schemes = [
        row
        for row in schemes
        if row["eligibility_status"] == "eligible" and row["complete_scheme_in_dataset"] == "yes"
    ]
    partial_schemes = [
        row
        for row in schemes
        if row["eligibility_status"] == "eligible" and row["complete_scheme_in_dataset"] == "no"
    ]
    eligible_designs = [row for row in designs if row["eligibility_status"] == "eligible"]
    qualifying_datasets = {row["dataset_id"] for row in uses}
    rq1_datasets = {row["dataset_id"] for row in rq1_dataset}
    rq2_papers = {row["paper_id"] for row in rq2_paper}
    structural = [
        {"item": "included_papers", "records": len(included)},
        {"item": "canonical_dataset_registry", "records": len(datasets)},
        {"item": "qualifying_used_datasets", "records": len(qualifying_datasets)},
        {"item": "paper_dataset_uses", "records": len(uses)},
        {"item": "class_scheme_registry", "records": len(schemes)},
        {"item": "complete_class_schemes", "records": len(complete_schemes)},
        {"item": "partial_class_schemes", "records": len(partial_schemes)},
        {"item": "evaluation_design_registry", "records": len(designs)},
        {"item": "eligible_evaluation_designs", "records": len(eligible_designs)},
        {"item": "rq1_scheme_condition_decisions", "records": len(rq1_scheme)},
        {"item": "rq1_canonical_datasets", "records": len(rq1_datasets)},
        {"item": "rq1_dataset_condition_summaries", "records": len(rq1_dataset)},
        {"item": "rq2_design_condition_decisions", "records": len(rq2_design)},
        {"item": "rq2_papers", "records": len(rq2_papers)},
        {"item": "rq2_paper_condition_summaries", "records": len(rq2_paper)},
        {"item": "source_located_evidence", "records": len(evidence)},
    ]
    write_csv(output_root / "results" / "structural_counts.csv", ["item", "records"], structural)

    rq1_scheme_rows = outcome_summary(
        rq1_scheme,
        "complete_class_schemes",
        "supported",
        "documented_no_support",
    )
    write_csv(
        output_root / "results" / "rq1_scheme_summary.csv",
        ["dimension", "complete_class_schemes", "supported", "documented_no_support", "not_documented"],
        rq1_scheme_rows,
    )
    rq1_dataset_rows = outcome_summary(
        rq1_dataset,
        "canonical_datasets",
        "supported",
        "documented_no_support",
    )
    write_csv(
        output_root / "results" / "rq1_dataset_summary.csv",
        ["dimension", "canonical_datasets", "supported", "documented_no_support", "not_documented"],
        rq1_dataset_rows,
    )
    rq2_design_rows = outcome_summary(
        rq2_design,
        "eligible_evaluation_designs",
        "documented_holdout",
        "documented_no_holdout",
    )
    write_csv(
        output_root / "results" / "rq2_design_summary.csv",
        ["dimension", "eligible_evaluation_designs", "documented_holdout", "documented_no_holdout", "not_documented"],
        rq2_design_rows,
    )
    rq2_paper_rows = outcome_summary(
        rq2_paper,
        "included_papers",
        "documented_holdout",
        "documented_no_holdout",
    )
    write_csv(
        output_root / "results" / "rq2_paper_summary.csv",
        ["dimension", "included_papers", "documented_holdout", "documented_no_holdout", "not_documented"],
        rq2_paper_rows,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=PACKAGE_ROOT,
        help="Directory that receives regenerated corpus and results files",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    output_root = arguments.output_root.resolve()
    candidates, route_sets = rebuild_candidates(output_root)
    rebuild_results(output_root, candidates, route_sets)
    print(f"Rebuilt candidate membership and summaries under {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
