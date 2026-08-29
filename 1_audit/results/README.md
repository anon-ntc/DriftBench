# Derived results

The tables in this directory are regenerated from the released corpus and coding records by `scripts/rebuild.py`.

## Files

- `screening_flow.csv` reconciles publication enumeration, filtering, candidate review, exclusion, and inclusion.
- `venue_family_summary.csv` reports retained records, candidate records, and included papers by venue family.
- `candidate_overlap.csv` reports the exact three-route candidate overlap.
- `structural_counts.csv` reports the dataset, class-scheme, design, and decision-table sizes.
- `rq1_scheme_summary.csv` summarizes class-scheme outcomes for each collection-condition dimension.
- `rq2_design_summary.csv` summarizes evaluation-design outcomes for each dimension.
- `rq1_dataset_summary.csv` provides the alternate canonical-dataset aggregation.
- `rq2_paper_summary.csv` provides the alternate paper aggregation.

The manuscript-facing RQ1 denominator is 447 complete class schemes. The manuscript-facing RQ2 denominator is 554 eligible evaluation designs.

Each outcome summary contains one row for each of `client`, `network`, and `temporal`. The denominator column names the unit being aggregated, followed by the three mutually exclusive outcome counts. `structural_counts.csv` uses `item` and `records` columns. The screening and overlap tables use a stage or membership label followed by a record count.

From the package root, run `python3 scripts/rebuild.py` to regenerate every file in this directory.