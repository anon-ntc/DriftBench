# Coding table data dictionary

This schema covers the coding tables in `coding/`.

## Identifier policy

Paper identifiers and canonical dataset identifiers are stable corpus identifiers. Uses, schemes, designs, evidence records, and RQ decisions use deterministic publication identifiers assigned from the sorted frozen source keys. Pipe-delimited identifier fields use ` | ` as the delimiter.

## Analytical units

- A paper-dataset use records one paper using one canonical dataset.
- A class scheme records one paper-specific fixed label scheme associated with one canonical dataset.
- A complete class scheme contains every target class within the associated canonical dataset and enters the RQ1 denominator.
- An evaluation design records one distinct data partition and evaluation construction. Only rows marked `eligible` enter the RQ2 denominator.
- RQ1 scheme decisions contain one row for each complete scheme and each collection dimension.
- RQ1 dataset summaries aggregate complete scheme outcomes within canonical datasets.
- RQ2 design decisions contain one row for each eligible evaluation design and each collection dimension.
- RQ2 paper summaries aggregate eligible design outcomes within papers. Papers without a reconstructable eligible design remain represented by `not_documented` summaries.

## Table guide

| Table | One row represents | Primary identifier |
|---|---|---|
| `canonical_datasets.csv` | One canonical traffic source boundary | `dataset_id` |
| `paper_dataset_uses.csv` | One paper and canonical dataset association | `use_id` |
| `class_schemes.csv` | One paper-specific label scheme associated with one dataset | `scheme_id` |
| `evaluation_designs.csv` | One distinct data partition and evaluation construction | `design_id` |
| `rq1_scheme_decisions.csv` | One complete scheme and condition-dimension decision | `rq1_scheme_decision_id` |
| `rq1_dataset_summary.csv` | One canonical dataset and condition-dimension summary | `rq1_dataset_summary_id` |
| `rq2_design_decisions.csv` | One eligible design and condition-dimension decision | `rq2_design_decision_id` |
| `rq2_paper_summary.csv` | One paper and condition-dimension summary | `rq2_paper_summary_id` |
| `evidence.csv` | One source-located evidence statement | `evidence_id` |
| `structural_corrections.csv` | One retained structural normalization decision | `normalization_id` |
| `condition_interpretation_decisions.csv` | One retained condition-boundary interpretation | `condition_decision_id` |

## Shared field meanings

- `paper_id` refers to the included-paper corpus.
- `dataset_id` refers to the canonical dataset registry.
- Fields ending in `_ids` contain zero or more public identifiers separated by ` | `.
- `complete_scheme_in_dataset` is `yes` only when the associated dataset contains every target class in that scheme.
- `eligibility_status` identifies whether a scheme or design enters its corresponding analytical universe.
- `condition_pair` gives the contrasted condition values when they are recoverable.
- `decision_basis` is the concise rationale for the published outcome.
- `confidence` records evidentiary confidence, not coder agreement.
- Empty strings represent unavailable or inapplicable values.

Excluded evaluation designs remain in the master design table for scope transparency. An excluded design can have an empty `dataset_ids` field when its reported input was not admitted to the canonical dataset registry.

## Evidence fields

Evidence rows retain a source type, a canonical URL when one is available, and page, paper-page, section, table, appendix, or metadata locators. Local file paths, local PDF names and workflow lineage fields are not published.

## Decision fields

RQ1 outcomes are `supported`, `documented_no_support`, and `not_documented`. RQ2 outcomes are `documented_holdout`, `documented_no_holdout`, and `not_documented`. Each decision refers to exactly one of `client`, `network`, or `temporal`.

## Normalization ledgers

`structural_corrections.csv` records final structural normalization decisions using retained public identifiers. `condition_interpretation_decisions.csv` records final boundary interpretations that target retained RQ decisions.
