# Audit coding tables

This directory contains the dataset, class-scheme, evaluation-design, RQ1, RQ2, evidence, and normalization records. The tables form one linked release. Paper identifiers join to the final paper corpus, and dataset identifiers join to the canonical dataset registry in this directory.

## Contents

| File | Rows | Unit |
|---|---:|---|
| `canonical_datasets.csv` | 193 | Canonical dataset |
| `paper_dataset_uses.csv` | 309 | Paper and canonical-dataset association |
| `class_schemes.csv` | 495 | Paper-specific class scheme associated with one dataset |
| `evaluation_designs.csv` | 603 | Distinct evaluation construction |
| `rq1_scheme_decisions.csv` | 1,341 | Complete scheme and condition dimension |
| `rq1_dataset_summary.csv` | 516 | Canonical dataset and condition dimension |
| `rq2_design_decisions.csv` | 1,662 | Eligible design and condition dimension |
| `rq2_paper_summary.csv` | 327 | Included paper and condition dimension |
| `evidence.csv` | 2,616 | Source-located evidence statement |
| `structural_corrections.csv` | 79 | Retained structural normalization decision |
| `condition_interpretation_decisions.csv` | 77 | Retained condition-boundary interpretation |

## Analytical universes

`class_schemes.csv` is the complete master table. It contains 447 eligible complete schemes, 47 eligible partial schemes, and one excluded scheme. Only the 447 complete schemes enter RQ1. Each has one decision for `client`, one for `network`, and one for `temporal`, producing 1,341 RQ1 rows. These complete schemes occur in 103 papers and map to 172 canonical datasets. The dataset summary therefore contains 172 datasets times three dimensions, or 516 rows.

`evaluation_designs.csv` is also a master table. It contains 554 eligible designs and 49 excluded designs. Only the 554 eligible designs enter RQ2. Each has one decision for the three collection dimensions, producing 1,662 RQ2 rows. Eligible designs occur in 107 papers. The paper summary retains all 109 included papers across all three dimensions, producing 327 rows. A paper with no reconstructable eligible design is represented by a `not_documented` paper summary with an evaluation count of zero.

## Join paths

- `paper_id` joins to `../corpus/included_papers.csv`.
- `dataset_id` joins to `canonical_datasets.csv`.
- `use_id`, `scheme_id`, `design_id`, and `evidence_id` are public identifiers local to this release.
- RQ1 scheme decisions join through `scheme_id`.
- RQ2 design decisions join through `design_id`.
- Fields ending in `_ids` contain zero or more identifiers separated by ` | `.
- Evidence identifiers link coding and normalization decisions to `evidence.csv`.

Paper and canonical-dataset identifiers are preserved. Other public identifiers are assigned deterministically from the sorted frozen unit keys.

## Evidence policy

Every evidence row retains a `source_type`. A canonical web URL is retained when one is available. Page, paper-page, section, table, appendix, repository, or metadata locators are retained in dedicated fields.

Five evidence rows represent calculations or corpus-registry evidence without an external URL. Their `source_type`, locator, and evidence statement identify the evidentiary basis. Ten official web or repository records use the canonical page itself as the locator and therefore have no separate page or section value.

## Structural and condition decisions

`structural_corrections.csv` records the final normalization decisions that affect retained public datasets, schemes, designs, fields, or links. Each row targets one or more retained public identifiers.

`condition_interpretation_decisions.csv` records final scope-boundary interpretations for retained RQ1 and RQ2 rows. If one structural decision applies to multiple retained split schemes, the table contains one row for each retained target.