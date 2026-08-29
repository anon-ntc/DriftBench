# Publication corpus

This directory contains the sanitized publication frame, candidate set, eligibility decisions, and final included-paper corpus.

## Files

- `publication_records.csv.gz` contains all 48,876 deduplicated DBLP publication records. It records publication filtering, candidate membership, and final disposition without local file paths or workflow provenance.
- `candidate_records.csv` contains the 1,571 unique records selected by at least one candidate-identification route. It includes route membership and the final eligibility decision.
- `selection_decisions.csv` gives the final disposition of every enumerated publication record.
- `included_papers.csv` lists the 109 included papers and the evidence supporting paper-level eligibility.
- `general_route_components.csv` records the exact 1,280-record membership of Route G (see ../methods/README.md) and its retrieval components.
- `general_route_component_summary.csv` reports the mutually exclusive primary component counts for Route G.
- `candidate_route_overlap.csv` gives the seven mutually exclusive route-membership cells.
- `screening_flow.csv` reconciles the complete record flow.
- `venue_family_summary.csv` reports retained records, candidates, and included papers by venue family.
- `publication_filter_summary.csv` reports the mutually exclusive publication-type assignments.
- `final_disposition_summary.csv` reports the final mutually exclusive disposition codes for all records.
- `exclusion_codes.csv` defines the eligibility decision codes.

The complete corpus-column inventory and field definitions are in `../schemas/table_columns.md`.

## Headline reconciliation

The DBLP enumeration contains 48,876 records. Publication filtering excludes 5,413 and retains 43,463 for candidate identification. The three candidate routes yield 1,571 unique records, leaving 41,892 retained records outside the candidate-review frame. Detailed eligibility review excludes 1,462 candidates and includes 109 papers. No candidate remains unresolved.

The candidate counts by venue family are 671 for security and privacy, 174 for networking, 108 for measurement, 526 for artificial intelligence, and 92 for the Web family.

This repository does not redistribute publication PDFs. Eligibility evidence is represented by bibliographic identifiers, authoritative URLs, source descriptions, and source locations.

From the package root, `python3 scripts/rebuild.py` reconstructs `candidate_records.csv` from the compressed publication table, the released general-route components, and the two executable text searches.