# Corpus construction methods

This directory contains the executable and tabular specification of the publication frame, publication filtering, candidate retrieval, paper eligibility, and condition coding used to construct and analyze the paper corpus.

The frame covers 2020 through 2025 for 16 venues. DBLP publication streams and year values define the enumeration frame. The DBLP query is in `queries/dblp_universe.sparql`. Records are deduplicated first by normalized DOI and otherwise by normalized title, venue, and year. The frozen enumeration contains 48,876 unique publication records and no duplicate keys.

`venue_frame.csv` defines the venue names, venue families, DBLP streams, years, and venue-specific handling. `venue_year_coverage.csv` reports all 96 venue-year cells and supplies the corresponding DBLP and official proceedings locations. `publication_filter_rules.csv` records the ordered publication-track rules and the number of records assigned by each rule.

The complete machine-readable query specification is `candidate_queries.json`. `queries/candidate_identification.py` replays Routes R and P over the compressed publication table, joins the recorded Route G components, and verifies the route and overlap counts.

The three routes contain 1,571 unique records. Their exact membership cells are 827 G-only, 204 R-only, 82 P-only, 138 G-and-R-only, 186 G-and-P-only, 5 R-and-P-only, and 129 in all three routes.

The publication filtering retained 43,463 records for candidate identification. Detailed eligibility review excluded 1,462 of the 1,571 candidates and included 109 papers. The substantive criteria used in that review are recorded in `ELIGIBILITY_CRITERIA.md` and the decision codes are in `../corpus/exclusion_codes.csv`.

`CODING_RULES.md` defines canonical dataset identity, complete class schemes, client, network, and temporal values, the RQ1 support gate, the RQ2 holdout gate, design distinctness, aggregation, and evidence handling.

The complete methods-table column inventory and field definitions are in `../schemas/table_columns.md`.

## Reproduction

From the package root, run:

```bash
python3 methods/queries/candidate_identification.py
python3 methods/validate_corpus.py
```

Both commands are read-only and use only packaged inputs.
