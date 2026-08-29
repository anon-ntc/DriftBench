# Public schemas and identifiers

Schema files in this directory define coding-table columns, coding enumerations and foreign keys, and the complete set of columns used.

Paper identifiers and canonical-dataset identifiers remain stable across the release. Class-scheme, evaluation-design, evidence, RQ1 and RQ2 use deterministic identifiers. Fields containing multiple identifiers use a pipe-delimited list. Empty lists are stored as empty strings. Condition values are `client`, `network`, and `temporal`.

## Files

- `coding_tables.schema.json` defines all coding-table columns, primary keys, row counts, enumerations, and foreign keys.
- `coding_data_dictionary.md` explains coding units and shared field meanings.
- `table_columns.md` is the complete cross-directory column inventory and field glossary.