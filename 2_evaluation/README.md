# Empirical Evaluation

This folder contains the sanitized traffic corpus, split metadata, the data-construction pipeline recipes for the seven classifier families, and the traffic-only distribution-shift analysis.

## Directory guide

- `driftbench/` contains the released dataset. 
  - `pcaps/` holds the compressed PCAP archives for the general, temporal-source, and temporal-target cohorts. 
  - `public_manifest.csv.gz` binds released files to their classes, configurations, hashes, and grouping identifiers. 
  - `splits/` contains the frozen split assignments. 
  - `configurations.csv` and `label_schemas.json` define the configuration and label metadata.

- `collection_pipeline/` contains the self-contained `driftbench_pipeline.py` script and its usage guide. The script implements collection, TCP sessionization, SNI annotation, deterministic split selection, PCAP sanitization, and manifest verification.

- `evaluation/` contains the public 44-cell classifier evaluation plan for seven model families. 
    - `specification/` defines protocols, labels, and evaluation cells. 
    - `recipes/` records model procedures and upstream source acquisition. 
    - `environments/` contains the runtime matrix and pinned dependency locks. 
    - `src/` contains the declarative dry-run planner.

- `distribution_shift/` contains the traffic-only distribution-shift analysis. 
  - `observations/` stores the identifier-free packet observations. 
  - `tables/` contains descriptives, distances, robustness checks, and cohort inventories. 
  - `figure_data/` and `figures/` contain the selected plotting data and rendered figures. 
  - `methods/` records the analysis contract.
  - `src/` contains the table recomputation and figure generation programs.

- `paper_assets/` contains the publication-ready copies used by the paper. 
  - `figures/` contains the PDF, PNG, and SVG figures. 
  - `figure_data/` contains their machine-readable source rows. 
  - `tables/` contains the dataset-design, evaluation-pair, and traffic-feature tables.

## Quick start

```bash
python3 collection_pipeline/driftbench_pipeline.py --help
python3 evaluation/src/driftbench_evaluation.py plan
python3 evaluation/src/driftbench_evaluation.py matrix --model lim
```
