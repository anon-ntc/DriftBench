# DriftBench traffic-distribution assets

This directory contains the distribution-shift analysis.

- `tables/` contains inventories, group summaries, within-class distances, robustness checks, composites, and first-40 positional results.
- `observations/` contains privacy-preserving packet observations for the held-out and general all-session cohorts.
- `figure_data/` contains the exact selected CSV rows used for paper figures 2--4;
- `figures/` contains deterministic PNG, SVG, and PDF renderings.
- `src/generate_traffic_figures.py` regenerates those figures using the curated `figure_data/` directory.
- `src/recompute_traffic_tables.py` independently recomputes the paper-claim path from the two identifier-free observation files and curated pair table.
- `src/requirements-lock.txt` pins the exact NumPy, Matplotlib, pandas, and seaborn versions used with Python 3.12.3 for these public recipes.

Regenerate the figures into a new directory with:

```bash
python src/generate_traffic_figures.py --data-root figure_data --output-root regenerated_figures
```

Recompute and validate the traffic tables with:

```bash
python src/recompute_traffic_tables.py --root .
```

The recomputation covers observation invariants and counts, numeric and categorical descriptives, every within-class distance, all deterministic bootstrap summaries and sensitivity/rank tables, all first-40 results, pair-level traffic composites, and the three paper figure-data CSVs. It also reconstructs directional pair mappings and validates all observation-derived cohort counts.
