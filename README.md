# DriftBench

Public artifact for the study, *"Conditions Apply: The Limits of Evaluation Protocols in Encrypted Network Traffic Classification"*

The two main sections:

1. `1_audit/` documents how recent network traffic classification research constructs datasets and evaluates client, network, and temporal conditions (RQ1, RQ2).
2. `2_evaluation/` provides the DriftBench dataset and the public materials used to study those condition changes empirically (RQ3).

## Repository guide

### Literature audit

[`1_audit/`](1_audit/README.md) contains the artifacts generated through the literature audit of network traffic classification research published between 2020 and 2025. It contains the frozen publication universe, candidate selection, paper-level eligibility decisions, normalized dataset and evaluation coding, evidence records, schemas, derived results, and an offline rebuild program.

Its principal analytical units are 109 included papers, 447 complete class schemes for RQ1, and 554 eligible evaluation designs for RQ2.

- [`methods/`](1_audit/methods/README.md) defines the venue frame, publication filters, candidate searches, eligibility rules, and condition coding.

- [`corpus/`](1_audit/corpus/README.md) contains the publication records, candidate frame, screening decisions, and included-paper metadata.

- [`coding/`](1_audit/coding/README.md) contains canonical datasets, dataset uses, class schemes, evaluation designs, RQ decisions, and evidence.

- [`results/`](1_audit/results/README.md) contains regenerated screening and research-question summaries.

- [`schemas/`](1_audit/schemas/README.md) defines identifiers, columns, enumerations, and relationships between released tables.

- [`scripts/`](1_audit/scripts/README.md) contains the deterministic offline rebuild and validation entry point.

### Empirical evaluation

[`2_evaluation/`](2_evaluation/README.md) contains the sanitized DriftBench traffic corpus, frozen split metadata, collection and preprocessing pipeline, seven-family classifier evaluation plan, traffic-distribution analysis, and figures.

- [`driftbench/`](2_evaluation/driftbench/README.md) is the released dataset. It contains compressed PCAP archives, the public manifest, frozen general and temporal split files, configuration metadata, and the shared ten-class label schema.

- [`collection_pipeline/`](2_evaluation/collection_pipeline/README.md) contains self-contained script for collection, TCP sessionization, SNI annotation, deterministic selection, PCAP sanitization, and manifest verification.

- [`evaluation/`](2_evaluation/evaluation/README.md) contains the public 44-cell plan for seven classifier families, model recipes, upstream acquisition metadata, runtime locks, protocol definitions, and a declarative runner.

- [`distribution_shift/`](2_evaluation/distribution_shift/README.md) contains identifier-free packet observations, traffic descriptives, within-class distances, robustness checks, figure data, rendered figures, analysis methods, and recomputation programs.

- [`paper_assets/`](2_evaluation/paper_assets/) contains figures, their machine-readable source rows, and tables describing the dataset design, evaluation pairs, and traffic features.

## Quick start

##### Rebuild the literature audit

```bash
cd 1_audit
python3 scripts/rebuild.py
```

##### Inspect the collection pipeline

```bash
cd 2_evaluation
python3 collection_pipeline/driftbench_pipeline.py --help
```

##### Inspect the evaluation plan

```bash
cd 2_evaluation
python3 evaluation/src/driftbench_evaluation.py plan
```

##### Recompute distribution-shift tables and figures

```bash
cd 2_evaluation/distribution_shift
python3 src/recompute_traffic_tables.py --root .
python3 src/generate_traffic_figures.py --data-root figure_data --output-root regenerated_figures
```