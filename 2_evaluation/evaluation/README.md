# Classifier evaluation

This directory contains the contract for the seven DriftBench classifier families. It contains specifications, recipes, runtime requirements, and upstream acquisition metadata.

## Layout

- `specification/evaluation_spec.json`: compact, hash-bound 44-cell plan, seeds, model order, and count contract.
- `recipes/model_recipes.json`: preprocessing, fitting, selection, inference, and reference argv templates for all recipe variants.
- `recipes/upstream_acquisition.json`: repository revisions and pretrained resource URLs/hashes, with unavailable values explicitly recorded.
- `environments/runtime_matrix.json`: model-to-runtime mapping and hashes for the seven per-family `*.lock.json` dependency locks.
- `src/driftbench_evaluation.py`: common CLI in a built release.

## Execution

```text
python3 src/driftbench_evaluation.py plan
python3 src/driftbench_evaluation.py preprocess
python3 src/driftbench_evaluation.py train
python3 src/driftbench_evaluation.py evaluate
python3 src/driftbench_evaluation.py matrix
```

Add `--emit-commands` to include non-executable, reference-only argv arrays.

Model and source filters are available for preprocessing. Training supports model, source, and seed filters. Evaluation and matrix planning support model, source, target, seed, and evaluation-ID filters.