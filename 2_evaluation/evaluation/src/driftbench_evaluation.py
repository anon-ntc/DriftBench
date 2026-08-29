#!/usr/bin/env python3
"""Build deterministic DriftBench classifier workload plans.

The logical matrix contains seven models, the frozen 44 evaluation cells, and
seeds 0/1/2 (924 logical evaluation jobs). Every model uses canonical,
session-disjoint source train and validation roles and frozen target-test
sessions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


RELEASE_VERSION = "driftbench-open-science-evaluation-v1"
SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if SCRIPT_DIRECTORY.name == "src":
    # Installed release layout: evaluation/src/driftbench_evaluation.py.
    WORKSPACE_ROOT = SCRIPT_DIRECTORY.parent
    DEFAULT_ASSET_ROOT = WORKSPACE_ROOT
else:
    # Repository development layout: scripts/<this file> plus release_assets/.
    WORKSPACE_ROOT = SCRIPT_DIRECTORY.parent
    DEFAULT_ASSET_ROOT = (
        WORKSPACE_ROOT
        / "release_assets"
        / "driftbench_v2_open_science_release_v1"
        / "evaluation"
    )
DEFAULT_SPEC = DEFAULT_ASSET_ROOT / "specification" / "evaluation_spec.json"
DEFAULT_RECIPES = DEFAULT_ASSET_ROOT / "recipes" / "model_recipes.json"
DEFAULT_ENVIRONMENTS = DEFAULT_ASSET_ROOT / "environments" / "runtime_matrix.json"
DEFAULT_ACQUISITION = DEFAULT_ASSET_ROOT / "recipes" / "upstream_acquisition.json"

MODEL_KEYS = (
    "lim",
    "nprintml",
    "yatc",
    "trafficformer",
    "mhnet",
    "tfe_gnn",
    "etbert",
)
SEEDS = (0, 1, 2)
KINDS = ("cross_condition", "matched_reference")


class ContractError(ValueError):
    """Raised when a release recipe or requested plan violates the contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ContractError(f"cannot read JSON authority {path}: {error}") from error
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"invalid JSON authority {path}: {error}") from error
    if type(value) is not dict:
        raise ContractError(f"JSON authority is not an object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _portable_authority_path(path: Path) -> str:
    """Prefer a repository-relative authority locator when one is available."""

    try:
        return str(path.resolve().relative_to(WORKSPACE_ROOT.resolve()))
    except ValueError:
        return str(path)


def _cell_records(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    fields = spec.get("cell_fields")
    values = spec.get("cells")
    if (
        type(fields) is not list
        or not fields
        or not all(isinstance(field, str) for field in fields)
        or len(fields) != len(set(fields))
    ):
        raise ContractError("cell_fields must be a non-empty unique list")
    if type(values) is not list:
        raise ContractError("cells must be a list")
    records: list[dict[str, Any]] = []
    for index, row in enumerate(values, start=1):
        if type(row) is not list or len(row) != len(fields):
            raise ContractError(f"cell row {index} does not match cell_fields")
        records.append(dict(zip(fields, row, strict=True)))
    return records


def load_contract(
    spec_path: Path = DEFAULT_SPEC, recipes_path: Path = DEFAULT_RECIPES
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and validate the portable release authorities."""

    spec = _load_json(spec_path)
    recipes = _load_json(recipes_path)
    if spec.get("release_version") != RELEASE_VERSION:
        raise ContractError("evaluation spec release_version differs")
    if recipes.get("release_version") != RELEASE_VERSION:
        raise ContractError("model recipes release_version differs")
    if spec.get("seeds") != list(SEEDS):
        raise ContractError("seed contract must be exactly [0, 1, 2]")
    if spec.get("models") != list(MODEL_KEYS):
        raise ContractError("model order/coverage differs")

    records = _cell_records(spec)
    if len(records) != 44:
        raise ContractError("evaluation specification must contain exactly 44 cells")
    expected_ids = [f"E{number:03d}" for number in range(1, 45)]
    ids = [row.get("evaluation_id") for row in records]
    if ids != expected_ids:
        raise ContractError("evaluation IDs/order must be exactly E001--E044")
    if [row.get("ordinal") for row in records] != list(range(1, 45)):
        raise ContractError("evaluation ordinals/order differ")
    kind_counts = Counter(row.get("evaluation_kind") for row in records)
    if kind_counts != Counter({"cross_condition": 34, "matched_reference": 10}):
        raise ContractError("evaluation-kind counts differ from 34 cross + 10 matched")
    for row in records:
        kind = row.get("evaluation_kind")
        source = row.get("source_configuration_id")
        target = row.get("target_configuration_id")
        if kind not in KINDS:
            raise ContractError(f"unrecognized evaluation kind: {kind}")
        if not isinstance(source, str) or not isinstance(target, str):
            raise ContractError("source/target configuration IDs must be strings")
        if (kind == "matched_reference") != (source == target):
            raise ContractError(
                f"matched/source-target identity contract differs for {row['evaluation_id']}"
            )
        if row.get("class_count") != 10:
            raise ContractError(f"class count differs for {row['evaluation_id']}")

    expected = spec.get("count_contract")
    if expected != {
        "models": 7,
        "evaluation_cells_per_model": 44,
        "cross_cells_per_model": 34,
        "matched_cells_per_model": 10,
        "seeds": 3,
        "logical_evaluation_jobs": 924,
    }:
        raise ContractError("count_contract differs")

    variants = recipes.get("variants")
    routing = recipes.get("routing")
    if type(variants) is not dict or type(routing) is not dict:
        raise ContractError("model recipes require variants and routing objects")
    required_variants = set(MODEL_KEYS)
    if set(variants) != required_variants:
        raise ContractError("recipe variant coverage differs")
    for model in MODEL_KEYS:
        if routing.get(model) != {"all": model}:
            raise ContractError(f"routing differs for {model}")
    for variant_id, recipe in variants.items():
        if type(recipe) is not dict or recipe.get("variant_id") != variant_id:
            raise ContractError(f"invalid variant record: {variant_id}")
        if recipe.get("training_unit") != "session":
            raise ContractError(f"training unit differs for {variant_id}")
        if recipe.get("session_separation") != (
            "source train/validation and target test are session-disjoint"
        ):
            raise ContractError(f"session separation differs for {variant_id}")
        if type(recipe.get("training")) is not dict:
            raise ContractError(f"training recipe is absent: {variant_id}")
        if type(recipe.get("evaluation")) is not dict:
            raise ContractError(f"evaluation recipe is absent: {variant_id}")
        evaluation = recipe["evaluation"]
        if (
            evaluation.get("unit") != "session"
            or evaluation.get("role") != "frozen_target_test"
            or evaluation.get("canonical_target_test_used") is not True
        ):
            raise ContractError(f"evaluation protocol differs for {variant_id}")
    return spec, recipes


def load_environments(path: Path = DEFAULT_ENVIRONMENTS) -> dict[str, Any]:
    """Load the informational, model-free runtime matrix."""

    environments = _load_json(path)
    if environments.get("release_version") != RELEASE_VERSION:
        raise ContractError("runtime matrix release_version differs")
    records = environments.get("environments")
    if type(records) is not dict or set(records) != {
        "python312_cpu_lim",
        "python39_cpu_nprintml",
        "python312_cuda130_transformers",
    }:
        raise ContractError("runtime environment coverage differs")
    covered: set[str] = set()
    for record in records.values():
        if type(record) is not dict or type(record.get("models")) is not list:
            raise ContractError("invalid runtime environment record")
        covered.update(record["models"])
    if covered != set(MODEL_KEYS):
        raise ContractError("runtime model/variant coverage differs")
    locks = environments.get("family_locks")
    if type(locks) is not dict or set(locks) != set(MODEL_KEYS):
        raise ContractError("per-family runtime lock coverage differs")
    evaluation_root = path.parent.parent
    for model, link in locks.items():
        if (
            type(link) is not dict
            or not isinstance(link.get("path"), str)
            or not isinstance(link.get("sha256"), str)
        ):
            raise ContractError(f"invalid runtime lock link: {model}")
        lock_path = evaluation_root / link["path"]
        if _sha256(lock_path) != link["sha256"]:
            raise ContractError(f"runtime lock hash differs: {model}")
        lock = _load_json(lock_path)
        if (
            lock.get("release_version") != RELEASE_VERSION
            or lock.get("model_family") != model
            or type(lock.get("packages")) is not dict
        ):
            raise ContractError(f"runtime lock contract differs: {model}")
    return environments


def load_acquisition(path: Path = DEFAULT_ACQUISITION) -> dict[str, Any]:
    """Load repository and pretrained-resource acquisition metadata."""

    acquisition = _load_json(path)
    if acquisition.get("release_version") != RELEASE_VERSION:
        raise ContractError("upstream acquisition release_version differs")
    families = acquisition.get("families")
    if type(families) is not dict or set(families) != set(MODEL_KEYS):
        raise ContractError("upstream acquisition family coverage differs")
    for model, record in families.items():
        if type(record) is not dict:
            raise ContractError(f"invalid upstream acquisition record: {model}")
        repository = record.get("repository")
        weight = record.get("pretrained_weight")
        if type(repository) is not dict or type(weight) is not dict:
            raise ContractError(f"incomplete upstream acquisition record: {model}")
        if not all(
            isinstance(repository.get(key), str) and repository[key]
            for key in ("url", "commit")
        ):
            raise ContractError(f"invalid repository locator: {model}")
        if type(weight.get("required_by_recipe")) is not bool:
            raise ContractError(f"invalid pretrained requirement: {model}")
        for key in ("url", "expected_sha256", "target_relative_path"):
            if not isinstance(weight.get(key), str) or not weight[key]:
                raise ContractError(f"invalid pretrained acquisition field: {model}/{key}")
    return acquisition


def _select(
    allowed: Sequence[Any], requested: Sequence[Any] | None, label: str
) -> tuple[Any, ...]:
    if not requested:
        return tuple(allowed)
    unknown = sorted(set(requested) - set(allowed))
    if unknown:
        raise ContractError(f"unknown {label}: {unknown}")
    requested_set = set(requested)
    return tuple(value for value in allowed if value in requested_set)


def _route_variant(
    recipes: Mapping[str, Any], model: str, evaluation_kind: str
) -> str:
    route = recipes["routing"][model]
    return route.get(evaluation_kind, route.get("all"))


def _evaluation_semantics(recipe: Mapping[str, Any]) -> dict[str, Any]:
    evaluation = recipe["evaluation"]
    return {
        "training_unit": recipe["training_unit"],
        "evaluation_unit": evaluation["unit"],
        "evaluation_role": evaluation["role"],
        "canonical_target_test_used": evaluation["canonical_target_test_used"],
        "session_separation": recipe["session_separation"],
        "representation_adapter": evaluation["adapter"],
    }


def build_evaluation_jobs(
    spec: Mapping[str, Any],
    recipes: Mapping[str, Any],
    *,
    models: Sequence[str] | None = None,
    seeds: Sequence[int] | None = None,
    evaluation_ids: Sequence[str] | None = None,
    sources: Sequence[str] | None = None,
    targets: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Return deterministic logical model/cell/seed records."""

    selected_models = _select(MODEL_KEYS, models, "model")
    selected_seeds = _select(SEEDS, seeds, "seed")
    cells = _cell_records(spec)
    selected_ids = _select(
        tuple(row["evaluation_id"] for row in cells), evaluation_ids, "evaluation ID"
    )
    selected_id_set = set(selected_ids)
    selected_sources = set(_select(_unique_sources(spec), sources, "source"))
    all_targets = tuple(
        dict.fromkeys(row["target_configuration_id"] for row in cells)
    )
    selected_targets = set(_select(all_targets, targets, "target"))
    jobs: list[dict[str, Any]] = []
    variants = recipes["variants"]
    for model in selected_models:
        for cell in cells:
            if cell["evaluation_id"] not in selected_id_set:
                continue
            if cell["source_configuration_id"] not in selected_sources:
                continue
            if cell["target_configuration_id"] not in selected_targets:
                continue
            variant_id = _route_variant(recipes, model, cell["evaluation_kind"])
            semantics = _evaluation_semantics(variants[variant_id])
            for seed in selected_seeds:
                jobs.append(
                    {
                        "job_id": f"{model}:{cell['evaluation_id']}:seed-{seed}",
                        "model": model,
                        "recipe_variant": variant_id,
                        "seed": seed,
                        **cell,
                        **semantics,
                    }
                )
    return jobs


def _unique_sources(spec: Mapping[str, Any]) -> tuple[str, ...]:
    configured = spec.get("source_configurations")
    if type(configured) is not list or len(configured) != 10:
        raise ContractError("source_configurations must contain exactly ten entries")
    if len(set(configured)) != 10 or not all(isinstance(x, str) for x in configured):
        raise ContractError("source_configurations must be ten unique strings")
    return tuple(configured)


def build_preprocess_jobs(
    spec: Mapping[str, Any],
    recipes: Mapping[str, Any],
    *,
    models: Sequence[str] | None = None,
    sources: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Return seed-independent preprocessing records (70 for the full plan)."""

    selected_models = _select(MODEL_KEYS, models, "model")
    selected_sources = _select(_unique_sources(spec), sources, "source")
    jobs: list[dict[str, Any]] = []
    for model in selected_models:
        recipe = recipes["variants"][model]
        for source in selected_sources:
            jobs.append(
                {
                    "job_id": f"preprocess:{model}:{source}",
                    "model": model,
                    "recipe_variant": model,
                    "source_configuration_id": source,
                    "training_unit": recipe["training_unit"],
                    "representation": recipe["representation"],
                    "session_separation": recipe["session_separation"],
                    "execution": recipe["preprocessing"]["execution"],
                    "training_roles_only": recipe["preprocessing"][
                        "training_roles_only"
                    ],
                }
            )
    return jobs


def build_training_jobs(
    spec: Mapping[str, Any],
    recipes: Mapping[str, Any],
    *,
    models: Sequence[str] | None = None,
    sources: Sequence[str] | None = None,
    seeds: Sequence[int] | None = None,
) -> list[dict[str, Any]]:
    """Return grouped three-seed training records (70 full, 210 seed instances)."""

    selected_models = _select(MODEL_KEYS, models, "model")
    selected_sources = _select(_unique_sources(spec), sources, "source")
    selected_seeds = _select(SEEDS, seeds, "seed")
    jobs: list[dict[str, Any]] = []
    for model in selected_models:
        recipe = recipes["variants"][model]
        for source in selected_sources:
            jobs.append(
                {
                    "job_id": f"train:{model}:{source}",
                    "model": model,
                    "recipe_variant": model,
                    "source_configuration_id": source,
                    "training_unit": recipe["training_unit"],
                    "seeds": list(selected_seeds),
                    "seed_instances": len(selected_seeds),
                    "session_separation": recipe["session_separation"],
                    "hyperparameters": recipe["training"]["hyperparameters"],
                    "selection": recipe["training"]["selection"],
                }
            )
    return jobs


def _format(template: Any, values: Mapping[str, str]) -> Any:
    if isinstance(template, str):
        try:
            return template.format_map(values)
        except KeyError as error:
            raise ContractError(f"unknown command-template placeholder: {error}") from error
    if isinstance(template, list):
        return [_format(item, values) for item in template]
    raise ContractError("command templates must be strings or lists of strings")


def _command_values(
    args: argparse.Namespace, *, model: str, variant_id: str, source: str
) -> dict[str, str]:
    runner_root = args.runner_root or Path("RUNNER_ROOT")
    if args.runner_root is None:
        runner_scripts = runner_root / "scripts"
    elif runner_root.name in {"scripts", "src"}:
        runner_scripts = runner_root
    elif (runner_root / "scripts").is_dir():
        runner_scripts = runner_root / "scripts"
    elif (runner_root / "src").is_dir():
        runner_scripts = runner_root / "src"
    else:
        runner_scripts = runner_root / "scripts"
    return {
        "python": str(args.python),
        "runner_root": str(runner_root),
        "runner_scripts": str(runner_scripts),
        "workspace_root": str(runner_root),
        "dataset_root": str(args.dataset_root or Path("DATASET_ROOT")),
        "output_root": str(args.output_root or Path("OUTPUT_ROOT")),
        "model": model,
        "variant_id": variant_id,
        "source": source,
    }


def build_training_commands(
    jobs: Sequence[Mapping[str, Any]], recipes: Mapping[str, Any], args: argparse.Namespace
) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for job in jobs:
        variant_id = job["recipe_variant"]
        recipe = recipes["variants"][variant_id]
        values = _command_values(
            args,
            model=job["model"],
            variant_id=variant_id,
            source=job["source_configuration_id"],
        )
        argv = _format(recipe["training"]["reference_argv"], values)
        commands.append(
            {
                "command_id": job["job_id"],
                "covers_job_ids": [job["job_id"]],
                "argv": argv,
                "reference_only": True,
                "executable": False,
                "logical_seeds": job["seeds"],
            }
        )
    return commands


def build_preprocess_commands(
    jobs: Sequence[Mapping[str, Any]], recipes: Mapping[str, Any], args: argparse.Namespace
) -> list[dict[str, Any]]:
    """Emit non-executable integrated-stage references for reviewed recipes."""

    commands: list[dict[str, Any]] = []
    for job in jobs:
        variant_id = job["recipe_variant"]
        recipe = recipes["variants"][variant_id]
        values = _command_values(
            args,
            model=job["model"],
            variant_id=variant_id,
            source=job["source_configuration_id"],
        )
        argv = _format(recipe["training"]["reference_argv"], values)
        commands.append(
            {
                "command_id": job["job_id"],
                "covers_job_ids": [job["job_id"]],
                "argv": argv,
                "reference_only": True,
                "executable": False,
                "stage_scope": "integrated_preprocessing_and_training_reference",
            }
        )
    return commands


def build_evaluation_commands(
    jobs: Sequence[Mapping[str, Any]], recipes: Mapping[str, Any], args: argparse.Namespace
) -> list[dict[str, Any]]:
    """Group logical cells into reviewed source-runner invocations."""

    grouped: dict[tuple[str, str, str], list[str]] = {}
    for job in jobs:
        key = (
            job["model"],
            job["recipe_variant"],
            job["source_configuration_id"],
        )
        grouped.setdefault(key, []).append(job["job_id"])
    commands: list[dict[str, Any]] = []
    for (model, variant_id, source), job_ids in grouped.items():
        recipe = recipes["variants"][variant_id]
        template = recipe["evaluation"].get("reference_argv")
        if template is None:
            commands.append(
                {
                    "command_id": f"evaluate:{variant_id}:{source}",
                    "covers_job_ids": job_ids,
                    "argv": None,
                    "reference_only": True,
                    "executable": False,
                    "integrated_into_training": True,
                }
            )
            continue
        values = _command_values(
            args, model=model, variant_id=variant_id, source=source
        )
        argv = _format(template, values)
        commands.append(
            {
                "command_id": f"evaluate:{variant_id}:{source}",
                "covers_job_ids": job_ids,
                "argv": argv,
                "reference_only": True,
                "executable": False,
                "postfilter_to_covered_job_ids": recipe["evaluation"].get(
                    "postfilter_to_covered_job_ids", False
                ),
            }
        )
    return commands


def _filters(args: argparse.Namespace) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("model", "source", "target", "seed", "evaluation_id"):
        value = getattr(args, key, None)
        if value:
            result[key] = list(value)
    return result


def _base_document(
    command: str,
    args: argparse.Namespace,
    spec_path: Path,
    recipes_path: Path,
    environments_path: Path,
    acquisition_path: Path,
) -> dict[str, Any]:
    return {
        "release_version": RELEASE_VERSION,
        "command": command,
        "dry_run": True,
        "workloads_executed": False,
        "commands_emitted": bool(args.emit_commands),
        "authorities": {
            "evaluation_spec": {
                "path": _portable_authority_path(spec_path),
                "sha256": _sha256(spec_path),
            },
            "model_recipes": {
                "path": _portable_authority_path(recipes_path),
                "sha256": _sha256(recipes_path),
            },
            "runtime_matrix": {
                "path": _portable_authority_path(environments_path),
                "sha256": _sha256(environments_path),
            },
            "upstream_acquisition": {
                "path": _portable_authority_path(acquisition_path),
                "sha256": _sha256(acquisition_path),
            },
        },
        "filters": _filters(args),
    }


def make_document(args: argparse.Namespace) -> dict[str, Any]:
    spec_path = Path(args.spec)
    recipes_path = Path(args.recipes)
    environments_path = Path(args.environments)
    acquisition_path = Path(args.acquisition)
    spec, recipes = load_contract(spec_path, recipes_path)
    environments = load_environments(environments_path)
    acquisition = load_acquisition(acquisition_path)
    document = _base_document(
        args.action,
        args,
        spec_path,
        recipes_path,
        environments_path,
        acquisition_path,
    )

    if args.action == "plan":
        eval_jobs = build_evaluation_jobs(spec, recipes)
        preprocess_jobs = build_preprocess_jobs(spec, recipes)
        training_jobs = build_training_jobs(spec, recipes)
        document.update(
            {
                "count_contract": spec["count_contract"],
                "derived_counts": {
                    "preprocessing_jobs": len(preprocess_jobs),
                    "grouped_training_jobs": len(training_jobs),
                    "training_seed_instances": sum(
                        job["seed_instances"] for job in training_jobs
                    ),
                    "logical_evaluation_jobs": len(eval_jobs),
                },
                "model_order": list(MODEL_KEYS),
                "seeds": list(SEEDS),
                "execution_policy": spec["execution_policy"],
                "runtime_environment_ids": list(environments["environments"]),
                "upstream_family_ids": list(acquisition["families"]),
                "included_payload_types": spec["included_payload_types"],
            }
        )
        if args.emit_commands:
            document["commands"] = build_training_commands(
                training_jobs, recipes, args
            ) + build_evaluation_commands(eval_jobs, recipes, args)
        return document

    if args.action == "preprocess":
        jobs = build_preprocess_jobs(
            spec, recipes, models=args.model, sources=args.source
        )
        document.update(
            {
                "job_count": len(jobs),
                "jobs": jobs,
                "stage_scope": "integrated_preprocessing_and_training_reference",
            }
        )
        if args.emit_commands:
            document["commands"] = build_preprocess_commands(jobs, recipes, args)
        return document

    if args.action == "train":
        jobs = build_training_jobs(
            spec,
            recipes,
            models=args.model,
            sources=args.source,
            seeds=args.seed,
        )
        document.update(
            {
                "grouped_job_count": len(jobs),
                "seed_instance_count": sum(job["seed_instances"] for job in jobs),
                "jobs": jobs,
            }
        )
        if args.emit_commands:
            document["commands"] = build_training_commands(jobs, recipes, args)
        return document

    jobs = build_evaluation_jobs(
        spec,
        recipes,
        models=args.model,
        seeds=args.seed,
        evaluation_ids=args.evaluation_id,
        sources=args.source,
        targets=args.target,
    )
    document.update(
        {
            "job_count": len(jobs),
            "jobs": jobs,
        }
    )
    if args.emit_commands:
        document["commands"] = build_evaluation_commands(jobs, recipes, args)
    if args.action == "matrix":
        selected_evaluation_ids = {
            job["evaluation_id"] for job in jobs
        }
        document["matrix_shape"] = {
            "models": len({job["model"] for job in jobs}),
            "evaluation_cells": len(selected_evaluation_ids),
            "seeds": len({job["seed"] for job in jobs}),
        }
    return document


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--recipes", type=Path, default=DEFAULT_RECIPES)
    parser.add_argument("--environments", type=Path, default=DEFAULT_ENVIRONMENTS)
    parser.add_argument("--acquisition", type=Path, default=DEFAULT_ACQUISITION)
    parser.add_argument(
        "--runner-root",
        "--workspace-root",
        dest="runner_root",
        type=Path,
        help="root used only to format non-executable reference paths",
    )
    parser.add_argument("--dataset-root", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--python", default="python3")
    parser.add_argument(
        "--emit-commands",
        action="store_true",
        help="include non-executable reference argv arrays",
    )
    parser.add_argument("--compact", action="store_true")


def _add_model_source_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", action="append", choices=MODEL_KEYS)
    parser.add_argument("--source", action="append")


def _add_matrix_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model", action="append", choices=MODEL_KEYS)
    parser.add_argument("--source", action="append")
    parser.add_argument("--target", action="append")
    parser.add_argument("--seed", action="append", type=int, choices=SEEDS)
    parser.add_argument("--evaluation-id", action="append")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    plan = subparsers.add_parser("plan", help="show the complete workload contract")
    _add_common_options(plan)

    preprocess = subparsers.add_parser(
        "preprocess", help="list seed-independent preprocessing units"
    )
    _add_common_options(preprocess)
    _add_model_source_filters(preprocess)

    train = subparsers.add_parser("train", help="list grouped three-seed fits")
    _add_common_options(train)
    _add_model_source_filters(train)
    train.add_argument("--seed", action="append", type=int, choices=SEEDS)

    evaluate = subparsers.add_parser(
        "evaluate", help="list logical model/cell/seed evaluations"
    )
    _add_common_options(evaluate)
    _add_matrix_filters(evaluate)

    matrix = subparsers.add_parser(
        "matrix", help="materialize the complete logical evaluation matrix"
    )
    _add_common_options(matrix)
    _add_matrix_filters(matrix)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        document = make_document(args)
    except ContractError as error:
        parser.error(str(error))
    print(
        json.dumps(
            document,
            indent=None if args.compact else 2,
            separators=(",", ":") if args.compact else None,
            sort_keys=True,
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
