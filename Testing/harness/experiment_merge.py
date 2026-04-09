"""
File: experiment_merge.py
Author: Matt-Ung
Last Updated: 2026-04-07
Purpose:
  Combine compatible experiment directories into one aggregate comparison view.

Summary:
  This module merges multiple sweep experiment directories when they share the
  same sample/task scope and repetition structure. It is intended for cases
  where a later follow-up sweep adds new variant families on top of an earlier
  baseline experiment and the user wants one combined experiment-level browser
  and graph view.
"""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .experiment_sweep import materialize_experiment_outputs
from .paths import RESULTS_ROOT, read_json, slugify, write_json
from .result_store import resolve_catalog_run_dir


def _safe_json(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            return read_json(path)
    except Exception:
        return {}
    return {}


def _normalize_text_list(values: Iterable[Any]) -> List[str]:
    return [str(item).strip() for item in values if str(item).strip()]


def _normalize_planned_run_cfg(run_cfg: Dict[str, Any]) -> Dict[str, Any]:
    cfg = dict(run_cfg or {})
    keys = [
        "variant_id",
        "variant_name",
        "display_label",
        "changed_variable",
        "comparison_baseline_id",
        "comparison_baseline_label",
        "pipeline",
        "pipeline_preset",
        "architecture",
        "response_scope_variant",
        "analysis_hint_variant",
        "subagent_profile",
        "worker_persona_profile",
        "worker_role_prompt_mode",
        "validator_review_level",
        "tool_profile",
        "model_profile",
        "force_model",
        "judge_mode",
        "judge_model",
        "prefer_upx_unpacked",
        "task_failure_retries",
    ]
    return {key: cfg.get(key) for key in keys if key in cfg}


def _baseline_cfg_from_manifest(experiment_manifest: Dict[str, Any]) -> Dict[str, Any]:
    planned_runs = [dict(item) for item in (experiment_manifest.get("planned_runs") or []) if isinstance(item, dict)]
    for item in planned_runs:
        if str(item.get("variant_id") or "") == "baseline":
            return _normalize_planned_run_cfg(item)
    return {}


def _load_run_entries(experiment_root: Path) -> List[Dict[str, Any]]:
    catalog = _safe_json(experiment_root / "run_catalog.json")
    run_entries: List[Dict[str, Any]] = []
    for raw_entry in (catalog.get("runs") or []):
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        run_dir = resolve_catalog_run_dir(experiment_root, entry)
        entry["run_dir"] = str(run_dir.resolve()) if run_dir.exists() else str(run_dir)
        entry["run_manifest"] = _safe_json(run_dir / "run_manifest.json")
        entry["aggregate"] = _safe_json(run_dir / "aggregate.json")
        entry["ok"] = bool(entry.get("ok")) and bool(entry.get("aggregate"))
        entry["status"] = str(entry.get("status") or ("completed" if entry.get("ok") else "failed"))
        entry["error"] = str(entry.get("error") or "")
        run_entries.append(entry)
    return run_entries


def _validate_compatibility(primary_manifest: Dict[str, Any], secondary_manifest: Dict[str, Any], secondary_root: Path) -> None:
    primary_corpus = str(primary_manifest.get("corpus") or "").strip()
    secondary_corpus = str(secondary_manifest.get("corpus") or "").strip()
    if primary_corpus != secondary_corpus:
        raise ValueError(
            f"Incompatible corpus for {secondary_root.name}: expected {primary_corpus!r}, found {secondary_corpus!r}"
        )

    primary_samples = _normalize_text_list(primary_manifest.get("selected_samples") or [])
    secondary_samples = _normalize_text_list(secondary_manifest.get("selected_samples") or [])
    if primary_samples != secondary_samples:
        raise ValueError(
            f"Incompatible selected_samples for {secondary_root.name}: expected {primary_samples}, found {secondary_samples}"
        )

    primary_tasks = _normalize_text_list(primary_manifest.get("selected_task_keys") or [])
    secondary_tasks = _normalize_text_list(secondary_manifest.get("selected_task_keys") or [])
    if primary_tasks != secondary_tasks:
        raise ValueError(
            f"Incompatible selected_task_keys for {secondary_root.name}: expected {primary_tasks}, found {secondary_tasks}"
        )

    primary_reps = int(primary_manifest.get("repetitions") or 1)
    secondary_reps = int(secondary_manifest.get("repetitions") or 1)
    if primary_reps != secondary_reps:
        raise ValueError(
            f"Incompatible repetitions for {secondary_root.name}: expected {primary_reps}, found {secondary_reps}"
        )

    primary_baseline = _baseline_cfg_from_manifest(primary_manifest)
    secondary_baseline = _baseline_cfg_from_manifest(secondary_manifest)
    if primary_baseline != secondary_baseline:
        raise ValueError(
            f"Incompatible baseline configuration for {secondary_root.name}; the follow-up experiment baseline does not match the primary experiment baseline"
        )


def plan_merged_experiment(
    primary_experiment: Path,
    *,
    additional_experiments: Iterable[Path],
    output_root: Path | None = None,
    output_experiment_id: str = "",
    include_duplicate_variants: bool = False,
) -> Dict[str, Any]:
    primary_root = primary_experiment.expanduser().resolve()
    primary_manifest = _safe_json(primary_root / "experiment_manifest.json")
    if not primary_manifest:
        raise FileNotFoundError(f"experiment_manifest.json not found under {primary_root}")

    additional_roots = [Path(item).expanduser().resolve() for item in additional_experiments]
    if not additional_roots:
        raise ValueError("At least one additional experiment is required to build a merged experiment")

    merged_planned_runs = [dict(item) for item in (primary_manifest.get("planned_runs") or []) if isinstance(item, dict)]
    seen_variant_ids = {str(item.get("variant_id") or "").strip() for item in merged_planned_runs if str(item.get("variant_id") or "").strip()}
    included_sources = [str(primary_root)]
    variant_sources: Dict[str, str] = {variant_id: primary_root.name for variant_id in seen_variant_ids}
    run_count = 0

    for secondary_root in additional_roots:
        secondary_manifest = _safe_json(secondary_root / "experiment_manifest.json")
        if not secondary_manifest:
            raise FileNotFoundError(f"experiment_manifest.json not found under {secondary_root}")
        _validate_compatibility(primary_manifest, secondary_manifest, secondary_root)
        included_sources.append(str(secondary_root))
        for item in (secondary_manifest.get("planned_runs") or []):
            if not isinstance(item, dict):
                continue
            variant_id = str(item.get("variant_id") or "").strip()
            if not variant_id:
                continue
            if not include_duplicate_variants and variant_id in seen_variant_ids:
                continue
            merged_planned_runs.append(dict(item))
            seen_variant_ids.add(variant_id)
            variant_sources[variant_id] = secondary_root.name

    run_plans = []
    for planned in merged_planned_runs:
        variant_id = str(planned.get("variant_id") or "").strip()
        run_plans.append(
            {
                "variant_id": variant_id,
                "display_label": str(planned.get("display_label") or planned.get("variant_name") or variant_id),
                "source_experiment": variant_sources.get(variant_id, primary_root.name),
            }
        )
        run_count += int(primary_manifest.get("repetitions") or 1)

    resolved_output_root = (output_root or (RESULTS_ROOT / "experiments")).expanduser().resolve()
    if output_experiment_id:
        merged_experiment_id = str(output_experiment_id).strip()
    else:
        suffix = slugify("-".join([primary_root.name] + [root.name for root in additional_roots])) or "merged"
        merged_experiment_id = f"{primary_root.name}-merged-{suffix}"
    output_dir = resolved_output_root / merged_experiment_id

    return {
        "primary_experiment_root": str(primary_root),
        "primary_experiment_id": str(primary_manifest.get("experiment_id") or primary_root.name),
        "additional_experiment_roots": [str(root) for root in additional_roots],
        "additional_experiment_ids": [root.name for root in additional_roots],
        "output_root": str(resolved_output_root),
        "output_experiment_id": merged_experiment_id,
        "output_experiment_root": str(output_dir),
        "repetitions": int(primary_manifest.get("repetitions") or 1),
        "planned_run_count": run_count,
        "variant_count": len(merged_planned_runs),
        "run_plans": run_plans,
    }


def merge_experiments(
    primary_experiment: Path,
    *,
    additional_experiments: Iterable[Path],
    output_root: Path | None = None,
    output_experiment_id: str = "",
    include_duplicate_variants: bool = False,
    overwrite: bool = False,
    skip_visuals: bool = False,
) -> Dict[str, Any]:
    plan = plan_merged_experiment(
        primary_experiment,
        additional_experiments=additional_experiments,
        output_root=output_root,
        output_experiment_id=output_experiment_id,
        include_duplicate_variants=include_duplicate_variants,
    )

    primary_root = Path(str(plan.get("primary_experiment_root") or "")).resolve()
    primary_manifest = _safe_json(primary_root / "experiment_manifest.json")
    output_dir = Path(str(plan.get("output_experiment_root") or "")).resolve()
    if output_dir.exists():
        if not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing merged experiment at {output_dir}")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    merged_manifest = dict(primary_manifest)
    merged_manifest["experiment_id"] = str(plan.get("output_experiment_id") or output_dir.name)
    merged_manifest["planned_runs"] = []
    merged_manifest["merged_experiment"] = True
    merged_manifest["merge_created_at"] = datetime.now().isoformat(timespec="seconds")
    merged_manifest["merge_primary_experiment_id"] = str(primary_manifest.get("experiment_id") or primary_root.name)
    merged_manifest["merge_source_experiment_ids"] = [
        str(primary_manifest.get("experiment_id") or primary_root.name),
        *[Path(path).name for path in (plan.get("additional_experiment_roots") or [])],
    ]
    merged_manifest["merge_source_experiment_roots"] = [
        str(primary_root),
        *[str(Path(path).resolve()) for path in (plan.get("additional_experiment_roots") or [])],
    ]

    merged_run_entries: List[Dict[str, Any]] = []
    seen_variant_ids: set[str] = set()
    source_roots = [primary_root, *[Path(path).resolve() for path in (plan.get("additional_experiment_roots") or [])]]
    variant_owner: Dict[str, str] = {}
    for source_index, source_root in enumerate(source_roots):
        source_manifest = _safe_json(source_root / "experiment_manifest.json")
        for item in (source_manifest.get("planned_runs") or []):
            if not isinstance(item, dict):
                continue
            variant_id = str(item.get("variant_id") or "").strip()
            if not variant_id:
                continue
            if source_index > 0 and not include_duplicate_variants and variant_id in seen_variant_ids:
                continue
            merged_manifest["planned_runs"].append(dict(item))
            seen_variant_ids.add(variant_id)
            variant_owner[variant_id] = source_root.name

    included_variant_ids = {str(item.get("variant_id") or "").strip() for item in merged_manifest.get("planned_runs") or [] if isinstance(item, dict)}
    for source_index, source_root in enumerate(source_roots):
        for entry in _load_run_entries(source_root):
            variant_id = str(entry.get("variant_id") or "").strip()
            if not variant_id or variant_id not in included_variant_ids:
                continue
            if not include_duplicate_variants and variant_owner.get(variant_id) != source_root.name:
                continue
            entry = dict(entry)
            entry["merged_from_experiment_id"] = source_root.name
            merged_run_entries.append(entry)

    outputs_summary = materialize_experiment_outputs(
        experiment_root=output_dir,
        experiment_manifest=merged_manifest,
        run_entries=merged_run_entries,
        skip_visuals=bool(skip_visuals),
    )

    merge_manifest = {
        "merged_at": datetime.now().isoformat(timespec="seconds"),
        "primary_experiment_id": str(primary_manifest.get("experiment_id") or primary_root.name),
        "primary_experiment_root": str(primary_root),
        "additional_experiment_ids": [Path(path).name for path in (plan.get("additional_experiment_roots") or [])],
        "additional_experiment_roots": [str(Path(path).resolve()) for path in (plan.get("additional_experiment_roots") or [])],
        "output_experiment_id": str(plan.get("output_experiment_id") or output_dir.name),
        "output_experiment_root": str(output_dir),
        "include_duplicate_variants": bool(include_duplicate_variants),
        "merged_run_count": len(merged_run_entries),
        "variant_ids": sorted(included_variant_ids),
        "outputs_summary": outputs_summary,
    }
    write_json(output_dir / "experiment_merge_manifest.json", merge_manifest)
    write_json(output_dir / "experiment_manifest.json", merged_manifest)
    return merge_manifest
