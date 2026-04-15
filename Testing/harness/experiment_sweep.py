"""
File: experiment_sweep.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Orchestrate maintained baseline-first experiment sweeps for the benchmark.

Summary:
  This module plans the sweep from the experiment configuration, launches and
  monitors child runs, aggregates experiment-level outputs, and writes the
  comparison artifacts used for later analysis and visualization. It is the
  canonical multi-configuration execution path for the testing harness.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Callable, Dict, List, Tuple

from .artifacts import parse_tool_log_sections, prepare_corpus_bundles
from .budgeting import (
    evaluate_budget_status,
    evaluate_projected_experiment_budget,
    resolve_budget_config,
    summarize_record_budget,
    project_experiment_budget,
)
from .building import build_corpus
from .live_progress import start_live_view_server
from .config_groups import compute_config_group_id, normalize_run_config_group_payload
from .output_comparison import build_task_output_comparisons
from .paths import BUNDLE_ROOT, CONFIG_ROOT, PREFLIGHT_ROOT, REPO_ROOT, RESULTS_ROOT, build_run_id, ensure_dir, read_json, repo_python_executable, slugify, write_json
from .preflight import _module_available_in_python, validate_run_configuration
from .result_layout import build_experiment_output_layout
from .result_store import experiment_run_dir, run_log_path
from .runtime_limits import request_limit_env_value, resolve_testing_deep_agent_request_limit
from .reporting import _refresh_record_tool_metrics, aggregate_records
from .significance import build_significance_outputs
from .samples import build_evaluation_tasks, get_corpus_config, list_sample_binaries, load_sample_manifest
from .subprocess_utils import run_command
from .timing import build_timing_outputs
from .tool_redundancy import normalize_tool_call_entries
from .visualization import generate_experiment_visuals


def _parse_metadata(values: List[str]) -> Dict[str, str]:
    """
    Function: _parse_metadata
    Inputs:
      - values: CLI metadata fragments in `key=value` form.
    Description:
      Normalize experiment-level metadata into the dictionary recorded in the
      experiment manifest and child run manifests.
    Outputs:
      Returns a dictionary of parsed metadata entries.
    Side Effects:
      None.
    """
    parsed: Dict[str, str] = {}
    for item in values:
        if "=" not in str(item):
            continue
        key, value = str(item).split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            parsed[key] = value
    return parsed


def _load_experiment_config(path: Path | None = None) -> Dict[str, Any]:
    """
    Function: _load_experiment_config
    Inputs:
      - path: optional explicit path to an experiment sweep config file.
    Description:
      Load the maintained sweep-definition JSON, defaulting to the repo's
      canonical `experiment_sweeps.json`.
    Outputs:
      Returns the parsed sweep configuration dictionary.
    Side Effects:
      Reads the experiment configuration file from disk.
    """
    config_path = path or (CONFIG_ROOT / "experiment_sweeps.json")
    return read_json(config_path)


def _resolve_force_model(run_cfg: Dict[str, Any], model_profiles: Dict[str, Any]) -> str:
    """
    Function: _resolve_force_model
    Inputs:
      - run_cfg: normalized run configuration for one baseline or variant run.
      - model_profiles: configured model-profile mapping from the sweep config.
    Description:
      Determine the concrete forced model ID for a planned run, honoring an
      explicit run override before falling back to the selected model profile.
    Outputs:
      Returns the resolved model ID string, or an empty string when the run
      should use the runtime defaults.
    Side Effects:
      None.
    """
    explicit_force = str(run_cfg.get("force_model") or "").strip()
    if explicit_force:
        return explicit_force
    profile_name = str(run_cfg.get("model_profile") or "repo_default").strip()
    profile = model_profiles.get(profile_name) if isinstance(model_profiles, dict) else None
    if isinstance(profile, dict):
        return str(profile.get("force_model") or "").strip()
    return ""


def _build_config_group_summary_rows(successful_runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in successful_runs:
        run_manifest = entry.get("run_manifest") if isinstance(entry.get("run_manifest"), dict) else {}
        if not run_manifest:
            continue
        config_group_id = str(run_manifest.get("config_lineage_id") or "").strip()
        if not config_group_id:
            config_group_id = compute_config_group_id(run_manifest)
            run_manifest["config_lineage_id"] = config_group_id
            run_manifest["config_lineage_key"] = normalize_run_config_group_payload(run_manifest)
            run_dir = Path(str(entry.get("run_dir") or "")).resolve() if entry.get("run_dir") else None
            if run_dir:
                write_json(run_dir / "run_manifest.json", run_manifest)
        if config_group_id:
            grouped[config_group_id].append(entry)

    rows: List[Dict[str, Any]] = []
    for config_group_id, entries in sorted(grouped.items(), key=lambda item: item[0]):
        first_manifest = entries[0].get("run_manifest") if isinstance(entries[0].get("run_manifest"), dict) else {}
        config_group_key = normalize_run_config_group_payload(first_manifest)
        records: List[Dict[str, Any]] = []
        for entry in entries:
            aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
            records.extend(list(aggregate.get("records") or []))
        if not records:
            continue
        config_group_metadata = dict(config_group_key)
        config_group_metadata["config_lineage_id"] = config_group_id
        config_group_metadata["config_group_run_count"] = len(entries)
        config_group_aggregate = aggregate_records(config_group_metadata, records)
        rows.append(
            {
                "config_lineage_id": config_group_id,
                "run_count": len(entries),
                "records_count": len(records),
                "overall_score_mean": config_group_aggregate.get("overall_score_mean"),
                "task_success_rate": config_group_aggregate.get("task_success_rate"),
                "mean_relative_cost_index": config_group_aggregate.get("mean_relative_cost_index"),
                "mean_total_duration_sec": config_group_aggregate.get("mean_total_duration_sec"),
                "mean_task_wall_clock_duration_sec": config_group_aggregate.get("mean_task_wall_clock_duration_sec"),
                "corpus": config_group_key.get("corpus"),
                "pipeline": config_group_key.get("pipeline"),
                "architecture": config_group_key.get("architecture"),
                "response_scope_variant": config_group_key.get("response_scope_variant"),
                "analysis_hint_variant": config_group_key.get("analysis_hint_variant"),
                "worker_persona_profile": config_group_key.get("worker_persona_profile"),
                "worker_role_prompt_mode": config_group_key.get("worker_role_prompt_mode"),
                "selected_samples": "; ".join(config_group_key.get("selected_samples") or []),
                "selected_tasks": "; ".join(config_group_key.get("selected_tasks") or []),
                "selected_difficulties": "; ".join(config_group_key.get("selected_difficulties") or []),
            }
        )
    return rows


def _build_run_plan(
    config: Dict[str, Any],
    *,
    variable_filters: List[str] | None = None,
    corpus_override: str = "",
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], int]:
    """
    Function: _build_run_plan
    Inputs:
      - config: parsed experiment sweep configuration.
      - variable_filters: optional list of family names to include.
      - corpus_override: optional corpus name replacing the config baseline.
    Description:
      Expand the baseline-first sweep definition into the concrete list of run
      configurations the experiment runner will launch, including any family
      baselines required for controlled comparisons.
    Outputs:
      Returns the normalized baseline config, the planned run list, and the
      number of family-baseline runs inserted into the plan.
    Side Effects:
      None.
    """
    # Tutorial 5.1 in multi_agent_wf/extension_tutorial.md: add maintained
    # sweep families in `Testing/config/experiment_sweeps.json`. If a family
    # adds a new runner field, continue with Tutorial 5.3 as well.
    baseline = dict(config.get("baseline") or {})
    if corpus_override:
        baseline["corpus"] = corpus_override
    model_profiles = config.get("model_profiles") if isinstance(config.get("model_profiles"), dict) else {}
    baseline["force_model"] = _resolve_force_model(baseline, model_profiles)
    baseline["variant_id"] = "baseline"
    baseline["variant_name"] = "baseline"
    baseline["changed_variable"] = ""
    baseline["is_baseline"] = True
    baseline["is_family_baseline"] = False
    baseline["comparison_baseline_id"] = ""
    baseline["comparison_baseline_label"] = ""

    selected_filters = {str(item).strip() for item in (variable_filters or []) if str(item).strip()}
    planned_runs: List[Dict[str, Any]] = [baseline]
    for sweep in config.get("sweeps") or []:
        if not isinstance(sweep, dict):
            continue
        variable = str(sweep.get("variable") or "").strip()
        if selected_filters and variable not in selected_filters:
            continue
        family_baseline_cfg: Dict[str, Any] | None = None
        family_baseline_overrides = dict(sweep.get("baseline_overrides") or {})
        comparison_baseline_id = "baseline"
        comparison_baseline_label = "baseline"
        if family_baseline_overrides:
            family_base = dict(baseline)
            family_base.update(family_baseline_overrides)
            family_base["force_model"] = _resolve_force_model(family_base, model_profiles)
            family_base["variant_id"] = f"{variable}__baseline"
            family_base["variant_name"] = "baseline"
            family_base["changed_variable"] = variable
            family_base["variant_description"] = str(sweep.get("description") or "").strip()
            family_base["is_baseline"] = False
            family_base["is_family_baseline"] = True
            family_base["comparison_baseline_id"] = "baseline"
            family_base["comparison_baseline_label"] = "baseline"
            planned_runs.append(family_base)
            family_baseline_cfg = family_base
            comparison_baseline_id = str(family_base["variant_id"])
            comparison_baseline_label = f"{variable}:baseline"
        for variant in sweep.get("variants") or []:
            if not isinstance(variant, dict):
                continue
            run_cfg = dict(baseline)
            if family_baseline_overrides:
                run_cfg.update(family_baseline_overrides)
            run_cfg.update(dict(variant.get("overrides") or {}))
            run_cfg["force_model"] = _resolve_force_model(run_cfg, model_profiles)
            run_cfg["variant_id"] = f"{variable}__{slugify(str(variant.get('name') or 'variant'))}"
            run_cfg["variant_name"] = str(variant.get("name") or run_cfg["variant_id"]).strip()
            run_cfg["changed_variable"] = variable
            run_cfg["variant_description"] = str(sweep.get("description") or "").strip()
            run_cfg["is_baseline"] = False
            run_cfg["is_family_baseline"] = False
            run_cfg["comparison_baseline_id"] = comparison_baseline_id
            run_cfg["comparison_baseline_label"] = comparison_baseline_label
            planned_runs.append(run_cfg)
    repetitions = max(1, int(config.get("repetitions") or 1))
    return baseline, planned_runs, repetitions


def _parse_completion_payload(stdout: str) -> Dict[str, Any]:
    marker = "EVAL_RUN_RESULT_JSON::"
    for line in reversed(str(stdout or "").splitlines()):
        if line.startswith(marker):
            return json.loads(line[len(marker):].strip())
    raise ValueError("run_evaluation.py did not emit the EVAL_RUN_RESULT_JSON marker")


def _planned_run_instance(
    *,
    experiment_root: Path | None = None,
    experiment_id: str,
    corpus_name: str,
    run_cfg: Dict[str, Any],
    repetition_index: int,
    planned_repetitions: int,
    live_logs_dir: Path | None = None,
) -> Dict[str, Any]:
    variant_id = str(run_cfg.get("variant_id") or "variant").strip() or "variant"
    variant_name = str(run_cfg.get("variant_name") or variant_id).strip() or variant_id
    changed_variable = str(run_cfg.get("changed_variable") or "").strip()
    if bool(run_cfg.get("is_baseline")):
        display_label = "baseline"
    elif bool(run_cfg.get("is_family_baseline")):
        display_label = f"{changed_variable}:baseline"
    else:
        display_label = f"{changed_variable}:{variant_name}"
    resolved_experiment_root = Path(experiment_root).expanduser() if experiment_root is not None else (RESULTS_ROOT / "experiments" / experiment_id)
    run_id = f"eval-{slugify(corpus_name)}-{slugify(experiment_id)}-{slugify(variant_id)}-r{int(repetition_index)}"
    run_dir = experiment_run_dir(resolved_experiment_root, variant_id, repetition_index)
    log_path = run_log_path(run_dir)
    run_path = str(run_dir.relative_to(resolved_experiment_root))
    return {
        "variant_id": variant_id,
        "variant_name": variant_name,
        "changed_variable": changed_variable,
        "comparison_baseline_id": str(run_cfg.get("comparison_baseline_id") or "").strip(),
        "comparison_baseline_label": str(run_cfg.get("comparison_baseline_label") or "").strip(),
        "display_label": display_label,
        "is_baseline": bool(run_cfg.get("is_baseline")),
        "is_family_baseline": bool(run_cfg.get("is_family_baseline")),
        "replicate_index": int(repetition_index),
        "planned_repetitions": int(planned_repetitions),
        "status": "pending",
        "ok": None,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "run_path": run_path,
        "live_status_path": str(run_dir / "live_status.json"),
        "log_path": str(log_path),
        "log_rel_path": str(log_path.relative_to(resolved_experiment_root)),
        "pipeline": str(run_cfg.get("pipeline") or ""),
        "architecture": str(run_cfg.get("architecture") or ""),
        "response_scope_variant": str(run_cfg.get("response_scope_variant") or ""),
        "analysis_hint_variant": str(run_cfg.get("analysis_hint_variant") or ""),
        "validator_review_level": str(run_cfg.get("validator_review_level") or ""),
        "tool_profile": str(run_cfg.get("tool_profile") or ""),
        "prefer_upx_unpacked": bool(run_cfg.get("prefer_upx_unpacked")),
        "worker_persona_profile": str(run_cfg.get("worker_persona_profile") or ""),
        "worker_role_prompt_mode": str(run_cfg.get("worker_role_prompt_mode") or ""),
        "subagent_profile": str(run_cfg.get("subagent_profile") or ""),
    }


def _run_instance_key(entry: Dict[str, Any]) -> str:
    return f"{str(entry.get('variant_id') or '')}::r{int(entry.get('replicate_index') or 0)}"


def _write_run_catalog(experiment_root: Path, entries: List[Dict[str, Any]]) -> None:
    write_json(experiment_root / "run_catalog.json", {"runs": entries})


def _write_rows_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    ensure_dir(path.parent)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: List[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


"""
Function: _resolve_sweep_root
Inputs:
  - corpus_name: logical corpus name used for the sweep.
  - label: optional researcher-supplied label suffix.
  - resume_path: optional existing experiment directory or experiment id.
  - preflight_only: whether the sweep should stop after readiness checks.
Description:
  Choose the root directory that will own this sweep's artifacts. Real runs
  live under `Testing/results/experiments`, while `--preflight-only` writes
  into `Testing/results/preflight` so planning scaffolds do not pollute the
  active experiments folder.
Outputs:
  Returns the resolved root directory path for the sweep or preflight record.
Side Effects:
  Creates a new root directory when not resuming an existing sweep. Raises
  `SystemExit` when the requested mode combination is invalid.
"""
def _resolve_sweep_root(
    *,
    corpus_name: str,
    label: str = "",
    resume_path: str = "",
    preflight_only: bool = False,
) -> Path:
    normalized_resume = str(resume_path or "").strip()
    if preflight_only and normalized_resume:
        raise SystemExit(
            "--resume cannot be combined with --preflight-only. "
            "Preflight-only sweeps write to Testing/results/preflight and do not reuse experiment directories."
        )
    if normalized_resume:
        resume_dir = Path(normalized_resume)
        if not resume_dir.is_dir():
            resume_dir = RESULTS_ROOT / "experiments" / normalized_resume
        if not resume_dir.is_dir():
            raise SystemExit(f"--resume target not found: {normalized_resume}")
        return resume_dir
    if preflight_only:
        return ensure_dir(PREFLIGHT_ROOT / build_run_id("preflight", corpus_name, label))
    return ensure_dir(RESULTS_ROOT / "experiments" / build_run_id("sweep", corpus_name, label))


def _score_or_none(record: Dict[str, Any] | None) -> float | None:
    if not isinstance(record, dict):
        return None
    metrics = record.get("metrics") or {}
    value = metrics.get("overall_score_0_to_100")
    if value is not None:
        try:
            return float(value)
        except Exception:
            pass
    if str(metrics.get("judge_status") or "") == "judge_error":
        return 0.0
    return None


def _success_numeric(record: Dict[str, Any] | None) -> float:
    if not isinstance(record, dict):
        return 0.0
    return 1.0 if (record.get("metrics") or {}).get("task_success") else 0.0


def _record_key(record: Dict[str, Any]) -> str:
    sample_task_id = str(record.get("sample_task_id") or "").strip()
    if sample_task_id:
        return sample_task_id
    sample = str(record.get("sample") or "").strip()
    task_id = str(record.get("task_id") or "").strip()
    return f"{sample}::{task_id}" if sample and task_id else sample


def _group_records(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[_record_key(record)].append(record)
    return dict(grouped)


def _mean_metric(records: List[Dict[str, Any]], path: str) -> float | None:
    parts = path.split(".")
    values: List[float] = []
    for record in records:
        value: Any = record
        for part in parts:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        try:
            if value is not None:
                values.append(float(value))
        except Exception:
            continue
    return round(mean(values), 3) if values else None


def _rate_metric(records: List[Dict[str, Any]], path: str) -> float | None:
    if not records:
        return None
    parts = path.split(".")
    total = 0
    for record in records:
        value: Any = record
        for part in parts:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        total += 1 if value else 0
    return round(total / len(records), 3)


def _string_metric_mode(records: List[Dict[str, Any]], path: str) -> str:
    parts = path.split(".")
    counts: Dict[str, int] = {}
    for record in records:
        value: Any = record
        for part in parts:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        text = str(value or "").strip()
        if not text:
            continue
        counts[text] = counts.get(text, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _status_summary(records: List[Dict[str, Any]]) -> str:
    counts: Dict[str, int] = {}
    for record in records:
        status = str((record.get("metrics") or {}).get("analysis_status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    if not counts:
        return ""
    if len(counts) == 1:
        return next(iter(counts.keys()))
    return ", ".join(f"{key}:{counts[key]}" for key in sorted(counts.keys()))


def _task_group_summary(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    reference = records[0] if records else {}
    scores = [_score_or_none(record) for record in records]
    score_values = [float(value) for value in scores if value is not None]
    wall_clock_duration = _mean_metric(records, "metrics.task_wall_clock_duration_sec")
    if wall_clock_duration is None:
        wall_clock_duration = _mean_metric(records, "metrics.total_duration_sec")
    return {
        "sample": str(reference.get("sample") or ""),
        "task_id": str(reference.get("task_id") or ""),
        "task_name": str(reference.get("task_name") or ""),
        "sample_task_id": str(reference.get("sample_task_id") or _record_key(reference)),
        "difficulty": str(reference.get("difficulty") or "unknown"),
        "primary_techniques": "; ".join(reference.get("primary_techniques") or []),
        "analysis_status": _status_summary(records),
        "produced_result_rate": _rate_metric(records, "metrics.produced_result"),
        "score": round(mean(score_values), 3) if score_values else None,
        "task_success_rate": _rate_metric(records, "metrics.task_success"),
        "relative_cost_index": _mean_metric(records, "metrics.total_relative_cost_index"),
        "estimated_cost_usd": _mean_metric(records, "metrics.total_estimated_cost_usd"),
        "tool_calls_total": _mean_metric(records, "metrics.tool_calls_total"),
        "tool_exact_duplicate_calls": _mean_metric(records, "metrics.tool_exact_duplicate_calls"),
        "tool_semantic_duplicate_calls": _mean_metric(records, "metrics.tool_semantic_duplicate_calls"),
        "tool_exact_duplicate_rate": _mean_metric(records, "metrics.tool_exact_duplicate_rate"),
        "tool_semantic_duplicate_rate": _mean_metric(records, "metrics.tool_semantic_duplicate_rate"),
        "tool_cache_hit_count": _mean_metric(records, "metrics.tool_cache_hit_count"),
        "tool_most_redundant_target": _string_metric_mode(records, "metrics.tool_most_redundant_target"),
        "target_tool_hit_rate": _mean_metric(records, "metrics.target_tool_hit_rate"),
        "analysis_duration_sec": _mean_metric(records, "metrics.analysis_duration_sec"),
        "judge_duration_sec": _mean_metric(records, "metrics.judge_duration_sec"),
        "total_duration_sec": _mean_metric(records, "metrics.total_duration_sec"),
        "task_wall_clock_duration_sec": wall_clock_duration,
    }


def _group_records_by_sample(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in records:
        sample = str(record.get("sample") or "").strip()
        if sample:
            grouped[sample].append(record)
    return dict(grouped)


def _sample_group_summary(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    reference = records[0] if records else {}
    scores = [_score_or_none(record) for record in records]
    score_values = [float(value) for value in scores if value is not None]
    wall_clock_duration = _mean_metric(records, "metrics.task_wall_clock_duration_sec")
    if wall_clock_duration is None:
        wall_clock_duration = _mean_metric(records, "metrics.total_duration_sec")
    return {
        "sample": str(reference.get("sample") or ""),
        "task_count": len(records),
        "scored_task_count": len(score_values),
        "analysis_status": _status_summary(records),
        "score": round(mean(score_values), 3) if score_values else None,
        "task_success_rate": _rate_metric(records, "metrics.task_success"),
        "produced_result_rate": _rate_metric(records, "metrics.produced_result"),
        "relative_cost_index": _mean_metric(records, "metrics.total_relative_cost_index"),
        "estimated_cost_usd": _mean_metric(records, "metrics.total_estimated_cost_usd"),
        "tool_calls_total": _mean_metric(records, "metrics.tool_calls_total"),
        "tool_semantic_duplicate_calls": _mean_metric(records, "metrics.tool_semantic_duplicate_calls"),
        "tool_same_source_semantic_duplicate_calls": _mean_metric(
            records,
            "metrics.tool_same_source_semantic_duplicate_calls",
        ),
        "tool_semantic_duplicate_rate": _mean_metric(records, "metrics.tool_semantic_duplicate_rate"),
        "tool_same_source_semantic_duplicate_rate": _mean_metric(
            records,
            "metrics.tool_same_source_semantic_duplicate_rate",
        ),
        "tool_most_redundant_family": _string_metric_mode(records, "metrics.tool_most_redundant_family"),
        "tool_most_redundant_target": _string_metric_mode(records, "metrics.tool_most_redundant_target"),
        "task_wall_clock_duration_sec": wall_clock_duration,
    }


def _build_default_analysis_executable_resource_rows(
    run_entries: List[Dict[str, Any]],
    *,
    task_id: str = "default_analysis",
) -> List[Dict[str, Any]]:
    buckets: Dict[str, Dict[str, Any]] = {}
    wanted_task_id = str(task_id or "default_analysis").strip() or "default_analysis"
    for entry in list(run_entries or []):
        if not isinstance(entry, dict):
            continue
        run_id = str(entry.get("run_id") or "").strip()
        variant_id = str(entry.get("variant_id") or "").strip()
        display_label = str(entry.get("display_label") or "").strip()
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        for raw_record in list(aggregate.get("records") or []):
            if not isinstance(raw_record, dict):
                continue
            record = _refresh_record_tool_metrics(raw_record)
            record_task_id = str(record.get("task_id") or "").strip()
            if record_task_id != wanted_task_id:
                continue
            sample = str(record.get("sample") or "").strip()
            if not sample:
                continue
            bucket = buckets.setdefault(
                sample,
                {
                    "sample": sample,
                    "run_ids": set(),
                    "variant_ids": set(),
                    "display_labels": set(),
                    "analysis_statuses": [],
                    "runtime_values": [],
                    "cost_values": [],
                },
            )
            if run_id:
                bucket["run_ids"].add(run_id)
            if variant_id:
                bucket["variant_ids"].add(variant_id)
            if display_label:
                bucket["display_labels"].add(display_label)
            analysis_status = str(((record.get("metrics") or {}) if isinstance(record.get("metrics"), dict) else {}).get("analysis_status") or "").strip()
            if analysis_status:
                bucket["analysis_statuses"].append(analysis_status)
            metrics = (record.get("metrics") or {}) if isinstance(record.get("metrics"), dict) else {}
            runtime_value = metrics.get("task_wall_clock_duration_sec")
            if runtime_value is None:
                runtime_value = metrics.get("total_duration_sec")
            try:
                if runtime_value is not None:
                    bucket["runtime_values"].append(float(runtime_value))
            except Exception:
                pass
            cost_value = metrics.get("total_estimated_cost_usd")
            try:
                if cost_value is not None:
                    bucket["cost_values"].append(float(cost_value))
            except Exception:
                pass

    rows: List[Dict[str, Any]] = []
    for sample in sorted(buckets):
        bucket = buckets[sample]
        runtime_values = list(bucket.get("runtime_values") or [])
        cost_values = list(bucket.get("cost_values") or [])
        rows.append(
            {
                "sample": sample,
                "task_id": wanted_task_id,
                "completed_run_count": len(bucket.get("run_ids") or []),
                "variant_count": len(bucket.get("variant_ids") or []),
                "duration_observation_count": len(runtime_values),
                "cost_observation_count": len(cost_values),
                "mean_task_wall_clock_duration_sec": _mean_or_none(runtime_values),
                "mean_estimated_cost_usd": _mean_or_none(cost_values),
                "analysis_status": _dominant_text(list(bucket.get("analysis_statuses") or [])),
                "variants_seen": "; ".join(sorted(bucket.get("display_labels") or [])),
            }
        )
    return rows


def _stddev_or_zero(values: List[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return round(pstdev(values), 3)


def _mean_or_none(values: List[float]) -> float | None:
    if not values:
        return None
    return round(mean(values), 3)


def _dominant_text(values: List[str]) -> str:
    counts: Dict[str, int] = {}
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        counts[text] = counts.get(text, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _assess_duplicate_target(
    *,
    tool_family: str,
    duplicate_calls: int,
    call_count: int,
    unique_exact_call_shapes: int,
    stages: List[str],
    source_count: int = 0,
    same_source_duplicate_calls: int = 0,
) -> str:
    broad_scan_families = {
        "strings_scan",
        "floss_scan",
        "capa_scan",
        "binwalk_scan",
        "yara_scan",
        "ghidra_program_info",
        "ghidra_imports",
    }
    if duplicate_calls <= 0:
        return "not_duplicate"
    if tool_family == "todo_read":
        if same_source_duplicate_calls > 0:
            return "likely_wasteful_same_worker_loop"
        if source_count >= 2:
            return "likely_expected_cross_worker_read"
        return "review_needed"
    if tool_family in broad_scan_families:
        if same_source_duplicate_calls > 0:
            return "likely_wasteful_rescan"
        if source_count >= 2:
            return "likely_expected_cross_worker_overlap"
        return "review_needed"
    if unique_exact_call_shapes <= 1 and call_count >= 2:
        if same_source_duplicate_calls > 0:
            return "likely_wasteful_exact_repeat"
        if source_count >= 2:
            return "likely_expected_cross_worker_overlap"
        return "review_needed"
    if tool_family in {"ghidra_decompile_function", "ghidra_function_lookup", "ghidra_xref_lookup", "ghidra_data_listing"}:
        if same_source_duplicate_calls > 0 and call_count >= 4 and unique_exact_call_shapes <= 1:
            return "likely_wasteful_same_target_loop"
        if source_count >= 2 and same_source_duplicate_calls <= 0:
            return "likely_expected_cross_worker_overlap"
        if len(stages) > 1 and duplicate_calls <= 2:
            return "possible_cross_stage_refresh"
        return "possibly_justified_followup"
    if source_count >= 2 and same_source_duplicate_calls <= 0:
        return "likely_expected_cross_worker_overlap"
    if len(stages) > 1 and duplicate_calls <= 2:
        return "possible_cross_stage_refresh"
    return "review_needed"


def _normalized_tool_calls_from_agent_result(agent_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    calls = [call for call in list(agent_result.get("normalized_tool_calls") or []) if isinstance(call, dict)]
    if calls:
        return calls
    sections = agent_result.get("tool_log_sections") or {}
    if not isinstance(sections, dict) or not sections:
        return []
    try:
        return normalize_tool_call_entries(parse_tool_log_sections(sections))
    except Exception:
        return []


def _build_executable_summary_tables(
    *,
    run_entries: List[Dict[str, Any]],
    variant_rows: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    if not run_entries or not variant_rows:
        return {
            "per_run_rows": [],
            "executable_rows": [],
            "resource_rows": [],
            "consistency_rows": [],
            "variant_tool_rows": [],
            "executable_tool_rows": [],
            "target_rows": [],
            "source_tool_rows": [],
            "source_run_rows": [],
        }

    variant_meta_by_id = {
        str(row.get("variant_id") or ""): row
        for row in variant_rows
        if str(row.get("variant_id") or "").strip()
    }
    per_run_rows: List[Dict[str, Any]] = []
    tool_buckets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    target_buckets: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    source_tool_buckets: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}

    for entry in run_entries:
        variant_id = str(entry.get("variant_id") or "").strip()
        if not variant_id or variant_id not in variant_meta_by_id:
            continue
        meta = variant_meta_by_id[variant_id]
        aggregate = dict(entry.get("aggregate") or {})
        run_id = str(entry.get("run_id") or "")
        replicate_index = entry.get("replicate_index")
        records = [
            _refresh_record_tool_metrics(record)
            for record in list(aggregate.get("records") or [])
            if isinstance(record, dict)
        ]
        by_sample = _group_records_by_sample(records)
        for sample_name, sample_records in sorted(by_sample.items()):
            summary = _sample_group_summary(sample_records)
            per_run_rows.append(
                {
                    "variant_id": variant_id,
                    "display_label": str(meta.get("display_label") or variant_id),
                    "changed_variable": str(meta.get("changed_variable") or ""),
                    "comparison_baseline_id": str(meta.get("comparison_baseline_id") or "baseline"),
                    "comparison_baseline_label": str(meta.get("comparison_baseline_label") or "baseline"),
                    "sample": sample_name,
                    "run_id": run_id,
                    "replicate_index": replicate_index,
                    "analysis_status": summary.get("analysis_status"),
                    "task_count": summary.get("task_count"),
                    "score": summary.get("score"),
                    "task_success_rate": summary.get("task_success_rate"),
                    "produced_result_rate": summary.get("produced_result_rate"),
                    "relative_cost_index": summary.get("relative_cost_index"),
                    "estimated_cost_usd": summary.get("estimated_cost_usd"),
                    "tool_calls_total": summary.get("tool_calls_total"),
                    "tool_semantic_duplicate_calls": summary.get("tool_semantic_duplicate_calls"),
                    "tool_same_source_semantic_duplicate_calls": summary.get("tool_same_source_semantic_duplicate_calls"),
                    "tool_semantic_duplicate_rate": summary.get("tool_semantic_duplicate_rate"),
                    "tool_same_source_semantic_duplicate_rate": summary.get("tool_same_source_semantic_duplicate_rate"),
                    "tool_most_redundant_family": summary.get("tool_most_redundant_family"),
                    "tool_most_redundant_target": summary.get("tool_most_redundant_target"),
                    "task_wall_clock_duration_sec": summary.get("task_wall_clock_duration_sec"),
                }
            )

        for record in records:
            sample_name = str(record.get("sample") or "").strip()
            task_name = str(record.get("task_name") or record.get("task_id") or "")
            sample_task_id = str(record.get("sample_task_id") or "")
            agent_result = dict(record.get("agent_result") or {})
            redundancy = dict(agent_result.get("tool_redundancy") or {})
            normalized_calls = _normalized_tool_calls_from_agent_result(agent_result)
            source_tool_counters: Dict[Tuple[str, str], Dict[str, Any]] = {}

            for call in normalized_calls:
                source_label = str(call.get("source") or "").strip()
                tool_family = str(call.get("tool_family") or "").strip()
                if not source_label or not tool_family:
                    continue
                counter_bucket = source_tool_counters.setdefault(
                    (source_label, tool_family),
                    {
                        "source": source_label,
                        "tool_family": tool_family,
                        "semantic_counts": Counter(),
                        "exact_counts": Counter(),
                        "stages": set(),
                        "total_calls": 0,
                    },
                )
                counter_bucket["total_calls"] += 1
                semantic_key = str(call.get("semantic_key") or "").strip()
                exact_key = str(call.get("exact_key") or "").strip()
                if semantic_key:
                    counter_bucket["semantic_counts"][semantic_key] += 1
                if exact_key:
                    counter_bucket["exact_counts"][exact_key] += 1
                stage_label = str(call.get("stage") or "").strip()
                if stage_label:
                    counter_bucket["stages"].add(stage_label)

            for counter_bucket in source_tool_counters.values():
                source_label = str(counter_bucket.get("source") or "")
                tool_family = str(counter_bucket.get("tool_family") or "")
                key = (variant_id, sample_name, run_id, source_label, tool_family)
                bucket = source_tool_buckets.setdefault(
                    key,
                    {
                        "variant_id": variant_id,
                        "display_label": str(meta.get("display_label") or variant_id),
                        "changed_variable": str(meta.get("changed_variable") or ""),
                        "sample": sample_name,
                        "run_id": run_id,
                        "replicate_index": replicate_index,
                        "task_name": task_name,
                        "sample_task_id": sample_task_id,
                        "source": source_label,
                        "tool_family": tool_family,
                        "stages": set(),
                        "total_calls": 0,
                        "semantic_duplicate_calls": 0,
                        "same_source_semantic_duplicate_calls": 0,
                        "exact_duplicate_calls": 0,
                    },
                )
                semantic_counts = counter_bucket.get("semantic_counts") or Counter()
                exact_counts = counter_bucket.get("exact_counts") or Counter()
                total_calls = int(counter_bucket.get("total_calls") or 0)
                semantic_duplicate_calls = sum(max(0, int(count) - 1) for count in semantic_counts.values())
                exact_duplicate_calls = sum(max(0, int(count) - 1) for count in exact_counts.values())
                bucket["total_calls"] += total_calls
                bucket["semantic_duplicate_calls"] += semantic_duplicate_calls
                bucket["same_source_semantic_duplicate_calls"] += semantic_duplicate_calls
                bucket["exact_duplicate_calls"] += exact_duplicate_calls
                bucket["stages"].update(counter_bucket.get("stages") or set())

            for raw_tool in list(redundancy.get("top_duplicate_tools") or []):
                if not isinstance(raw_tool, dict):
                    continue
                tool_family = str(raw_tool.get("tool_family") or "").strip()
                if not tool_family:
                    continue
                key = (variant_id, sample_name, tool_family)
                bucket = tool_buckets.setdefault(
                    key,
                    {
                        "variant_id": variant_id,
                        "display_label": str(meta.get("display_label") or variant_id),
                        "changed_variable": str(meta.get("changed_variable") or ""),
                        "sample": sample_name,
                        "tool_family": tool_family,
                        "total_calls": 0,
                        "semantic_duplicate_calls": 0,
                        "same_source_semantic_duplicate_calls": 0,
                        "exact_duplicate_calls": 0,
                        "same_source_exact_duplicate_calls": 0,
                        "task_count": 0,
                        "samples_tasks": set(),
                    },
                )
                bucket["total_calls"] += int(raw_tool.get("total_calls") or 0)
                bucket["semantic_duplicate_calls"] += int(raw_tool.get("semantic_duplicate_calls") or 0)
                bucket["same_source_semantic_duplicate_calls"] += int(
                    raw_tool.get("same_source_semantic_duplicate_calls") or 0
                )
                bucket["exact_duplicate_calls"] += int(raw_tool.get("exact_duplicate_calls") or 0)
                bucket["same_source_exact_duplicate_calls"] += int(
                    raw_tool.get("same_source_exact_duplicate_calls") or 0
                )
                bucket["task_count"] += 1
                if sample_task_id:
                    bucket["samples_tasks"].add(sample_task_id)

            for raw_target in list(redundancy.get("top_duplicate_targets") or []):
                if not isinstance(raw_target, dict):
                    continue
                tool_family = str(raw_target.get("tool_family") or "").strip()
                target_label = str(raw_target.get("semantic_target_label") or "").strip()
                if not tool_family or not target_label:
                    continue
                stages = [str(stage).strip() for stage in list(raw_target.get("stages") or []) if str(stage).strip()]
                sources = [str(source).strip() for source in list(raw_target.get("sources") or []) if str(source).strip()]
                duplicate_calls = int(raw_target.get("duplicate_calls") or 0)
                call_count = int(raw_target.get("call_count") or 0)
                unique_shapes = int(raw_target.get("unique_exact_call_shapes") or 0)
                source_count = int(raw_target.get("source_count") or 0)
                same_source_duplicate_calls = int(raw_target.get("same_source_duplicate_calls") or 0)
                assessment = _assess_duplicate_target(
                    tool_family=tool_family,
                    duplicate_calls=duplicate_calls,
                    call_count=call_count,
                    unique_exact_call_shapes=unique_shapes,
                    stages=stages,
                    source_count=source_count,
                    same_source_duplicate_calls=same_source_duplicate_calls,
                )
                key = (variant_id, sample_name, tool_family, target_label)
                bucket = target_buckets.setdefault(
                    key,
                    {
                        "variant_id": variant_id,
                        "display_label": str(meta.get("display_label") or variant_id),
                        "changed_variable": str(meta.get("changed_variable") or ""),
                        "sample": sample_name,
                        "task_name": task_name,
                        "sample_task_id": sample_task_id,
                        "tool_family": tool_family,
                        "semantic_target_kind": str(raw_target.get("semantic_target_kind") or ""),
                        "semantic_target_label": target_label,
                        "call_count": 0,
                        "duplicate_calls": 0,
                        "record_count": 0,
                        "unique_exact_call_shapes": 0,
                        "source_count": 0,
                        "same_source_duplicate_calls": 0,
                        "stages": set(),
                        "sources": set(),
                        "assessments": [],
                    },
                )
                bucket["call_count"] += call_count
                bucket["duplicate_calls"] += duplicate_calls
                bucket["record_count"] += 1
                bucket["unique_exact_call_shapes"] = max(bucket["unique_exact_call_shapes"], unique_shapes)
                bucket["source_count"] = max(bucket["source_count"], source_count)
                bucket["same_source_duplicate_calls"] += same_source_duplicate_calls
                bucket["stages"].update(stages)
                bucket["sources"].update(sources)
                if assessment:
                    bucket["assessments"].append(assessment)

    executable_bucket_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in per_run_rows:
        key = (str(row.get("variant_id") or ""), str(row.get("sample") or ""))
        bucket = executable_bucket_map.setdefault(
            key,
            {
                "variant_id": str(row.get("variant_id") or ""),
                "display_label": str(row.get("display_label") or row.get("variant_id") or ""),
                "changed_variable": str(row.get("changed_variable") or ""),
                "comparison_baseline_id": str(row.get("comparison_baseline_id") or "baseline"),
                "comparison_baseline_label": str(row.get("comparison_baseline_label") or "baseline"),
                "sample": str(row.get("sample") or ""),
                "run_ids": [],
                "scores": [],
                "task_success_rates": [],
                "relative_cost_indices": [],
                "estimated_cost_usds": [],
                "tool_calls": [],
                "tool_duplicate_calls": [],
                "tool_same_source_duplicate_calls": [],
                "tool_duplicate_rates": [],
                "tool_same_source_duplicate_rates": [],
                "durations": [],
                "analysis_statuses": [],
                "top_families": [],
                "top_targets": [],
            },
        )
        bucket["run_ids"].append(str(row.get("run_id") or ""))
        for key_name, dest in (
            ("score", "scores"),
            ("task_success_rate", "task_success_rates"),
            ("relative_cost_index", "relative_cost_indices"),
            ("estimated_cost_usd", "estimated_cost_usds"),
            ("tool_calls_total", "tool_calls"),
            ("tool_semantic_duplicate_calls", "tool_duplicate_calls"),
            ("tool_same_source_semantic_duplicate_calls", "tool_same_source_duplicate_calls"),
            ("tool_semantic_duplicate_rate", "tool_duplicate_rates"),
            ("tool_same_source_semantic_duplicate_rate", "tool_same_source_duplicate_rates"),
            ("task_wall_clock_duration_sec", "durations"),
        ):
            value = row.get(key_name)
            try:
                if value is not None:
                    bucket[dest].append(float(value))
            except Exception:
                pass
        bucket["analysis_statuses"].append(str(row.get("analysis_status") or ""))
        bucket["top_families"].append(str(row.get("tool_most_redundant_family") or ""))
        bucket["top_targets"].append(str(row.get("tool_most_redundant_target") or ""))

    executable_rows: List[Dict[str, Any]] = []
    for bucket in executable_bucket_map.values():
        executable_rows.append(
            {
                "variant_id": bucket["variant_id"],
                "display_label": bucket["display_label"],
                "changed_variable": bucket["changed_variable"],
                "comparison_baseline_id": bucket["comparison_baseline_id"],
                "comparison_baseline_label": bucket["comparison_baseline_label"],
                "sample": bucket["sample"],
                "planned_repetitions": int(variant_meta_by_id.get(bucket["variant_id"], {}).get("planned_repetitions") or 0),
                "completed_repetitions": len(bucket["run_ids"]),
                "mean_score": _mean_or_none(bucket["scores"]),
                "score_stddev": _stddev_or_zero(bucket["scores"]),
                "mean_task_success_rate": _mean_or_none(bucket["task_success_rates"]),
                "task_success_rate_stddev": _stddev_or_zero(bucket["task_success_rates"]),
                "mean_relative_cost_index": _mean_or_none(bucket["relative_cost_indices"]),
                "mean_estimated_cost_usd": _mean_or_none(bucket["estimated_cost_usds"]),
                "mean_tool_calls": _mean_or_none(bucket["tool_calls"]),
                "mean_tool_semantic_duplicate_calls": _mean_or_none(bucket["tool_duplicate_calls"]),
                "mean_tool_same_source_semantic_duplicate_calls": _mean_or_none(
                    bucket["tool_same_source_duplicate_calls"]
                ),
                "tool_semantic_duplicate_calls_stddev": _stddev_or_zero(bucket["tool_duplicate_calls"]),
                "mean_tool_semantic_duplicate_rate": _mean_or_none(bucket["tool_duplicate_rates"]),
                "mean_tool_same_source_semantic_duplicate_rate": _mean_or_none(
                    bucket["tool_same_source_duplicate_rates"]
                ),
                "tool_semantic_duplicate_rate_stddev": _stddev_or_zero(bucket["tool_duplicate_rates"]),
                "mean_task_wall_clock_duration_sec": _mean_or_none(bucket["durations"]),
                "analysis_status": _dominant_text(bucket["analysis_statuses"]),
                "tool_most_redundant_family": _dominant_text(bucket["top_families"]),
                "tool_most_redundant_target": _dominant_text(bucket["top_targets"]),
            }
        )

    executable_map = {
        (str(row.get("sample") or ""), str(row.get("variant_id") or "")): row
        for row in executable_rows
    }
    sample_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in executable_rows:
        baseline_row = executable_map.get((str(row.get("sample") or ""), str(row.get("comparison_baseline_id") or "baseline")))
        baseline_score = baseline_row.get("mean_score") if isinstance(baseline_row, dict) else None
        baseline_success = baseline_row.get("mean_task_success_rate") if isinstance(baseline_row, dict) else None
        baseline_duplicates = baseline_row.get("mean_tool_semantic_duplicate_calls") if isinstance(baseline_row, dict) else None
        row["baseline_score_mean"] = baseline_score
        row["baseline_task_success_rate"] = baseline_success
        row["baseline_tool_semantic_duplicate_calls"] = baseline_duplicates
        row["score_delta"] = (
            round(float(row.get("mean_score") or 0.0) - float(baseline_score or 0.0), 3)
            if row.get("mean_score") is not None and baseline_score is not None
            else None
        )
        row["task_success_delta"] = (
            round(float(row.get("mean_task_success_rate") or 0.0) - float(baseline_success or 0.0), 3)
            if row.get("mean_task_success_rate") is not None and baseline_success is not None
            else None
        )
        row["tool_semantic_duplicate_delta"] = (
            round(float(row.get("mean_tool_semantic_duplicate_calls") or 0.0) - float(baseline_duplicates or 0.0), 3)
            if row.get("mean_tool_semantic_duplicate_calls") is not None and baseline_duplicates is not None
            else None
        )
        sample_groups[str(row.get("sample") or "")].append(row)

    for sample_name, rows in sample_groups.items():
        for rank, row in enumerate(
            sorted(
                rows,
                key=lambda item: (
                    -1e9 if item.get("mean_score") is None else -float(item.get("mean_score") or 0.0),
                    str(item.get("display_label") or item.get("variant_id") or ""),
                ),
            ),
            start=1,
        ):
            row["absolute_score_rank"] = rank
        for rank, row in enumerate(
            sorted(
                rows,
                key=lambda item: (
                    -1e9 if item.get("score_delta") is None else -float(item.get("score_delta") or 0.0),
                    str(item.get("display_label") or item.get("variant_id") or ""),
                ),
            ),
            start=1,
        ):
            row["delta_from_baseline_rank"] = rank

    consistency_rows: List[Dict[str, Any]] = []
    by_variant: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in executable_rows:
        by_variant[str(row.get("variant_id") or "")].append(row)
    for variant_id, rows in by_variant.items():
        if variant_id == "baseline":
            continue
        deltas = [float(row["score_delta"]) for row in rows if row.get("score_delta") is not None]
        if not deltas:
            continue
        positive = len([value for value in deltas if value > 0.0])
        negative = len([value for value in deltas if value < 0.0])
        neutral = len(deltas) - positive - negative
        strongest = max((row for row in rows if row.get("score_delta") is not None), key=lambda item: float(item.get("score_delta") or -1e9))
        weakest = min((row for row in rows if row.get("score_delta") is not None), key=lambda item: float(item.get("score_delta") or 1e9))
        if positive and negative:
            heterogeneity_label = "mixed"
        elif positive and neutral:
            heterogeneity_label = "mostly_positive"
        elif negative and neutral:
            heterogeneity_label = "mostly_negative"
        elif positive:
            heterogeneity_label = "consistent_gain"
        elif negative:
            heterogeneity_label = "consistent_loss"
        else:
            heterogeneity_label = "neutral"
        max_abs_delta = max(abs(value) for value in deltas)
        masked_by_average = positive > 0 and negative > 0 and abs(mean(deltas)) <= max_abs_delta * 0.6
        consistency_rows.append(
            {
                "variant_id": variant_id,
                "display_label": str(rows[0].get("display_label") or variant_id),
                "changed_variable": str(rows[0].get("changed_variable") or ""),
                "executable_count": len(deltas),
                "mean_score_delta": round(mean(deltas), 3),
                "score_delta_stddev": _stddev_or_zero(deltas),
                "min_score_delta": round(min(deltas), 3),
                "max_score_delta": round(max(deltas), 3),
                "delta_span": round(max(deltas) - min(deltas), 3),
                "positive_executable_count": positive,
                "negative_executable_count": negative,
                "neutral_executable_count": neutral,
                "heterogeneity_label": heterogeneity_label,
                "masked_by_average": masked_by_average,
                "strongest_executable": str(strongest.get("sample") or ""),
                "strongest_executable_delta": strongest.get("score_delta"),
                "weakest_executable": str(weakest.get("sample") or ""),
                "weakest_executable_delta": weakest.get("score_delta"),
            }
        )

    resource_rows = _build_default_analysis_executable_resource_rows(run_entries)

    executable_tool_rows: List[Dict[str, Any]] = []
    likely_wasteful_totals: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for target_bucket in target_buckets.values():
        tool_key = (
            str(target_bucket.get("variant_id") or ""),
            str(target_bucket.get("sample") or ""),
            str(target_bucket.get("tool_family") or ""),
        )
        assessment = _dominant_text(list(target_bucket.get("assessments") or []))
        if assessment.startswith("likely_wasteful"):
            likely_wasteful_totals[tool_key] += int(target_bucket.get("same_source_duplicate_calls") or 0)

    for bucket in tool_buckets.values():
        total_calls = int(bucket.get("total_calls") or 0)
        semantic_duplicates = int(bucket.get("semantic_duplicate_calls") or 0)
        same_source_semantic_duplicates = int(bucket.get("same_source_semantic_duplicate_calls") or 0)
        exact_duplicates = int(bucket.get("exact_duplicate_calls") or 0)
        same_source_exact_duplicates = int(bucket.get("same_source_exact_duplicate_calls") or 0)
        task_count = int(bucket.get("task_count") or 0)
        tool_key = (
            str(bucket.get("variant_id") or ""),
            str(bucket.get("sample") or ""),
            str(bucket.get("tool_family") or ""),
        )
        executable_tool_rows.append(
            {
                "variant_id": str(bucket.get("variant_id") or ""),
                "display_label": str(bucket.get("display_label") or bucket.get("variant_id") or ""),
                "changed_variable": str(bucket.get("changed_variable") or ""),
                "sample": str(bucket.get("sample") or ""),
                "tool_family": str(bucket.get("tool_family") or ""),
                "task_count": task_count,
                "sample_task_count": len(bucket.get("samples_tasks") or []),
                "total_calls": total_calls,
                "semantic_duplicate_calls": semantic_duplicates,
                "same_source_semantic_duplicate_calls": same_source_semantic_duplicates,
                "exact_duplicate_calls": exact_duplicates,
                "same_source_exact_duplicate_calls": same_source_exact_duplicates,
                "semantic_duplicate_rate": round(semantic_duplicates / total_calls, 6) if total_calls else 0.0,
                "same_source_semantic_duplicate_rate": (
                    round(same_source_semantic_duplicates / total_calls, 6) if total_calls else 0.0
                ),
                "mean_semantic_duplicate_calls_per_task": round(semantic_duplicates / task_count, 3) if task_count else 0.0,
                "mean_same_source_semantic_duplicate_calls_per_task": (
                    round(same_source_semantic_duplicates / task_count, 3) if task_count else 0.0
                ),
                "likely_wasteful_duplicate_calls": int(likely_wasteful_totals.get(tool_key, 0)),
            }
        )

    variant_tool_buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in executable_tool_rows:
        key = (str(row.get("variant_id") or ""), str(row.get("tool_family") or ""))
        bucket = variant_tool_buckets.setdefault(
            key,
            {
                "variant_id": str(row.get("variant_id") or ""),
                "display_label": str(row.get("display_label") or row.get("variant_id") or ""),
                "changed_variable": str(row.get("changed_variable") or ""),
                "tool_family": str(row.get("tool_family") or ""),
                "executable_count": 0,
                "total_calls": 0,
                "semantic_duplicate_calls": 0,
                "same_source_semantic_duplicate_calls": 0,
                "exact_duplicate_calls": 0,
                "same_source_exact_duplicate_calls": 0,
                "likely_wasteful_duplicate_calls": 0,
            },
        )
        bucket["executable_count"] += 1
        bucket["total_calls"] += int(row.get("total_calls") or 0)
        bucket["semantic_duplicate_calls"] += int(row.get("semantic_duplicate_calls") or 0)
        bucket["same_source_semantic_duplicate_calls"] += int(row.get("same_source_semantic_duplicate_calls") or 0)
        bucket["exact_duplicate_calls"] += int(row.get("exact_duplicate_calls") or 0)
        bucket["same_source_exact_duplicate_calls"] += int(row.get("same_source_exact_duplicate_calls") or 0)
        bucket["likely_wasteful_duplicate_calls"] += int(row.get("likely_wasteful_duplicate_calls") or 0)

    variant_tool_rows: List[Dict[str, Any]] = []
    for bucket in variant_tool_buckets.values():
        total_calls = int(bucket.get("total_calls") or 0)
        executable_count = int(bucket.get("executable_count") or 0)
        semantic_duplicates = int(bucket.get("semantic_duplicate_calls") or 0)
        same_source_semantic_duplicates = int(bucket.get("same_source_semantic_duplicate_calls") or 0)
        variant_tool_rows.append(
            {
                "variant_id": str(bucket.get("variant_id") or ""),
                "display_label": str(bucket.get("display_label") or bucket.get("variant_id") or ""),
                "changed_variable": str(bucket.get("changed_variable") or ""),
                "tool_family": str(bucket.get("tool_family") or ""),
                "executable_count": executable_count,
                "total_calls": total_calls,
                "semantic_duplicate_calls": semantic_duplicates,
                "same_source_semantic_duplicate_calls": same_source_semantic_duplicates,
                "exact_duplicate_calls": int(bucket.get("exact_duplicate_calls") or 0),
                "same_source_exact_duplicate_calls": int(bucket.get("same_source_exact_duplicate_calls") or 0),
                "semantic_duplicate_rate": round(semantic_duplicates / total_calls, 6) if total_calls else 0.0,
                "same_source_semantic_duplicate_rate": (
                    round(same_source_semantic_duplicates / total_calls, 6) if total_calls else 0.0
                ),
                "mean_semantic_duplicate_calls_per_executable": round(semantic_duplicates / executable_count, 3) if executable_count else 0.0,
                "mean_same_source_semantic_duplicate_calls_per_executable": (
                    round(same_source_semantic_duplicates / executable_count, 3) if executable_count else 0.0
                ),
                "likely_wasteful_duplicate_calls": int(bucket.get("likely_wasteful_duplicate_calls") or 0),
            }
        )

    target_rows: List[Dict[str, Any]] = []
    for bucket in target_buckets.values():
        assessment = _dominant_text(list(bucket.get("assessments") or []))
        target_rows.append(
            {
                "variant_id": str(bucket.get("variant_id") or ""),
                "display_label": str(bucket.get("display_label") or bucket.get("variant_id") or ""),
                "changed_variable": str(bucket.get("changed_variable") or ""),
                "sample": str(bucket.get("sample") or ""),
                "task_name": str(bucket.get("task_name") or ""),
                "sample_task_id": str(bucket.get("sample_task_id") or ""),
                "tool_family": str(bucket.get("tool_family") or ""),
                "semantic_target_kind": str(bucket.get("semantic_target_kind") or ""),
                "semantic_target_label": str(bucket.get("semantic_target_label") or ""),
                "call_count": int(bucket.get("call_count") or 0),
                "duplicate_calls": int(bucket.get("duplicate_calls") or 0),
                "record_count": int(bucket.get("record_count") or 0),
                "unique_exact_call_shapes": int(bucket.get("unique_exact_call_shapes") or 0),
                "source_count": int(bucket.get("source_count") or 0),
                "same_source_duplicate_calls": int(bucket.get("same_source_duplicate_calls") or 0),
                "stages": "; ".join(sorted(bucket.get("stages") or [])),
                "sources": "; ".join(sorted(bucket.get("sources") or [])),
                "duplication_assessment": assessment,
                "likely_wasteful": assessment.startswith("likely_wasteful"),
            }
        )
    target_rows.sort(
        key=lambda row: (
            -int(row.get("duplicate_calls") or 0),
            -int(row.get("call_count") or 0),
            str(row.get("sample") or ""),
            str(row.get("display_label") or ""),
        )
    )

    source_tool_rows: List[Dict[str, Any]] = []
    for bucket in source_tool_buckets.values():
        total_calls = int(bucket.get("total_calls") or 0)
        semantic_duplicates = int(bucket.get("semantic_duplicate_calls") or 0)
        same_source_semantic_duplicates = int(bucket.get("same_source_semantic_duplicate_calls") or 0)
        exact_duplicates = int(bucket.get("exact_duplicate_calls") or 0)
        source_tool_rows.append(
            {
                "variant_id": str(bucket.get("variant_id") or ""),
                "display_label": str(bucket.get("display_label") or bucket.get("variant_id") or ""),
                "changed_variable": str(bucket.get("changed_variable") or ""),
                "sample": str(bucket.get("sample") or ""),
                "run_id": str(bucket.get("run_id") or ""),
                "replicate_index": bucket.get("replicate_index"),
                "task_name": str(bucket.get("task_name") or ""),
                "sample_task_id": str(bucket.get("sample_task_id") or ""),
                "source": str(bucket.get("source") or ""),
                "tool_family": str(bucket.get("tool_family") or ""),
                "stages": "; ".join(sorted(bucket.get("stages") or [])),
                "total_calls": total_calls,
                "semantic_duplicate_calls": semantic_duplicates,
                "same_source_semantic_duplicate_calls": same_source_semantic_duplicates,
                "exact_duplicate_calls": exact_duplicates,
                "semantic_duplicate_rate": round(semantic_duplicates / total_calls, 6) if total_calls else 0.0,
                "same_source_semantic_duplicate_rate": (
                    round(same_source_semantic_duplicates / total_calls, 6) if total_calls else 0.0
                ),
                "exact_duplicate_rate": round(exact_duplicates / total_calls, 6) if total_calls else 0.0,
            }
        )
    source_tool_rows.sort(
        key=lambda row: (
            str(row.get("variant_id") or ""),
            str(row.get("sample") or ""),
            str(row.get("run_id") or ""),
            -int(row.get("same_source_semantic_duplicate_calls") or 0),
            -int(row.get("total_calls") or 0),
            str(row.get("source") or ""),
            str(row.get("tool_family") or ""),
        )
    )

    source_run_buckets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for row in source_tool_rows:
        key = (
            str(row.get("variant_id") or ""),
            str(row.get("sample") or ""),
            str(row.get("run_id") or ""),
        )
        bucket = source_run_buckets.setdefault(
            key,
            {
                "variant_id": str(row.get("variant_id") or ""),
                "display_label": str(row.get("display_label") or row.get("variant_id") or ""),
                "changed_variable": str(row.get("changed_variable") or ""),
                "sample": str(row.get("sample") or ""),
                "run_id": str(row.get("run_id") or ""),
                "replicate_index": row.get("replicate_index"),
                "total_calls": 0,
                "same_source_semantic_duplicate_calls": 0,
                "semantic_duplicate_calls": 0,
                "source_counts": Counter(),
                "tool_family_counts": Counter(),
            },
        )
        total_calls = int(row.get("total_calls") or 0)
        semantic_duplicates = int(row.get("semantic_duplicate_calls") or 0)
        same_source_semantic_duplicates = int(row.get("same_source_semantic_duplicate_calls") or 0)
        source_label = str(row.get("source") or "")
        tool_family = str(row.get("tool_family") or "")
        bucket["total_calls"] += total_calls
        bucket["semantic_duplicate_calls"] += semantic_duplicates
        bucket["same_source_semantic_duplicate_calls"] += same_source_semantic_duplicates
        if source_label:
            bucket["source_counts"][source_label] += total_calls
        if tool_family:
            bucket["tool_family_counts"][tool_family] += total_calls

    source_run_rows: List[Dict[str, Any]] = []
    for bucket in source_run_buckets.values():
        source_counts = bucket.get("source_counts") or Counter()
        tool_family_counts = bucket.get("tool_family_counts") or Counter()
        top_source, top_source_calls = ("", 0)
        if source_counts:
            top_source, top_source_calls = sorted(
                source_counts.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )[0]
        top_tool_family, top_tool_family_calls = ("", 0)
        if tool_family_counts:
            top_tool_family, top_tool_family_calls = sorted(
                tool_family_counts.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )[0]
        source_run_rows.append(
            {
                "variant_id": str(bucket.get("variant_id") or ""),
                "display_label": str(bucket.get("display_label") or bucket.get("variant_id") or ""),
                "changed_variable": str(bucket.get("changed_variable") or ""),
                "sample": str(bucket.get("sample") or ""),
                "run_id": str(bucket.get("run_id") or ""),
                "replicate_index": bucket.get("replicate_index"),
                "source_count": len(source_counts),
                "total_calls": int(bucket.get("total_calls") or 0),
                "semantic_duplicate_calls": int(bucket.get("semantic_duplicate_calls") or 0),
                "same_source_semantic_duplicate_calls": int(bucket.get("same_source_semantic_duplicate_calls") or 0),
                "top_source": top_source,
                "top_source_calls": int(top_source_calls or 0),
                "top_tool_family": top_tool_family,
                "top_tool_family_calls": int(top_tool_family_calls or 0),
            }
        )
    source_run_rows.sort(
        key=lambda row: (
            -int(row.get("same_source_semantic_duplicate_calls") or 0),
            -int(row.get("total_calls") or 0),
            str(row.get("variant_id") or ""),
            str(row.get("sample") or ""),
            str(row.get("run_id") or ""),
        )
    )

    executable_rows.sort(
        key=lambda row: (
            str(row.get("sample") or ""),
            int(row.get("absolute_score_rank") or 9999),
            str(row.get("display_label") or ""),
        )
    )
    consistency_rows.sort(
        key=lambda row: (
            bool(row.get("masked_by_average")),
            float(row.get("delta_span") or 0.0),
            float(abs(row.get("mean_score_delta") or 0.0)),
        ),
        reverse=True,
    )
    variant_tool_rows.sort(
        key=lambda row: (
            -int(row.get("likely_wasteful_duplicate_calls") or 0),
            -int(row.get("same_source_semantic_duplicate_calls") or 0),
            -int(row.get("semantic_duplicate_calls") or 0),
            str(row.get("display_label") or ""),
        )
    )
    executable_tool_rows.sort(
        key=lambda row: (
            -int(row.get("likely_wasteful_duplicate_calls") or 0),
            -int(row.get("same_source_semantic_duplicate_calls") or 0),
            -int(row.get("semantic_duplicate_calls") or 0),
            str(row.get("sample") or ""),
            str(row.get("display_label") or ""),
        )
    )
    return {
        "per_run_rows": per_run_rows,
        "executable_rows": executable_rows,
        "resource_rows": resource_rows,
        "consistency_rows": consistency_rows,
        "variant_tool_rows": variant_tool_rows,
        "executable_tool_rows": executable_tool_rows,
        "target_rows": target_rows,
        "source_tool_rows": source_tool_rows,
        "source_run_rows": source_run_rows,
    }


def _merge_run_group(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    manifests: List[Dict[str, Any]] = []
    run_ids: List[str] = []
    for entry in entries:
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        records.extend(list(aggregate.get("records") or []))
        manifests.append(dict(entry.get("run_manifest") or {}))
        run_ids.append(str(entry.get("run_id") or ""))
    base_manifest = manifests[0] if manifests else {}
    group_metadata = dict(base_manifest)
    group_metadata["replicate_count"] = len(entries)
    group_metadata["replicate_run_ids"] = run_ids
    aggregate = aggregate_records(group_metadata, records)
    aggregate["replicate_count"] = len(entries)
    aggregate["replicate_run_ids"] = run_ids
    return {
        "run_manifest": group_metadata,
        "aggregate": aggregate,
        "records": records,
        "replicate_count": len(entries),
        "run_ids": run_ids,
    }


def _run_entry_has_full_task_coverage(entry: Dict[str, Any]) -> bool:
    aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
    expected_task_count = int(aggregate.get("expected_task_count") or 0)
    completed_task_count = int(aggregate.get("sample_count") or 0)
    if expected_task_count > 0:
        return completed_task_count >= expected_task_count
    try:
        completion_rate = float(aggregate.get("task_completion_rate"))
        return completion_rate >= 1.0
    except Exception:
        return bool(aggregate.get("records"))


def _build_comparison_tables(
    *,
    planned_runs: List[Dict[str, Any]],
    repetitions: int,
    grouped_all_runs: Dict[str, List[Dict[str, Any]]],
    grouped_successful: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    variant_rows: List[Dict[str, Any]] = []
    dimension_rows: List[Dict[str, Any]] = []
    task_rows: List[Dict[str, Any]] = []
    technique_rows: List[Dict[str, Any]] = []
    difficulty_rows: List[Dict[str, Any]] = []

    grouped_results: Dict[str, Dict[str, Any]] = {
        variant_id: _merge_run_group(entries)
        for variant_id, entries in grouped_successful.items()
    }
    global_baseline = grouped_results.get("baseline")
    global_baseline_aggregate = (
        dict(global_baseline.get("aggregate") or {})
        if isinstance(global_baseline, dict)
        else {}
    )
    global_baseline_dimensions = dict(global_baseline_aggregate.get("dimension_means") or {})
    global_baseline_score = global_baseline_aggregate.get("overall_score_mean")
    global_baseline_success_rate = global_baseline_aggregate.get("task_success_rate")
    global_baseline_cost = global_baseline_aggregate.get("mean_relative_cost_index")

    planned_by_variant: Dict[str, Dict[str, Any]] = {}
    for run_cfg in planned_runs:
        planned_by_variant[str(run_cfg.get("variant_id") or "")] = run_cfg

    ordered_variant_ids: List[str] = []
    seen_variant_ids: set[str] = set()
    for run_cfg in planned_runs:
        variant_id = str(run_cfg.get("variant_id") or "")
        if variant_id and variant_id not in seen_variant_ids:
            seen_variant_ids.add(variant_id)
            ordered_variant_ids.append(variant_id)

    for variant_id in ordered_variant_ids:
        planned_cfg = planned_by_variant.get(variant_id) or {}
        group = grouped_results.get(variant_id)
        comparison_baseline_id = str(planned_cfg.get("comparison_baseline_id") or "").strip() or "baseline"
        comparison_group = grouped_results.get(comparison_baseline_id) or global_baseline or {}
        comparison_aggregate = (
            dict(comparison_group.get("aggregate") or {})
            if isinstance(comparison_group, dict)
            else {}
        )
        comparison_dimensions = dict(comparison_aggregate.get("dimension_means") or {})
        display_label = (
            "baseline"
            if planned_cfg.get("is_baseline")
            else f"{str(planned_cfg.get('changed_variable') or '')}:baseline"
            if planned_cfg.get("is_family_baseline")
            else f"{str(planned_cfg.get('changed_variable') or '')}:{str(planned_cfg.get('variant_name') or variant_id)}"
        )

        if group is None:
            attempted_repetitions = len(grouped_all_runs.get(variant_id) or [])
            failed_repetitions = max(0, attempted_repetitions)
            variant_rows.append(
                {
                    "variant_id": variant_id,
                    "variant_name": str(planned_cfg.get("variant_name") or variant_id),
                    "changed_variable": str(planned_cfg.get("changed_variable") or "") or "baseline",
                    "display_label": display_label,
                    "is_baseline": bool(planned_cfg.get("is_baseline")),
                    "is_family_baseline": bool(planned_cfg.get("is_family_baseline")),
                    "comparison_baseline_id": comparison_baseline_id,
                    "comparison_baseline_label": str(planned_cfg.get("comparison_baseline_label") or "baseline"),
                    "pipeline": str(planned_cfg.get("pipeline") or ""),
                    "architecture": str(planned_cfg.get("architecture") or ""),
                    "response_scope_variant": str(planned_cfg.get("response_scope_variant") or ""),
                    "analysis_hint_variant": str(planned_cfg.get("analysis_hint_variant") or ""),
                    "subagent_profile": str(planned_cfg.get("subagent_profile") or ""),
                    "worker_persona_profile": str(planned_cfg.get("worker_persona_profile") or ""),
                    "worker_role_prompt_mode": str(planned_cfg.get("worker_role_prompt_mode") or ""),
                    "validator_review_level": str(planned_cfg.get("validator_review_level") or ""),
                    "model_profile": str(planned_cfg.get("model_profile") or ""),
                    "force_model": str(planned_cfg.get("force_model") or ""),
                    "config_lineage_id": "",
                    "planned_repetitions": repetitions,
                    "attempted_repetitions": attempted_repetitions,
                    "completed_repetitions": 0,
                    "failed_repetitions": failed_repetitions,
                    "completion_rate": (
                        round(0.0 / attempted_repetitions, 3) if attempted_repetitions else None
                    ),
                    "run_ids": [],
                    "overall_score_mean": None,
                    "overall_score_stddev": None,
                    "overall_score_min": None,
                    "overall_score_max": None,
                    "task_success_rate": None,
                    "task_success_rate_stddev": None,
                    "judge_pass_rate": None,
                    "scored_result_rate": None,
                    "produced_result_rate": None,
                    "synthetic_judge_rate": None,
                    "validator_blocked_rate": None,
                    "worker_assignment_failed_rate": None,
                    "analysis_failure_rate": None,
                    "judge_error_rate": None,
                    "mean_relative_cost_index": None,
                    "mean_relative_cost_index_stddev": None,
                    "mean_tool_calls": None,
                    "mean_tool_exact_duplicate_calls": None,
                    "mean_tool_semantic_duplicate_calls": None,
                    "mean_tool_exact_duplicate_rate": None,
                    "mean_tool_semantic_duplicate_rate": None,
                    "mean_target_tool_hit_rate": None,
                    "score_delta": None,
                    "task_success_delta": None,
                    "cost_delta": None,
                    "global_score_delta": None,
                }
            )
            continue

        aggregate = dict(group.get("aggregate") or {})
        attempted_repetitions = len(grouped_all_runs.get(variant_id) or [])
        completed_repetitions = int(group.get("replicate_count") or 0)
        replicate_entries = list(grouped_successful.get(variant_id) or [])
        score_series = _value_series(replicate_entries, "aggregate.overall_score_mean")
        success_series = _value_series(replicate_entries, "aggregate.task_success_rate")
        cost_series = _value_series(replicate_entries, "aggregate.mean_relative_cost_index")
        wall_clock_series = _value_series(replicate_entries, "aggregate.mean_task_wall_clock_duration_sec")
        row = {
            "variant_id": variant_id,
            "variant_name": str(planned_cfg.get("variant_name") or variant_id),
            "changed_variable": str(planned_cfg.get("changed_variable") or "") or "baseline",
            "display_label": display_label,
            "is_baseline": bool(planned_cfg.get("is_baseline")),
            "is_family_baseline": bool(planned_cfg.get("is_family_baseline")),
            "comparison_baseline_id": comparison_baseline_id,
            "comparison_baseline_label": str(planned_cfg.get("comparison_baseline_label") or "baseline"),
            "planned_repetitions": repetitions,
            "completed_repetitions": int(group.get("replicate_count") or 0),
            "run_ids": list(group.get("run_ids") or []),
            "pipeline": ((group.get("run_manifest") or {}).get("pipeline") or ""),
            "architecture": ((group.get("run_manifest") or {}).get("architecture") or ""),
            "response_scope_variant": ((group.get("run_manifest") or {}).get("response_scope_variant") or ""),
            "analysis_hint_variant": ((group.get("run_manifest") or {}).get("analysis_hint_variant") or ""),
            "subagent_profile": ((group.get("run_manifest") or {}).get("subagent_profile") or ""),
            "worker_persona_profile": ((group.get("run_manifest") or {}).get("worker_persona_profile") or ""),
            "worker_role_prompt_mode": ((group.get("run_manifest") or {}).get("worker_role_prompt_mode") or ""),
            "validator_review_level": ((group.get("run_manifest") or {}).get("validator_review_level") or ""),
            "model_profile": ((group.get("run_manifest") or {}).get("model_profile") or ""),
            "force_model": ((group.get("run_manifest") or {}).get("force_model") or ""),
            "config_lineage_id": ((group.get("run_manifest") or {}).get("config_lineage_id") or ""),
            "overall_score_mean": aggregate.get("overall_score_mean"),
            "overall_score_stddev": round(pstdev(score_series), 3) if len(score_series) > 1 else (0.0 if score_series else None),
            "overall_score_min": round(min(score_series), 3) if score_series else None,
            "overall_score_max": round(max(score_series), 3) if score_series else None,
            "task_success_rate": aggregate.get("task_success_rate"),
            "task_success_rate_stddev": round(pstdev(success_series), 3) if len(success_series) > 1 else (0.0 if success_series else None),
            "judge_pass_rate": aggregate.get("judge_pass_rate"),
            "scored_result_rate": aggregate.get("scored_result_rate"),
            "produced_result_rate": aggregate.get("produced_result_rate"),
            "synthetic_judge_rate": aggregate.get("synthetic_judge_rate"),
            "validator_blocked_rate": aggregate.get("validator_blocked_rate"),
            "worker_assignment_failed_rate": aggregate.get("worker_assignment_failed_rate"),
            "analysis_failure_rate": aggregate.get("analysis_failure_rate"),
            "judge_error_rate": aggregate.get("judge_error_rate"),
            "mean_relative_cost_index": aggregate.get("mean_relative_cost_index"),
            "mean_relative_cost_index_stddev": round(pstdev(cost_series), 6) if len(cost_series) > 1 else (0.0 if cost_series else None),
            "mean_tool_calls": aggregate.get("mean_tool_calls"),
            "mean_tool_exact_duplicate_calls": aggregate.get("mean_tool_exact_duplicate_calls"),
            "mean_tool_semantic_duplicate_calls": aggregate.get("mean_tool_semantic_duplicate_calls"),
            "mean_tool_exact_duplicate_rate": aggregate.get("mean_tool_exact_duplicate_rate"),
            "mean_tool_semantic_duplicate_rate": aggregate.get("mean_tool_semantic_duplicate_rate"),
            "mean_tool_cache_hit_count": aggregate.get("mean_tool_cache_hit_count"),
            "mean_target_tool_hit_rate": aggregate.get("mean_target_tool_hit_rate"),
            "mean_analysis_duration_sec": aggregate.get("mean_analysis_duration_sec"),
            "mean_judge_duration_sec": aggregate.get("mean_judge_duration_sec"),
            "mean_total_duration_sec": aggregate.get("mean_total_duration_sec"),
            "mean_task_wall_clock_duration_sec": aggregate.get("mean_task_wall_clock_duration_sec"),
            "mean_task_wall_clock_duration_sec_stddev": round(pstdev(wall_clock_series), 6) if len(wall_clock_series) > 1 else (0.0 if wall_clock_series else None),
            "attempted_repetitions": attempted_repetitions,
            "failed_repetitions": max(0, attempted_repetitions - completed_repetitions),
            "completion_rate": (
                round(completed_repetitions / attempted_repetitions, 3)
                if attempted_repetitions
                else None
            ),
            "score_delta": (
                round(float(aggregate.get("overall_score_mean") or 0.0) - float(comparison_aggregate.get("overall_score_mean") or 0.0), 3)
                if aggregate.get("overall_score_mean") is not None and comparison_aggregate.get("overall_score_mean") is not None
                else None
            ),
            "task_success_delta": (
                round(float(aggregate.get("task_success_rate") or 0.0) - float(comparison_aggregate.get("task_success_rate") or 0.0), 3)
                if aggregate.get("task_success_rate") is not None and comparison_aggregate.get("task_success_rate") is not None
                else None
            ),
            "cost_delta": (
                round(float(aggregate.get("mean_relative_cost_index") or 0.0) - float(comparison_aggregate.get("mean_relative_cost_index") or 0.0), 6)
                if aggregate.get("mean_relative_cost_index") is not None and comparison_aggregate.get("mean_relative_cost_index") is not None
                else None
            ),
            "global_score_delta": (
                round(float(aggregate.get("overall_score_mean") or 0.0) - float(global_baseline_score or 0.0), 3)
                if aggregate.get("overall_score_mean") is not None and global_baseline_score is not None
                else None
            ),
            "global_task_success_delta": (
                round(float(aggregate.get("task_success_rate") or 0.0) - float(global_baseline_success_rate or 0.0), 3)
                if aggregate.get("task_success_rate") is not None and global_baseline_success_rate is not None
                else None
            ),
            "global_cost_delta": (
                round(float(aggregate.get("mean_relative_cost_index") or 0.0) - float(global_baseline_cost or 0.0), 6)
                if aggregate.get("mean_relative_cost_index") is not None and global_baseline_cost is not None
                else None
            ),
            "task_wall_clock_duration_delta_sec": (
                round(float(aggregate.get("mean_task_wall_clock_duration_sec") or 0.0) - float(comparison_aggregate.get("mean_task_wall_clock_duration_sec") or 0.0), 6)
                if aggregate.get("mean_task_wall_clock_duration_sec") is not None and comparison_aggregate.get("mean_task_wall_clock_duration_sec") is not None
                else None
            ),
        }
        variant_rows.append(row)

        for dimension_name in sorted(set(list(comparison_dimensions.keys()) + list((aggregate.get("dimension_means") or {}).keys()) + list(global_baseline_dimensions.keys()))):
            current_value = (aggregate.get("dimension_means") or {}).get(dimension_name)
            baseline_value = comparison_dimensions.get(dimension_name)
            global_baseline_value = global_baseline_dimensions.get(dimension_name)
            dimension_rows.append(
                {
                    "variant_id": row["variant_id"],
                    "display_label": row["display_label"],
                    "changed_variable": row["changed_variable"],
                    "comparison_baseline_id": comparison_baseline_id,
                    "comparison_baseline_label": row["comparison_baseline_label"],
                    "dimension": dimension_name,
                    "value": current_value,
                    "baseline_value": baseline_value,
                    "global_baseline_value": global_baseline_value,
                    "delta_from_baseline": (
                        round(float(current_value or 0.0) - float(baseline_value or 0.0), 3)
                        if current_value is not None and baseline_value is not None
                        else None
                    ),
                    "delta_from_global_baseline": (
                        round(float(current_value or 0.0) - float(global_baseline_value or 0.0), 3)
                        if current_value is not None and global_baseline_value is not None
                        else None
                    ),
                }
            )

        current_records = _group_records(list(group.get("records") or []))
        baseline_records = _group_records(list((comparison_group.get("records") if isinstance(comparison_group, dict) else []) or []))
        all_samples = sorted(set(current_records.keys()) | set(baseline_records.keys()))
        for record_key in all_samples:
            current_group = current_records.get(record_key) or []
            baseline_group = baseline_records.get(record_key) or []
            current_summary = _task_group_summary(current_group) if current_group else {}
            baseline_summary = _task_group_summary(baseline_group) if baseline_group else {}
            reference_summary = current_summary or baseline_summary
            task_rows.append(
                {
                    "variant_id": row["variant_id"],
                    "display_label": row["display_label"],
                    "changed_variable": row["changed_variable"],
                    "comparison_baseline_id": comparison_baseline_id,
                    "comparison_baseline_label": row["comparison_baseline_label"],
                    "sample": reference_summary.get("sample", ""),
                    "task_id": reference_summary.get("task_id", ""),
                    "task_name": reference_summary.get("task_name", ""),
                    "sample_task_id": reference_summary.get("sample_task_id", record_key),
                    "difficulty": reference_summary.get("difficulty", "unknown"),
                    "primary_techniques": reference_summary.get("primary_techniques", ""),
                    "analysis_status": current_summary.get("analysis_status"),
                    "baseline_analysis_status": baseline_summary.get("analysis_status"),
                    "produced_result_rate": current_summary.get("produced_result_rate"),
                    "baseline_produced_result_rate": baseline_summary.get("produced_result_rate"),
                    "score": current_summary.get("score"),
                    "baseline_score": baseline_summary.get("score"),
                    "score_delta": (
                        round(float(current_summary.get("score") or 0.0) - float(baseline_summary.get("score") or 0.0), 3)
                        if current_summary.get("score") is not None and baseline_summary.get("score") is not None
                        else None
                    ),
                    "task_success_rate": current_summary.get("task_success_rate"),
                    "baseline_task_success_rate": baseline_summary.get("task_success_rate"),
                    "task_success_numeric": current_summary.get("task_success_rate"),
                    "baseline_task_success_numeric": baseline_summary.get("task_success_rate"),
                    "task_success_delta": (
                        round(float(current_summary.get("task_success_rate") or 0.0) - float(baseline_summary.get("task_success_rate") or 0.0), 3)
                        if current_summary.get("task_success_rate") is not None and baseline_summary.get("task_success_rate") is not None
                        else None
                    ),
                    "relative_cost_index": current_summary.get("relative_cost_index"),
                    "baseline_relative_cost_index": baseline_summary.get("relative_cost_index"),
                    "tool_calls_total": current_summary.get("tool_calls_total"),
                    "baseline_tool_calls_total": baseline_summary.get("tool_calls_total"),
                    "tool_semantic_duplicate_calls": current_summary.get("tool_semantic_duplicate_calls"),
                    "baseline_tool_semantic_duplicate_calls": baseline_summary.get("tool_semantic_duplicate_calls"),
                    "tool_semantic_duplicate_rate": current_summary.get("tool_semantic_duplicate_rate"),
                    "baseline_tool_semantic_duplicate_rate": baseline_summary.get("tool_semantic_duplicate_rate"),
                    "tool_most_redundant_target": current_summary.get("tool_most_redundant_target"),
                    "baseline_tool_most_redundant_target": baseline_summary.get("tool_most_redundant_target"),
                    "tool_semantic_duplicate_delta": (
                        round(float(current_summary.get("tool_semantic_duplicate_calls") or 0.0) - float(baseline_summary.get("tool_semantic_duplicate_calls") or 0.0), 3)
                        if current_summary.get("tool_semantic_duplicate_calls") is not None and baseline_summary.get("tool_semantic_duplicate_calls") is not None
                        else None
                    ),
                    "target_tool_hit_rate": current_summary.get("target_tool_hit_rate"),
                    "baseline_target_tool_hit_rate": baseline_summary.get("target_tool_hit_rate"),
                    "mean_analysis_duration_sec": current_summary.get("analysis_duration_sec"),
                    "baseline_mean_analysis_duration_sec": baseline_summary.get("analysis_duration_sec"),
                    "mean_judge_duration_sec": current_summary.get("judge_duration_sec"),
                    "baseline_mean_judge_duration_sec": baseline_summary.get("judge_duration_sec"),
                    "mean_total_duration_sec": current_summary.get("total_duration_sec"),
                    "baseline_mean_total_duration_sec": baseline_summary.get("total_duration_sec"),
                    "mean_task_wall_clock_duration_sec": current_summary.get("task_wall_clock_duration_sec"),
                    "baseline_mean_task_wall_clock_duration_sec": baseline_summary.get("task_wall_clock_duration_sec"),
                    "task_wall_clock_duration_delta_sec": (
                        round(float(current_summary.get("task_wall_clock_duration_sec") or 0.0) - float(baseline_summary.get("task_wall_clock_duration_sec") or 0.0), 6)
                        if current_summary.get("task_wall_clock_duration_sec") is not None and baseline_summary.get("task_wall_clock_duration_sec") is not None
                        else None
                    ),
                }
            )

        for difficulty_name in sorted(set((comparison_aggregate.get("by_difficulty") or {}).keys()) | set((aggregate.get("by_difficulty") or {}).keys())):
            current_bucket = (aggregate.get("by_difficulty") or {}).get(difficulty_name) or {}
            baseline_bucket = (comparison_aggregate.get("by_difficulty") or {}).get(difficulty_name) or {}
            difficulty_rows.append(
                {
                    "variant_id": row["variant_id"],
                    "display_label": row["display_label"],
                    "changed_variable": row["changed_variable"],
                    "comparison_baseline_id": comparison_baseline_id,
                    "comparison_baseline_label": row["comparison_baseline_label"],
                    "difficulty": difficulty_name,
                    "mean_score": current_bucket.get("mean_score"),
                    "baseline_mean_score": baseline_bucket.get("mean_score"),
                    "score_delta": (
                        round(float(current_bucket.get("mean_score") or 0.0) - float(baseline_bucket.get("mean_score") or 0.0), 3)
                        if current_bucket.get("mean_score") is not None and baseline_bucket.get("mean_score") is not None
                        else None
                    ),
                    "task_success_rate": current_bucket.get("task_success_rate"),
                    "baseline_task_success_rate": baseline_bucket.get("task_success_rate"),
                    "mean_task_wall_clock_duration_sec": current_bucket.get("mean_task_wall_clock_duration_sec"),
                    "baseline_mean_task_wall_clock_duration_sec": baseline_bucket.get("mean_task_wall_clock_duration_sec"),
                    "task_wall_clock_duration_delta_sec": (
                        round(float(current_bucket.get("mean_task_wall_clock_duration_sec") or 0.0) - float(baseline_bucket.get("mean_task_wall_clock_duration_sec") or 0.0), 6)
                        if current_bucket.get("mean_task_wall_clock_duration_sec") is not None and baseline_bucket.get("mean_task_wall_clock_duration_sec") is not None
                        else None
                    ),
                }
            )

        for technique_name in sorted(set((comparison_aggregate.get("by_technique") or {}).keys()) | set((aggregate.get("by_technique") or {}).keys())):
            current_bucket = (aggregate.get("by_technique") or {}).get(technique_name) or {}
            baseline_bucket = (comparison_aggregate.get("by_technique") or {}).get(technique_name) or {}
            technique_rows.append(
                {
                    "variant_id": row["variant_id"],
                    "display_label": row["display_label"],
                    "changed_variable": row["changed_variable"],
                    "comparison_baseline_id": comparison_baseline_id,
                    "comparison_baseline_label": row["comparison_baseline_label"],
                    "technique": technique_name,
                    "mean_score": current_bucket.get("mean_score"),
                    "baseline_mean_score": baseline_bucket.get("mean_score"),
                    "score_delta": (
                        round(float(current_bucket.get("mean_score") or 0.0) - float(baseline_bucket.get("mean_score") or 0.0), 3)
                        if current_bucket.get("mean_score") is not None and baseline_bucket.get("mean_score") is not None
                        else None
                    ),
                    "task_success_rate": current_bucket.get("task_success_rate"),
                    "baseline_task_success_rate": baseline_bucket.get("task_success_rate"),
                    "mean_task_wall_clock_duration_sec": current_bucket.get("mean_task_wall_clock_duration_sec"),
                    "baseline_mean_task_wall_clock_duration_sec": baseline_bucket.get("mean_task_wall_clock_duration_sec"),
                    "task_wall_clock_duration_delta_sec": (
                        round(float(current_bucket.get("mean_task_wall_clock_duration_sec") or 0.0) - float(baseline_bucket.get("mean_task_wall_clock_duration_sec") or 0.0), 6)
                        if current_bucket.get("mean_task_wall_clock_duration_sec") is not None and baseline_bucket.get("mean_task_wall_clock_duration_sec") is not None
                        else None
                    ),
                }
            )

    return {
        "grouped_results": grouped_results,
        "has_baseline": bool(global_baseline),
        "variant_rows": variant_rows,
        "dimension_rows": dimension_rows,
        "task_rows": task_rows,
        "difficulty_rows": difficulty_rows,
        "technique_rows": technique_rows,
    }


def _annotate_variant_coverage(
    variant_rows: List[Dict[str, Any]],
    *,
    attempted_counts: Dict[str, int],
    successful_counts: Dict[str, int],
    complete_counts: Dict[str, int],
) -> set[str]:
    row_by_variant = {str(row.get("variant_id") or ""): row for row in variant_rows}
    for row in variant_rows:
        variant_id = str(row.get("variant_id") or "")
        planned_repetitions = int(row.get("planned_repetitions") or 0)
        attempted_repetitions = int(attempted_counts.get(variant_id, int(row.get("attempted_repetitions") or 0)))
        successful_repetitions = int(successful_counts.get(variant_id, 0))
        fully_completed_repetitions = int(complete_counts.get(variant_id, 0))
        incomplete_successful_repetitions = max(0, successful_repetitions - fully_completed_repetitions)
        failed_repetitions = max(0, attempted_repetitions - successful_repetitions)
        intrinsic_complete = bool(planned_repetitions > 0 and fully_completed_repetitions >= planned_repetitions)
        if successful_repetitions <= 0:
            coverage_status = "missing"
        elif intrinsic_complete:
            coverage_status = "complete"
        else:
            coverage_status = "partial"
        row["attempted_repetitions"] = attempted_repetitions
        row["successful_repetitions"] = successful_repetitions
        row["fully_completed_repetitions"] = fully_completed_repetitions
        row["incomplete_successful_repetitions"] = incomplete_successful_repetitions
        row["failed_repetitions"] = failed_repetitions
        row["coverage_status"] = coverage_status
        row["intrinsic_complete"] = intrinsic_complete
        row["comparison_ready"] = False
        row["comparison_status"] = "excluded"
        row["comparison_ready_reason"] = ""
        row["included_in_complete_aggregate"] = False

    baseline_row = row_by_variant.get("baseline")
    baseline_complete = bool(baseline_row and baseline_row.get("intrinsic_complete"))
    ready_ids: set[str] = set()
    if baseline_row is not None:
        baseline_row["comparison_ready"] = baseline_complete
        baseline_row["comparison_status"] = "complete" if baseline_complete else baseline_row.get("coverage_status") or "partial"
        baseline_row["comparison_ready_reason"] = (
            "baseline has full planned coverage"
            if baseline_complete
            else "baseline did not finish its full planned coverage"
        )
        baseline_row["included_in_complete_aggregate"] = baseline_complete
        if baseline_complete:
            ready_ids.add("baseline")

    for row in variant_rows:
        if row.get("is_baseline"):
            continue
        variant_id = str(row.get("variant_id") or "")
        comparison_baseline_id = str(row.get("comparison_baseline_id") or "baseline")
        intrinsic_complete = bool(row.get("intrinsic_complete"))
        baseline_ready = bool(row_by_variant.get(comparison_baseline_id, {}).get("intrinsic_complete"))
        comparison_ready = intrinsic_complete and baseline_ready
        if row.get("is_family_baseline") and comparison_baseline_id == "baseline":
            baseline_ready = baseline_complete
            comparison_ready = intrinsic_complete and baseline_ready
        row["comparison_ready"] = comparison_ready
        row["comparison_status"] = "complete" if comparison_ready else (row.get("coverage_status") or "partial")
        if comparison_ready:
            row["comparison_ready_reason"] = "variant and comparison baseline both have full planned coverage"
            row["included_in_complete_aggregate"] = True
            ready_ids.add(variant_id)
        elif not intrinsic_complete:
            row["comparison_ready_reason"] = "variant did not finish its full planned coverage"
        else:
            row["comparison_ready_reason"] = f"comparison baseline {comparison_baseline_id} did not finish its full planned coverage"
    return ready_ids


def _filter_rows_by_variant_ids(rows: List[Dict[str, Any]], variant_ids: set[str]) -> List[Dict[str, Any]]:
    return [
        row for row in rows
        if str(row.get("variant_id") or "") in variant_ids
    ]


def _build_experiment_report(
    experiment_manifest: Dict[str, Any],
    variant_rows: List[Dict[str, Any]],
    task_rows: List[Dict[str, Any]],
    output_path: Path,
    *,
    title: str = "Experiment Sweep Report",
    executable_rows: List[Dict[str, Any]] | None = None,
    consistency_rows: List[Dict[str, Any]] | None = None,
    coverage_note: str = "",
) -> None:
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- Experiment ID: `{experiment_manifest.get('experiment_id', '')}`")
    lines.append(f"- Corpus: `{experiment_manifest.get('corpus', '')}`")
    lines.append(f"- Baseline variant: `{experiment_manifest.get('baseline_variant_id', 'baseline')}`")
    lines.append(f"- Run count: `{len(variant_rows)}`")
    if coverage_note:
        lines.append(f"- Coverage note: {coverage_note}")
    lines.append("- Interpretation note: these tables are descriptive experiment outputs, not automatically causal conclusions.")
    lines.append("- Statistical note: task-level and difficulty-level significance outputs are exploratory and are not multiple-comparison corrected.")
    lines.append("")

    baseline_row = next((row for row in variant_rows if row.get("is_baseline")), None)
    non_baseline = [row for row in variant_rows if not row.get("is_baseline")]

    if baseline_row:
        lines.append("## Baseline")
        lines.append("")
    elif coverage_note:
        lines.append("## Coverage")
        lines.append("")
        lines.append(f"- {coverage_note}")
        lines.append("")

    if non_baseline:
        scored_variants = [row for row in non_baseline if not row.get("is_family_baseline")]
        complete_scored_variants = [
            row for row in scored_variants
            if float(row.get("completion_rate") or 0.0) >= 1.0
        ]
        highlight_pool = complete_scored_variants or scored_variants or non_baseline
        best_overall = max(highlight_pool, key=lambda row: float(row.get("overall_score_mean") or -1.0))
        variable_impacts: Dict[str, List[float]] = {}
        for row in scored_variants:
            variable_impacts.setdefault(str(row.get("changed_variable") or "unknown"), []).append(abs(float(row.get("score_delta") or 0.0)))
        strongest_variable = max(variable_impacts.items(), key=lambda item: mean(item[1]))[0] if variable_impacts else ""

        cost_effective_candidates = [
            row
            for row in highlight_pool
            if row.get("overall_score_mean") is not None
            and baseline_row
            and float(row.get("overall_score_mean") or 0.0) >= float(baseline_row.get("overall_score_mean") or 0.0) * 0.95
        ]
        cheapest_good = min(
            cost_effective_candidates,
            key=lambda row: float(row.get("mean_relative_cost_index") or 1e9),
        ) if cost_effective_candidates else None

        lines.append("## Highlights")
        lines.append("")
        lines.append(
            f"- Highest observed mean score among complete variants: `{best_overall.get('display_label')}` "
            f"(mean score `{best_overall.get('overall_score_mean')}`, delta vs comparison baseline `{best_overall.get('score_delta')}`)"
        )
        if cheapest_good:
            lines.append(
                f"- Lowest observed mean cost among variants within 5% of the baseline mean score: `{cheapest_good.get('display_label')}` "
                f"(cost `{cheapest_good.get('mean_relative_cost_index')}`, score `{cheapest_good.get('overall_score_mean')}`)"
            )
        if strongest_variable:
            lines.append(f"- Largest mean absolute score shift by variable family: `{strongest_variable}`")
        most_blocked = max(highlight_pool, key=lambda row: float(row.get("validator_blocked_rate") or 0.0)) if highlight_pool else None
        if most_blocked and float(most_blocked.get("validator_blocked_rate") or 0.0) > 0.0:
            lines.append(
                f"- Highest validator-blocked rate: `{most_blocked.get('display_label')}` "
                f"(`{most_blocked.get('validator_blocked_rate')}`)"
            )
        most_redundant = max(
            highlight_pool,
            key=lambda row: float(row.get("mean_tool_semantic_duplicate_calls") or 0.0),
        ) if highlight_pool else None
        if most_redundant and float(most_redundant.get("mean_tool_semantic_duplicate_calls") or 0.0) > 0.0:
            lines.append(
                f"- Highest repeated tool-call load: `{most_redundant.get('display_label')}` "
                f"(`{most_redundant.get('mean_tool_semantic_duplicate_calls')}` mean repeated calls, rate `{most_redundant.get('mean_tool_semantic_duplicate_rate')}`)"
            )
        if consistency_rows:
            mixed_rows = [
                row for row in consistency_rows
                if str(row.get("heterogeneity_label") or "") == "mixed"
            ]
            if mixed_rows:
                most_mixed = max(mixed_rows, key=lambda row: float(row.get("delta_span") or 0.0))
                lines.append(
                    f"- Strongest executable-specific split: `{most_mixed.get('display_label')}` "
                    f"(delta span `{most_mixed.get('delta_span')}`, strongest on `{most_mixed.get('strongest_executable')}` and weakest on `{most_mixed.get('weakest_executable')}`)"
                )
        lines.append("")

        lines.append("## Variant Summary")
        lines.append("")
        lines.append("| Variant | Variable | Comparison Baseline | Replicates | Coverage | Mean Score | Score Delta | Success Rate | Repeated Calls | Repeat Rate | Scored Rate | Produced Result Rate | Synthetic Judge Rate | Validator Blocked Rate | Worker Failure Rate | Judge Error Rate | Cost Index |")
        lines.append("|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for row in variant_rows:
            lines.append(
                "| {label} | {variable} | {baseline} | {replicates} | {coverage} | {score} | {delta} | {success} | {repeat_calls} | {repeat_rate} | {scored} | {produced} | {synthetic} | {blocked} | {worker_failed} | {judge_error} | {cost} |".format(
                    label=row.get("display_label", ""),
                    variable=row.get("changed_variable", "baseline") or "baseline",
                    baseline=row.get("comparison_baseline_label", "baseline") or "baseline",
                    replicates=f"{row.get('completed_repetitions', 0)}/{row.get('planned_repetitions', 0)}",
                    coverage=row.get("coverage_status", ""),
                    score=row.get("overall_score_mean", ""),
                    delta=row.get("score_delta", ""),
                    success=row.get("task_success_rate", ""),
                    repeat_calls=row.get("mean_tool_semantic_duplicate_calls", ""),
                    repeat_rate=row.get("mean_tool_semantic_duplicate_rate", ""),
                    scored=row.get("scored_result_rate", ""),
                    produced=row.get("produced_result_rate", ""),
                    synthetic=row.get("synthetic_judge_rate", ""),
                    blocked=row.get("validator_blocked_rate", ""),
                    worker_failed=row.get("worker_assignment_failed_rate", ""),
                    judge_error=row.get("judge_error_rate", ""),
                    cost=row.get("mean_relative_cost_index", ""),
                )
            )
        lines.append("")

    if task_rows:
        lines.append("## Most Sensitive Sample-Tasks")
        lines.append("")
        sensitivity: Dict[str, float] = {}
        for row in task_rows:
            sample_task = str(row.get("sample_task_id") or row.get("sample") or "")
            sensitivity[sample_task] = max(sensitivity.get(sample_task, 0.0), abs(float(row.get("score_delta") or 0.0)))
        for sample_task, delta in sorted(sensitivity.items(), key=lambda item: item[1], reverse=True)[:10]:
            lines.append(f"- `{sample_task}`: max absolute score delta `{round(delta, 3)}`")
        lines.append("")

    if executable_rows:
        lines.append("## Per-Executable Summary")
        lines.append("")
        lines.append("| Executable | Configuration | Mean Score | Score SD | Delta vs Baseline | Success Rate | Repeated Calls | Repeat Rate |")
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|")
        for row in executable_rows[:40]:
            lines.append(
                "| {sample} | {label} | {score} | {score_sd} | {delta} | {success} | {repeat_calls} | {repeat_rate} |".format(
                    sample=row.get("sample", ""),
                    label=row.get("display_label", ""),
                    score=row.get("mean_score", ""),
                    score_sd=row.get("score_stddev", ""),
                    delta=row.get("score_delta", ""),
                    success=row.get("mean_task_success_rate", ""),
                    repeat_calls=row.get("mean_tool_semantic_duplicate_calls", ""),
                    repeat_rate=row.get("mean_tool_semantic_duplicate_rate", ""),
                )
            )
        lines.append("")

    if consistency_rows:
        lines.append("## Cross-Executable Consistency")
        lines.append("")
        for row in consistency_rows[:10]:
            mask_note = " masked by average" if row.get("masked_by_average") else ""
            lines.append(
                f"- `{row.get('display_label')}`: {row.get('heterogeneity_label')} "
                f"(mean delta `{row.get('mean_score_delta')}`, span `{row.get('delta_span')}`,{mask_note} strongest `{row.get('strongest_executable')}`, weakest `{row.get('weakest_executable')}`)"
            )
        lines.append("")

    lines.append("## Drill-Down Artifacts")
    lines.append("")
    lines.append("- Canonical child runs: `runs/<variant_id>/r###/`")
    lines.append("- Canonical task artifacts: `runs/<variant_id>/r###/cases/<sample>/<task>/`")
    lines.append("- Flat case index: `case_index.csv`")
    lines.append("- Per-executable comparisons: `executable_summary.csv` and `executable_consistency.csv`")
    lines.append("- Redundant tool usage tables: `tool_redundancy_by_variant.csv`, `tool_redundancy_by_executable.csv`, `tool_redundancy_target_hotspots.csv`, `tool_calls_by_source.csv`, and `tool_call_source_runs.csv`")
    lines.append("- Charts: `outputs/*.png`")
    lines.append("- Timing tables: `outputs/task_timing_individual.csv`, `outputs/task_timing_summary.csv`, `outputs/task_tag_timing_summary.csv`, and `outputs/variant_timing_summary.csv`")
    lines.append("- Per-task output comparisons: `outputs/task_output_comparisons/index.html`")
    lines.append("- Per-task comparison tables: `outputs/task_output_comparisons/task_variant_summary.csv` and `outputs/task_output_comparisons/all_rows.csv`")
    lines.append("- Statistical significance tables: `significance_overall.csv`, `significance_by_difficulty.csv`, `significance_by_task.csv`, and `variable_significance_summary.csv`")
    lines.append("- Config-group summary: `config_group_summary.csv`")
    lines.append("- Statistical summary note: `significance_report.md`")
    lines.append("")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

"""
Function: materialize_experiment_outputs
Inputs:
  - experiment_root: experiment directory that should receive aggregate
    comparison outputs.
  - experiment_manifest: canonical sweep manifest describing planned runs
    and scope filters.
  - run_entries: run catalog rows with attached manifests and aggregates.
  - skip_visuals: when True, skip PNG chart generation.
Description:
  Rebuild the experiment-level CSV summaries, drill-down layouts, timing
  tables, significance reports, and visualization artifacts from an
  existing set of child-run results.
Outputs:
  Returns a compact payload describing coverage and written output scope.
Side Effects:
  Overwrites experiment-level summary files under `experiment_root`.
"""
def materialize_experiment_outputs(
    *,
    experiment_root: Path,
    experiment_manifest: Dict[str, Any],
    run_entries: List[Dict[str, Any]],
    skip_visuals: bool = False,
) -> Dict[str, Any]:
    experiment_root = experiment_root.resolve()
    outputs_root = ensure_dir(experiment_root / "outputs")
    experiment_id = str(experiment_manifest.get("experiment_id") or experiment_root.name)
    planned_runs = list(experiment_manifest.get("planned_runs") or [])
    repetitions = int(experiment_manifest.get("repetitions") or 1)

    _write_run_catalog(experiment_root, run_entries)

    grouped_all_runs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in run_entries:
        grouped_all_runs[str(entry.get("variant_id") or "")].append(entry)

    successful_runs = [entry for entry in run_entries if entry.get("ok") and isinstance(entry.get("aggregate"), dict)]
    complete_successful_runs = [entry for entry in successful_runs if _run_entry_has_full_task_coverage(entry)]
    grouped_successful_all: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    grouped_successful_complete: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for entry in successful_runs:
        grouped_successful_all[str(entry.get("variant_id") or "")].append(entry)
    for entry in complete_successful_runs:
        grouped_successful_complete[str(entry.get("variant_id") or "")].append(entry)

    attempted_counts = {
        variant_id: len(entries)
        for variant_id, entries in grouped_all_runs.items()
    }
    successful_counts = {
        variant_id: len(entries)
        for variant_id, entries in grouped_successful_all.items()
    }
    complete_counts = {
        variant_id: len(entries)
        for variant_id, entries in grouped_successful_complete.items()
    }

    all_tables = _build_comparison_tables(
        planned_runs=planned_runs,
        repetitions=repetitions,
        grouped_all_runs=grouped_all_runs,
        grouped_successful=grouped_successful_all,
    )
    complete_tables = _build_comparison_tables(
        planned_runs=planned_runs,
        repetitions=repetitions,
        grouped_all_runs=grouped_all_runs,
        grouped_successful=grouped_successful_complete,
    )

    _annotate_variant_coverage(
        list(all_tables.get("variant_rows") or []),
        attempted_counts=attempted_counts,
        successful_counts=successful_counts,
        complete_counts=complete_counts,
    )
    complete_variant_ids = _annotate_variant_coverage(
        list(complete_tables.get("variant_rows") or []),
        attempted_counts=attempted_counts,
        successful_counts=successful_counts,
        complete_counts=complete_counts,
    )
    partial_variant_ids = {
        str(row.get("variant_id") or "")
        for row in (all_tables.get("variant_rows") or [])
        if (
            str(row.get("variant_id") or "") not in complete_variant_ids
            and int(row.get("attempted_repetitions") or 0) > 0
        )
    }

    variant_rows = _filter_rows_by_variant_ids(list(complete_tables.get("variant_rows") or []), complete_variant_ids)
    dimension_rows = _filter_rows_by_variant_ids(list(complete_tables.get("dimension_rows") or []), complete_variant_ids)
    task_rows = _filter_rows_by_variant_ids(list(complete_tables.get("task_rows") or []), complete_variant_ids)
    difficulty_rows = _filter_rows_by_variant_ids(list(complete_tables.get("difficulty_rows") or []), complete_variant_ids)
    technique_rows = _filter_rows_by_variant_ids(list(complete_tables.get("technique_rows") or []), complete_variant_ids)

    partial_variant_rows = _filter_rows_by_variant_ids(list(all_tables.get("variant_rows") or []), partial_variant_ids)
    partial_dimension_rows = _filter_rows_by_variant_ids(list(all_tables.get("dimension_rows") or []), partial_variant_ids)
    partial_task_rows = _filter_rows_by_variant_ids(list(all_tables.get("task_rows") or []), partial_variant_ids)
    partial_difficulty_rows = _filter_rows_by_variant_ids(list(all_tables.get("difficulty_rows") or []), partial_variant_ids)
    partial_technique_rows = _filter_rows_by_variant_ids(list(all_tables.get("technique_rows") or []), partial_variant_ids)
    partial_successful_runs = [
        entry for entry in successful_runs
        if str(entry.get("variant_id") or "") in partial_variant_ids
    ]
    executable_outputs = _build_executable_summary_tables(
        run_entries=complete_successful_runs,
        variant_rows=variant_rows,
    )
    partial_executable_outputs = _build_executable_summary_tables(
        run_entries=partial_successful_runs,
        variant_rows=partial_variant_rows,
    )

    baseline_group = (complete_tables.get("grouped_results") or {}).get("baseline") if isinstance(complete_tables.get("grouped_results"), dict) else None
    baseline_run_ids = list((baseline_group or {}).get("run_ids") or [])
    comparison_payload = {
        "experiment_id": experiment_id,
        "baseline_variant_id": "baseline",
        "baseline_run_ids": baseline_run_ids,
        "coverage": {
            "complete_variant_ids": sorted(complete_variant_ids),
            "partial_variant_ids": sorted(partial_variant_ids),
            "complete_variant_count": len(complete_variant_ids),
            "partial_variant_count": len(partial_variant_ids),
            "complete_baseline_available": "baseline" in complete_variant_ids,
        },
        "variant_summary": variant_rows,
        "dimension_summary": dimension_rows,
        "task_comparison": task_rows,
        "difficulty_summary": difficulty_rows,
        "technique_summary": technique_rows,
        "executable_summary": list(executable_outputs.get("executable_rows") or []),
        "executable_runtime_cost_summary": list(executable_outputs.get("resource_rows") or []),
        "executable_consistency": list(executable_outputs.get("consistency_rows") or []),
        "tool_redundancy_by_variant": list(executable_outputs.get("variant_tool_rows") or []),
        "tool_redundancy_by_executable": list(executable_outputs.get("executable_tool_rows") or []),
        "tool_redundancy_target_hotspots": list(executable_outputs.get("target_rows") or []),
        "tool_calls_by_source": list(executable_outputs.get("source_tool_rows") or []),
        "tool_call_source_runs": list(executable_outputs.get("source_run_rows") or []),
        "config_group_summary": [],
    }
    partial_comparison_payload = {
        "experiment_id": experiment_id,
        "baseline_variant_id": "baseline",
        "coverage_label": "partial",
        "variant_summary": partial_variant_rows,
        "dimension_summary": partial_dimension_rows,
        "task_comparison": partial_task_rows,
        "difficulty_summary": partial_difficulty_rows,
        "technique_summary": partial_technique_rows,
        "executable_summary": list(partial_executable_outputs.get("executable_rows") or []),
        "executable_runtime_cost_summary": list(partial_executable_outputs.get("resource_rows") or []),
        "executable_consistency": list(partial_executable_outputs.get("consistency_rows") or []),
        "tool_redundancy_by_variant": list(partial_executable_outputs.get("variant_tool_rows") or []),
        "tool_redundancy_by_executable": list(partial_executable_outputs.get("executable_tool_rows") or []),
        "tool_redundancy_target_hotspots": list(partial_executable_outputs.get("target_rows") or []),
        "tool_calls_by_source": list(partial_executable_outputs.get("source_tool_rows") or []),
        "tool_call_source_runs": list(partial_executable_outputs.get("source_run_rows") or []),
    }
    _write_rows_csv(experiment_root / "variant_summary.csv", variant_rows)
    _write_rows_csv(experiment_root / "dimension_summary.csv", dimension_rows)
    _write_rows_csv(experiment_root / "task_comparison.csv", task_rows)
    _write_rows_csv(experiment_root / "difficulty_summary.csv", difficulty_rows)
    _write_rows_csv(experiment_root / "technique_summary.csv", technique_rows)
    _write_rows_csv(experiment_root / "partial_variant_summary.csv", partial_variant_rows)
    _write_rows_csv(experiment_root / "partial_dimension_summary.csv", partial_dimension_rows)
    _write_rows_csv(experiment_root / "partial_task_comparison.csv", partial_task_rows)
    _write_rows_csv(experiment_root / "partial_difficulty_summary.csv", partial_difficulty_rows)
    _write_rows_csv(experiment_root / "partial_technique_summary.csv", partial_technique_rows)
    _write_rows_csv(experiment_root / "executable_summary.csv", list(executable_outputs.get("executable_rows") or []))
    _write_rows_csv(experiment_root / "executable_runtime_cost_summary.csv", list(executable_outputs.get("resource_rows") or []))
    _write_rows_csv(experiment_root / "executable_consistency.csv", list(executable_outputs.get("consistency_rows") or []))
    _write_rows_csv(experiment_root / "tool_redundancy_by_variant.csv", list(executable_outputs.get("variant_tool_rows") or []))
    _write_rows_csv(experiment_root / "tool_redundancy_by_executable.csv", list(executable_outputs.get("executable_tool_rows") or []))
    _write_rows_csv(experiment_root / "tool_redundancy_target_hotspots.csv", list(executable_outputs.get("target_rows") or []))
    _write_rows_csv(experiment_root / "tool_calls_by_source.csv", list(executable_outputs.get("source_tool_rows") or []))
    _write_rows_csv(experiment_root / "tool_call_source_runs.csv", list(executable_outputs.get("source_run_rows") or []))
    _write_rows_csv(experiment_root / "partial_executable_summary.csv", list(partial_executable_outputs.get("executable_rows") or []))
    _write_rows_csv(experiment_root / "partial_executable_runtime_cost_summary.csv", list(partial_executable_outputs.get("resource_rows") or []))
    _write_rows_csv(experiment_root / "partial_executable_consistency.csv", list(partial_executable_outputs.get("consistency_rows") or []))
    _write_rows_csv(experiment_root / "partial_tool_redundancy_by_variant.csv", list(partial_executable_outputs.get("variant_tool_rows") or []))
    _write_rows_csv(experiment_root / "partial_tool_redundancy_by_executable.csv", list(partial_executable_outputs.get("executable_tool_rows") or []))
    _write_rows_csv(experiment_root / "partial_tool_redundancy_target_hotspots.csv", list(partial_executable_outputs.get("target_rows") or []))
    _write_rows_csv(experiment_root / "partial_tool_calls_by_source.csv", list(partial_executable_outputs.get("source_tool_rows") or []))
    _write_rows_csv(experiment_root / "partial_tool_call_source_runs.csv", list(partial_executable_outputs.get("source_run_rows") or []))

    run_catalog_rows = [
        {
            "variant_id": entry.get("variant_id", ""),
            "variant_name": entry.get("variant_name", ""),
            "changed_variable": entry.get("changed_variable", ""),
            "comparison_baseline_id": entry.get("comparison_baseline_id", ""),
            "comparison_baseline_label": entry.get("comparison_baseline_label", ""),
            "config_lineage_id": (((entry.get("run_manifest") or {}) if isinstance(entry.get("run_manifest"), dict) else {}).get("config_lineage_id") or ""),
            "replicate_index": entry.get("replicate_index", ""),
            "run_id": entry.get("run_id", ""),
            "run_dir": entry.get("run_dir", ""),
            "run_path": entry.get("run_path", ""),
            "log_rel_path": entry.get("log_rel_path", ""),
            "ok": entry.get("ok", False),
            "overall_score_mean": ((entry.get("aggregate") or {}).get("overall_score_mean") if isinstance(entry.get("aggregate"), dict) else None),
            "task_success_rate": ((entry.get("aggregate") or {}).get("task_success_rate") if isinstance(entry.get("aggregate"), dict) else None),
            "scored_result_rate": ((entry.get("aggregate") or {}).get("scored_result_rate") if isinstance(entry.get("aggregate"), dict) else None),
            "produced_result_rate": ((entry.get("aggregate") or {}).get("produced_result_rate") if isinstance(entry.get("aggregate"), dict) else None),
            "validator_blocked_rate": ((entry.get("aggregate") or {}).get("validator_blocked_rate") if isinstance(entry.get("aggregate"), dict) else None),
            "analysis_failure_rate": ((entry.get("aggregate") or {}).get("analysis_failure_rate") if isinstance(entry.get("aggregate"), dict) else None),
            "judge_error_rate": ((entry.get("aggregate") or {}).get("judge_error_rate") if isinstance(entry.get("aggregate"), dict) else None),
            "mean_total_duration_sec": ((entry.get("aggregate") or {}).get("mean_total_duration_sec") if isinstance(entry.get("aggregate"), dict) else None),
            "mean_task_wall_clock_duration_sec": ((entry.get("aggregate") or {}).get("mean_task_wall_clock_duration_sec") if isinstance(entry.get("aggregate"), dict) else None),
            "sample_count": ((entry.get("aggregate") or {}).get("sample_count") if isinstance(entry.get("aggregate"), dict) else None),
            "expected_task_count": ((entry.get("aggregate") or {}).get("expected_task_count") if isinstance(entry.get("aggregate"), dict) else None),
            "task_completion_rate": ((entry.get("aggregate") or {}).get("task_completion_rate") if isinstance(entry.get("aggregate"), dict) else None),
            "full_task_coverage": _run_entry_has_full_task_coverage(entry) if isinstance(entry.get("aggregate"), dict) else False,
            "error": entry.get("error", ""),
        }
        for entry in run_entries
    ]
    _write_rows_csv(experiment_root / "run_catalog.csv", run_catalog_rows)

    config_group_rows = _build_config_group_summary_rows(successful_runs)
    _write_rows_csv(experiment_root / "config_group_summary.csv", config_group_rows)
    comparison_payload["config_group_summary"] = config_group_rows
    partial_comparison_payload["config_group_summary"] = config_group_rows
    write_json(experiment_root / "comparison.json", comparison_payload)
    write_json(experiment_root / "partial_comparison.json", partial_comparison_payload)

    partial_outputs_root = ensure_dir(outputs_root / "partial")

    timing_result = build_timing_outputs(
        outputs_root,
        run_entries=complete_successful_runs,
        variant_rows=variant_rows,
    )
    partial_timing_result = build_timing_outputs(
        partial_outputs_root,
        run_entries=partial_successful_runs,
        variant_rows=partial_variant_rows,
    ) if partial_variant_rows else {
        "variant_timing_rows": [],
        "task_summary_rows": [],
        "task_tag_summary_rows": [],
    }

    build_task_output_comparisons(
        outputs_root / "task_output_comparisons",
        run_entries=complete_successful_runs,
    )
    if partial_successful_runs:
        build_task_output_comparisons(
            partial_outputs_root / "task_output_comparisons",
            run_entries=partial_successful_runs,
        )

    result_layout_payload = build_experiment_output_layout(
        experiment_root=experiment_root,
        experiment_id=experiment_id,
        successful_entries=successful_runs,
    )
    write_json(experiment_root / "result_layout.json", result_layout_payload)

    significance_result = build_significance_outputs(
        experiment_root,
        successful_entries=complete_successful_runs,
        variant_rows=variant_rows,
    )

    significance_payload = dict(significance_result.get("payload") or {})

    if not skip_visuals:
        generate_experiment_visuals(
            outputs_root,
            variant_rows=variant_rows,
            dimension_rows=dimension_rows,
            task_rows=task_rows,
            difficulty_rows=difficulty_rows,
            technique_rows=technique_rows,
            executable_rows=list(executable_outputs.get("executable_rows") or []),
            executable_resource_rows=list(executable_outputs.get("resource_rows") or []),
            executable_consistency_rows=list(executable_outputs.get("consistency_rows") or []),
            redundancy_variant_rows=list(executable_outputs.get("variant_tool_rows") or []),
            redundancy_executable_rows=list(executable_outputs.get("executable_tool_rows") or []),
            redundancy_target_rows=list(executable_outputs.get("target_rows") or []),
            source_tool_rows=list(executable_outputs.get("source_tool_rows") or []),
            source_run_rows=list(executable_outputs.get("source_run_rows") or []),
            significance_overall_rows=list(significance_payload.get("overall") or []),
            significance_difficulty_rows=list(significance_payload.get("by_difficulty") or []),
            significance_task_rows=list(significance_payload.get("by_task") or []),
            paired_task_overall_rows=list(significance_payload.get("paired_task_overall") or []),
            paired_task_difficulty_rows=list(significance_payload.get("paired_task_by_difficulty") or []),
            timing_variant_rows=list(timing_result.get("variant_timing_rows") or []),
            timing_task_rows=list(timing_result.get("task_summary_rows") or []),
            timing_task_tag_rows=list(timing_result.get("task_tag_summary_rows") or []),
        )
        if partial_variant_rows:
            generate_experiment_visuals(
                partial_outputs_root,
                variant_rows=partial_variant_rows,
                dimension_rows=partial_dimension_rows,
                task_rows=partial_task_rows,
                difficulty_rows=partial_difficulty_rows,
                technique_rows=partial_technique_rows,
                executable_rows=list(partial_executable_outputs.get("executable_rows") or []),
                executable_resource_rows=list(partial_executable_outputs.get("resource_rows") or []),
                executable_consistency_rows=list(partial_executable_outputs.get("consistency_rows") or []),
                redundancy_variant_rows=list(partial_executable_outputs.get("variant_tool_rows") or []),
                redundancy_executable_rows=list(partial_executable_outputs.get("executable_tool_rows") or []),
                redundancy_target_rows=list(partial_executable_outputs.get("target_rows") or []),
                source_tool_rows=list(partial_executable_outputs.get("source_tool_rows") or []),
                source_run_rows=list(partial_executable_outputs.get("source_run_rows") or []),
                timing_variant_rows=list(partial_timing_result.get("variant_timing_rows") or []),
                timing_task_rows=list(partial_timing_result.get("task_summary_rows") or []),
                timing_task_tag_rows=list(partial_timing_result.get("task_tag_summary_rows") or []),
                title_prefix="Partial Coverage",
            )

    coverage_note = ""
    if partial_variant_rows:
        coverage_note = (
            f"{len(partial_variant_rows)} variant row(s) were excluded from the main aggregate outputs because they "
            "did not receive full planned coverage. See partial_*.csv and outputs/partial/ for incomplete comparisons."
        )
    elif "baseline" not in complete_variant_ids:
        coverage_note = "No fully covered baseline completed; the main aggregate comparison outputs are intentionally empty."

    _build_experiment_report(
        experiment_manifest,
        variant_rows,
        task_rows,
        experiment_root / "report.md",
        executable_rows=list(executable_outputs.get("executable_rows") or []),
        consistency_rows=list(executable_outputs.get("consistency_rows") or []),
        coverage_note=coverage_note,
    )
    if partial_variant_rows:
        _build_experiment_report(
            experiment_manifest,
            partial_variant_rows,
            partial_task_rows,
            experiment_root / "partial_report.md",
            title="Partial Coverage Report",
            executable_rows=list(partial_executable_outputs.get("executable_rows") or []),
            consistency_rows=list(partial_executable_outputs.get("consistency_rows") or []),
            coverage_note="These rows include incomplete or interrupted comparison groups and are excluded from the main aggregate outputs.",
        )

    return {
        "experiment_id": experiment_id,
        "run_count": len(run_entries),
        "successful_run_count": len(successful_runs),
        "complete_variant_ids": sorted(complete_variant_ids),
        "partial_variant_ids": sorted(partial_variant_ids),
    }


def _value_series(entries: List[Dict[str, Any]], path: str) -> List[float]:
    parts = path.split(".")
    values: List[float] = []
    for entry in entries:
        value: Any = entry
        for part in parts:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        try:
            if value is not None:
                values.append(float(value))
        except Exception:
            continue
    return values


def _invoke_child_run_spec(
    spec: Dict[str, Any],
    *,
    runner: Callable[..., Dict[str, Any]] = run_command,
) -> Dict[str, Any]:
    stream_capture_path = spec.get("stream_capture_path")
    capture_path = (
        Path(str(stream_capture_path)).expanduser()
        if str(stream_capture_path or "").strip()
        else None
    )
    cwd_value = spec.get("cwd")
    cwd = Path(str(cwd_value)).expanduser() if cwd_value else None
    return runner(
        list(spec.get("cmd") or []),
        cwd=cwd,
        timeout_sec=spec.get("timeout_sec"),
        stream_output=bool(spec.get("stream_output")),
        stream_prefix=str(spec.get("stream_prefix") or ""),
        stream_heartbeat_sec=int(spec.get("stream_heartbeat_sec") or 30),
        stream_capture_path=capture_path,
    )


def _execute_child_run_specs(
    child_specs: List[Dict[str, Any]],
    *,
    max_concurrent: int,
    runner: Callable[..., Dict[str, Any]] = run_command,
    on_launch: Callable[[Dict[str, Any]], None] | None = None,
    on_complete: Callable[[Dict[str, Any], Dict[str, Any]], bool | None] | None = None,
    max_concurrent_per_group: int | None = None,
    group_key_fn: Callable[[Dict[str, Any]], str] | None = None,
) -> None:
    concurrency = max(1, int(max_concurrent or 1))
    per_group_limit = max(1, int(max_concurrent_per_group or 0)) if max_concurrent_per_group is not None else None
    allow_new_launches = True

    def _group_key(spec: Dict[str, Any]) -> str:
        if group_key_fn is None:
            return ""
        return str(group_key_fn(spec) or "")

    pending_specs: List[Dict[str, Any]] = list(child_specs)
    future_to_spec: Dict[Any, Tuple[Dict[str, Any], str]] = {}
    active_by_group: Dict[str, int] = defaultdict(int)
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="sweep-child") as executor:
        while pending_specs or future_to_spec:
            while allow_new_launches and len(future_to_spec) < concurrency:
                launch_index: int | None = None
                launch_group = ""
                for index, spec in enumerate(pending_specs):
                    candidate_group = _group_key(spec)
                    if per_group_limit is not None and candidate_group and active_by_group.get(candidate_group, 0) >= per_group_limit:
                        continue
                    launch_index = index
                    launch_group = candidate_group
                    break
                if launch_index is None:
                    break
                spec = pending_specs.pop(launch_index)
                if on_launch is not None:
                    on_launch(spec)
                if per_group_limit is not None and launch_group:
                    active_by_group[launch_group] += 1
                future = executor.submit(_invoke_child_run_spec, spec, runner=runner)
                future_to_spec[future] = (spec, launch_group)

            if not future_to_spec:
                break

            completed_futures, _ = wait(list(future_to_spec.keys()), return_when=FIRST_COMPLETED)
            for future in completed_futures:
                spec, launch_group = future_to_spec.pop(future)
                if per_group_limit is not None and launch_group:
                    active_by_group[launch_group] = max(0, int(active_by_group.get(launch_group, 0)) - 1)
                try:
                    completed = future.result()
                except Exception as exc:
                    completed = {
                        "ok": False,
                        "returncode": None,
                        "command": list(spec.get("cmd") or []),
                        "stdout": "",
                        "stderr": "",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                if on_complete is not None and on_complete(spec, completed) is False:
                    allow_new_launches = False

"""
Function: run_experiment_sweep
Inputs:
  - argv: optional explicit argument list. When omitted, arguments are read
    from the process command line.
Description:
  Execute the maintained experiment-sweep workflow: plan the baseline-first
  run matrix, perform preflight, launch child evaluations, and aggregate the
  experiment-level outputs.
Outputs:
  Returns nothing. Exits with an error when the experiment cannot be run or
  when required child runs fail.
Side Effects:
  May build binaries, prepare bundles, launch many child processes, start
  the live-view server, and write experiment artifacts under results/.
"""
def run_experiment_sweep(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run a baseline + one-variable-at-a-time experiment sweep across the binary analysis corpus.")
    parser.add_argument("--config", default=str(CONFIG_ROOT / "experiment_sweeps.json"))
    parser.add_argument("--corpus", choices=["prototype", "experimental", "final_round"], default="")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample filename(s) to restrict to")
    parser.add_argument("--task", action="append", default=[], help="Optional task id(s) to restrict to when sample manifests define multiple evaluation tasks")
    parser.add_argument("--difficulty-filter", action="append", default=[], help="Optional difficulty label(s) to restrict to, e.g. --difficulty-filter medium --difficulty-filter hard")
    parser.add_argument("--variable", action="append", default=[], help="Optional variable name(s) to restrict the sweep to")
    parser.add_argument("--label", default="", help="Optional short label for this experiment sweep")
    parser.add_argument("--meta", action="append", default=[], help="Extra experiment metadata in key=value form")
    parser.add_argument("--skip-build", action="store_true", help="Reuse existing built binaries")
    parser.add_argument("--clean-build", action="store_true", help="Run make clean before rebuilding")
    parser.add_argument("--skip-prepare", action="store_true", help="Reuse existing prepared bundles")
    parser.add_argument("--skip-cli-tools", action="store_true", help="Skip optional CLI tools during bundle preparation")
    parser.add_argument("--keep-project", action="store_true", help="Preserve temporary Ghidra projects during headless export")
    parser.add_argument("--ghidra-install-dir", default="", help="Optional GHIDRA_INSTALL_DIR override")
    parser.add_argument("--ghidra-headless", default="", help="Optional analyzeHeadless override")
    parser.add_argument("--prefer-unpacked-upx", action="store_true", help="When a sample is recognized as UPX-packed, build a derived unpacked bundle and continue downstream analysis against it. Falls back to the original bundle if unpacking fails.")
    parser.add_argument("--task-failure-retries", type=int, default=0, help="Retry retryable sample-task failures this many times after the first attempt inside each child run.")
    parser.add_argument("--deep-agent-request-limit", type=int, default=None, help="Override the deep-agent request cap for every child evaluation run. Omit to use the maintained testing default, or pass 0 to disable the cap.")
    parser.add_argument("--judge-model", default="", help="Optional judge model override")
    parser.add_argument("--enable-budget-guardrails", action="store_true", help="Enable child-run and experiment budget guardrails. When omitted, all budget ceilings are disabled even if config defaults or preset values exist.")
    parser.add_argument("--max-run-input-tokens", type=int, default=None, help="Abort a child run after the current task if cumulative input tokens exceed this ceiling. Only active with --enable-budget-guardrails.")
    parser.add_argument("--max-run-output-tokens", type=int, default=None, help="Abort a child run after the current task if cumulative output tokens exceed this ceiling. Only active with --enable-budget-guardrails.")
    parser.add_argument("--max-run-total-tokens", type=int, default=None, help="Abort a child run after the current task if cumulative total tokens exceed this ceiling. Only active with --enable-budget-guardrails.")
    parser.add_argument("--max-run-relative-cost-index", type=float, default=None, help="Abort a child run after the current task if relative cost exceeds this ceiling. Only active with --enable-budget-guardrails.")
    parser.add_argument("--max-run-estimated-cost-usd", type=float, default=None, help="Advisory warning threshold for child-run estimated USD cost. Only active with --enable-budget-guardrails.")
    parser.add_argument("--hard-max-run-estimated-cost-usd", type=float, default=None, help="Optional explicit hard-stop ceiling for child-run estimated USD cost. Only active with --enable-budget-guardrails.")
    parser.add_argument("--max-experiment-relative-cost-index", type=float, default=None, help="Abort the sweep when cumulative relative cost exceeds this ceiling. Only active with --enable-budget-guardrails.")
    parser.add_argument("--max-experiment-estimated-cost-usd", type=float, default=None, help="Advisory warning threshold for projected or cumulative experiment estimated USD cost. Only active with --enable-budget-guardrails.")
    parser.add_argument("--hard-max-experiment-estimated-cost-usd", type=float, default=None, help="Optional explicit hard-stop ceiling for projected or cumulative experiment estimated USD cost. Only active with --enable-budget-guardrails.")
    parser.add_argument("--timeout-sec", type=int, default=0, help="Optional subprocess timeout in seconds for child runs; 0 disables it")
    parser.add_argument("--repetitions", type=int, default=0, help="Optional repetition-count override; 0 uses the config default")
    parser.add_argument("--max-concurrent-repetitions", type=int, default=1, help="Maximum number of child repetitions for the same planned configuration to execute at once. Default is 1 (sequential).")
    parser.add_argument("--max-concurrent-child-runs", type=int, default=0, help="Maximum total child runs across the whole sweep to execute at once. 0 uses the same limit as --max-concurrent-repetitions.")
    parser.add_argument("--skip-visuals", action="store_true", help="Skip PNG chart generation")
    parser.add_argument("--quiet-child-output", action="store_true", help="Do not stream child run status/output while the sweep is running")
    parser.add_argument("--live-view", action="store_true", help="Start a lightweight local progress monitor that polls the sweep artifacts while runs are executing")
    parser.add_argument("--plan-only", action="store_true", help="Write the run plan but do not execute it")
    parser.add_argument("--preflight-only", action="store_true", help="Validate rubric/config/build/bundle readiness and exit before launching child runs")
    parser.add_argument("--resume", default="", help="Resume a previously started sweep by experiment directory path or experiment id. Skips already-completed runs.")
    args = parser.parse_args(argv)

    config = _load_experiment_config(Path(args.config))
    baseline_cfg, planned_runs, config_repetitions = _build_run_plan(config, variable_filters=args.variable, corpus_override=args.corpus)
    repetitions = max(1, int(args.repetitions or config_repetitions))
    corpus_name = str(baseline_cfg.get("corpus") or "experimental").strip()
    corpus = get_corpus_config(corpus_name)
    manifest = load_sample_manifest(corpus_name)
    budget_config = resolve_budget_config(
        enable_budget_guardrails=bool(args.enable_budget_guardrails),
        max_run_input_tokens=args.max_run_input_tokens,
        max_run_output_tokens=args.max_run_output_tokens,
        max_run_total_tokens=args.max_run_total_tokens,
        max_run_relative_cost_index=args.max_run_relative_cost_index,
        max_run_estimated_cost_usd=args.max_run_estimated_cost_usd,
        hard_max_run_estimated_cost_usd=args.hard_max_run_estimated_cost_usd,
        max_experiment_relative_cost_index=args.max_experiment_relative_cost_index,
        max_experiment_estimated_cost_usd=args.max_experiment_estimated_cost_usd,
        hard_max_experiment_estimated_cost_usd=args.hard_max_experiment_estimated_cost_usd,
    )

    # --resume reuses an existing experiment directory for real sweeps only.
    sweep_root = _resolve_sweep_root(
        corpus_name=corpus_name,
        label=str(args.label or ""),
        resume_path=str(args.resume or ""),
        preflight_only=bool(args.preflight_only),
    )
    prior_run_entries: List[Dict[str, Any]] = []
    if str(args.resume or "").strip():
        catalog_path = sweep_root / "run_catalog.json"
        if catalog_path.exists():
            prior_catalog = read_json(catalog_path)
            prior_run_entries = [
                entry for entry in (prior_catalog.get("runs") or [])
                if entry.get("ok") and isinstance(entry.get("aggregate"), dict)
            ]
    experiment_root = sweep_root

    experiment_id = experiment_root.name
    outputs_root = ensure_dir(experiment_root / "outputs") if not args.preflight_only else (experiment_root / "outputs")
    live_view_dir = ensure_dir(experiment_root / "live_view") if not args.preflight_only else (experiment_root / "live_view")
    live_view_server = None
    live_view_thread = None
    live_view_url = ""

    selected_samples_for_manifest = list(args.sample) or list(manifest.get("sample_order") or [])
    manifest_planned_runs = [
        dict(run_cfg, prefer_upx_unpacked=True) if args.prefer_unpacked_upx else dict(run_cfg)
        for run_cfg in planned_runs
    ]
    deep_agent_request_limit = resolve_testing_deep_agent_request_limit(args.deep_agent_request_limit)
    effective_max_concurrent_repetitions = max(1, int(args.max_concurrent_repetitions or 1))
    effective_max_concurrent_child_runs = max(
        1,
        int(args.max_concurrent_child_runs or effective_max_concurrent_repetitions),
    )

    experiment_manifest = {
        "experiment_id": experiment_id,
        "config_path": str(Path(args.config).resolve()),
        "corpus": corpus_name,
        "selected_samples": selected_samples_for_manifest,
        "selected_tasks": list(args.task),
        "selected_difficulties": list(args.difficulty_filter),
        "repetitions": repetitions,
        "max_concurrent_repetitions": effective_max_concurrent_repetitions,
        "max_concurrent_child_runs": effective_max_concurrent_child_runs,
        "enable_budget_guardrails": bool(args.enable_budget_guardrails),
        "prefer_upx_unpacked": bool(args.prefer_unpacked_upx),
        "deep_agent_request_limit": deep_agent_request_limit,
        "budget_config": budget_config,
        "meta": _parse_metadata(args.meta),
        "baseline_variant_id": "baseline",
        "planned_runs": manifest_planned_runs,
    }
    write_json(experiment_root / "experiment_manifest.json", experiment_manifest)

    planned_instances: List[Dict[str, Any]] = []
    for run_cfg in planned_runs:
        effective_run_cfg = dict(run_cfg)
        if args.prefer_unpacked_upx:
            effective_run_cfg["prefer_upx_unpacked"] = True
        for repetition_index in range(1, repetitions + 1):
            planned_instances.append(
                _planned_run_instance(
                    experiment_root=experiment_root,
                    experiment_id=experiment_id,
                    corpus_name=corpus_name,
                    run_cfg=effective_run_cfg,
                    repetition_index=repetition_index,
                    planned_repetitions=repetitions,
                )
            )

    prior_entry_map: Dict[str, Dict[str, Any]] = {
        _run_instance_key(entry): entry for entry in prior_run_entries if isinstance(entry, dict)
    }
    run_entries: List[Dict[str, Any]] = []
    for planned_entry in planned_instances:
        existing = prior_entry_map.get(_run_instance_key(planned_entry))
        if existing:
            merged = dict(planned_entry)
            merged.update(existing)
            if merged.get("ok") is True and isinstance(merged.get("aggregate"), dict):
                merged["status"] = "completed"
            elif merged.get("status") not in {"pending", "running", "completed", "failed", "skipped"}:
                merged["status"] = "pending"
            run_entries.append(merged)
        else:
            run_entries.append(planned_entry)
    _write_run_catalog(experiment_root, run_entries)
    run_entry_index: Dict[str, int] = {
        _run_instance_key(entry): index for index, entry in enumerate(run_entries)
    }

    if args.live_view:
        live_view_server, live_view_thread, live_view_url = start_live_view_server(experiment_root)
        print(f"[live-view] monitor available at {live_view_url}", file=sys.stderr, flush=True)
        experiment_manifest["live_view_url"] = live_view_url
        write_json(experiment_root / "experiment_manifest.json", experiment_manifest)

    if args.plan_only:
        print(json.dumps({"experiment_id": experiment_id, "experiment_root": str(experiment_root), "planned_runs": len(planned_runs), "repetitions": repetitions}, indent=2))
        return

    sample_paths = list_sample_binaries(
        corpus_name,
        selected=args.sample,
        difficulty_filters=args.difficulty_filter,
        manifest=manifest,
    )
    build_record: Dict[str, Any] = {"skipped": True}
    if not args.skip_build:
        build_record = build_corpus(
            corpus_name,
            clean_first=args.clean_build,
            include_gcc=True,
            timeout_sec=args.timeout_sec,
        )
        sample_paths = list_sample_binaries(
            corpus_name,
            selected=args.sample,
            difficulty_filters=args.difficulty_filter,
            manifest=manifest,
        )
    if not sample_paths:
        raise SystemExit(f"No built sample binaries found for corpus={corpus_name} under {corpus.build_root}")
    evaluation_tasks = build_evaluation_tasks(
        corpus_name,
        sample_paths,
        manifest=manifest,
        selected_task_ids=args.task,
        selected_difficulties=args.difficulty_filter,
    )
    if not evaluation_tasks:
        raise SystemExit(f"No evaluation tasks resolved for corpus={corpus_name}; check the manifest task definitions.")

    bundle_root = ensure_dir(BUNDLE_ROOT / corpus_name)
    prepare_record: Dict[str, Any] = {"skipped": True}
    if not args.skip_prepare:
        prepare_record = prepare_corpus_bundles(
            corpus_name,
            sample_paths,
            manifest.get("samples") or {},
            output_root=bundle_root,
            timeout_sec=args.timeout_sec,
            ghidra_install_dir=args.ghidra_install_dir,
            ghidra_headless=args.ghidra_headless,
            skip_cli_tools=args.skip_cli_tools,
            keep_project=args.keep_project,
        )

    experiment_manifest["selected_samples"] = [path.name for path in sample_paths]
    experiment_manifest["selected_task_keys"] = [f"{task.sample_name}::{task.task_id}" for task in evaluation_tasks]
    write_json(experiment_root / "experiment_manifest.json", experiment_manifest)
    write_json(experiment_root / "build_record.json", build_record)
    write_json(experiment_root / "prepare_record.json", prepare_record)
    python_exec = repo_python_executable()

    preflight_variants: List[Dict[str, Any]] = []
    for run_cfg in planned_runs:
        preflight_variants.append(
            {
                "variant_id": str(run_cfg.get("variant_id") or ""),
                "changed_variable": str(run_cfg.get("changed_variable") or ""),
                "pipeline": str(run_cfg.get("pipeline") or corpus.default_pipeline),
                "architecture": str(run_cfg.get("architecture") or corpus.default_architecture),
                "validator_review_level": str(run_cfg.get("validator_review_level") or "default"),
                "response_scope_variant": str(run_cfg.get("response_scope_variant") or "default"),
                "analysis_hint_variant": str(run_cfg.get("analysis_hint_variant") or "default"),
                "worker_role_prompt_mode": str(run_cfg.get("worker_role_prompt_mode") or "default"),
                "prefer_upx_unpacked": bool(args.prefer_unpacked_upx or run_cfg.get("prefer_upx_unpacked")),
                "checks": validate_run_configuration(
                    corpus_name=corpus_name,
                    sample_paths=sample_paths,
                    manifest=manifest,
                    selected_samples=args.sample,
                    selected_task_ids=args.task,
                    selected_difficulties=args.difficulty_filter,
                    pipeline=str(run_cfg.get("pipeline") or corpus.default_pipeline),
                    architecture=str(run_cfg.get("architecture") or corpus.default_architecture),
                    response_scope_variant=str(run_cfg.get("response_scope_variant") or "default"),
                    analysis_hint_variant=str(run_cfg.get("analysis_hint_variant") or "default"),
                    worker_persona_profile=str(run_cfg.get("worker_persona_profile") or "default"),
                    worker_role_prompt_mode=str(run_cfg.get("worker_role_prompt_mode") or "default"),
                    validator_review_level=str(run_cfg.get("validator_review_level") or "default"),
                    tool_profile=str(run_cfg.get("tool_profile") or "full"),
                    prefer_upx_unpacked=bool(args.prefer_unpacked_upx or run_cfg.get("prefer_upx_unpacked")),
                    ghidra_install_dir=str(args.ghidra_install_dir or ""),
                    ghidra_headless=str(args.ghidra_headless or ""),
                    judge_mode=str(run_cfg.get("judge_mode") or "agent"),
                    explicit_judge_model=str(args.judge_model or "").strip(),
                    forced_model=str(run_cfg.get("force_model") or "").strip(),
                    python_executable=python_exec,
                    bundle_root=bundle_root,
                    require_ready_bundles=bool(args.skip_prepare or prepare_record),
                ),
            }
        )
    preflight_errors = [
        f"{entry['variant_id']}: {message}"
        for entry in preflight_variants
        for message in (entry.get("checks") or {}).get("errors") or []
    ]
    preflight_warnings = [
        f"{entry['variant_id']}: {message}"
        for entry in preflight_variants
        for message in (entry.get("checks") or {}).get("warnings") or []
    ]
    preflight_report = {
        "ok": not preflight_errors,
        "errors": list(dict.fromkeys(preflight_errors)),
        "warnings": list(dict.fromkeys(preflight_warnings)),
        "variants": preflight_variants,
    }
    if not args.skip_build and not bool(build_record.get("ok")):
        preflight_report.setdefault("warnings", []).append(
            "Build step reported failure, but usable binaries for the selected scope were still found. "
            "This run can continue with existing artifacts, but it is not a clean-rebuild validation. "
            "See build_record.json for the failing make step."
        )
    if not args.skip_prepare and not bool(prepare_record.get("ready_for_analysis", True)):
        preflight_report.setdefault("warnings", []).append(
            "Bundle preparation reported issues, but existing bundles were still inspected for readiness. "
            "See prepare_record.json for the regeneration details."
        )
    if not args.skip_visuals:
        missing_visual_modules: List[str] = []
        for module_name in ("matplotlib", "pandas"):
            if not _module_available_in_python(python_exec, module_name):
                missing_visual_modules.append(module_name)
        if missing_visual_modules:
            preflight_report["ok"] = False
            preflight_report.setdefault("errors", []).append(
                "Visualization outputs require the following modules in the sweep interpreter: "
                + ", ".join(missing_visual_modules)
                + ". Install them or rerun with --skip-visuals."
            )
    write_json(experiment_root / "preflight.json", preflight_report)

    # Build a set of (variant_id, replicate_index) pairs already completed in
    # a prior sweep run so that --resume can skip them.
    _completed_keys: set[tuple[str, int]] = set()
    for prior_entry in prior_run_entries:
        _completed_keys.add((
            str(prior_entry.get("variant_id") or ""),
            int(prior_entry.get("replicate_index") or 0),
        ))

    # Upfront cost projection so the researcher can see the planned spend
    # before committing to real API calls.
    total_planned_runs = len(planned_runs) * repetitions
    skipped_runs = len(_completed_keys)
    remaining_runs = total_planned_runs - skipped_runs
    task_count = len(evaluation_tasks)
    agent_judge_calls = remaining_runs * task_count
    projected_budget = project_experiment_budget(
        child_runs=remaining_runs,
        tasks_per_child_run=task_count,
        config=budget_config,
    )
    projected_budget_status = evaluate_projected_experiment_budget(projected_budget, budget_config)
    cost_projection = {
        "total_planned_child_runs": total_planned_runs,
        "already_completed_runs": skipped_runs,
        "remaining_child_runs": remaining_runs,
        "tasks_per_child_run": task_count,
        "estimated_agent_plus_judge_api_calls": agent_judge_calls,
        "budget_projection": projected_budget,
        "budget_projection_status": projected_budget_status,
        "note": "Each sample-task run includes one analysis call path plus one judge call path. Projected cost values are coarse preflight heuristics, not billing-authoritative estimates.",
    }
    write_json(experiment_root / "cost_projection.json", cost_projection)

    import sys as _sys
    print(
        f"\n--- Cost Projection ---\n"
        f"  Planned child runs:        {total_planned_runs}\n"
        f"  Already completed (resume): {skipped_runs}\n"
        f"  Remaining child runs:       {remaining_runs}\n"
        f"  Tasks per child run:        {task_count}\n"
        f"  Total agent+judge API calls: {agent_judge_calls}\n"
        f"  ---\n",
        file=_sys.stderr,
    )

    if projected_budget_status.get("warnings"):
        preflight_report.setdefault("warnings", []).extend(
            [f"budget_projection: {item}" for item in (projected_budget_status.get("warnings") or [])]
        )
        write_json(experiment_root / "preflight.json", preflight_report)

    if not projected_budget_status.get("ok"):
        preflight_report["ok"] = False
        preflight_report.setdefault("errors", []).extend(
            [f"budget_projection: {item}" for item in (projected_budget_status.get("exceeded") or [])]
        )
        write_json(experiment_root / "preflight.json", preflight_report)

    if args.preflight_only:
        print(json.dumps({"experiment_id": experiment_id, "experiment_root": str(experiment_root), "preflight_ok": bool(preflight_report.get("ok")), "cost_projection": cost_projection}, indent=2))
        if not preflight_report.get("ok"):
            raise SystemExit("Preflight validation failed; see preflight.json for details.")
        return
    if not preflight_report.get("ok"):
        raise SystemExit("Preflight validation failed; see preflight.json for details before launching paid runs.")

    experiment_budget_status: Dict[str, Any] = {
        "scope": "experiment",
        "ok": True,
        "exceeded": [],
        "warnings": [],
        "observed": {},
        "limits": budget_config,
        "aborted_early": False,
    }
    all_child_specs: List[Dict[str, Any]] = []
    for run_cfg in planned_runs:
        variant_id = str(run_cfg.get("variant_id") or "variant")
        variant_name = str(run_cfg.get("variant_name") or variant_id)
        comparison_baseline_id = str(run_cfg.get("comparison_baseline_id") or "").strip()
        comparison_baseline_label = str(run_cfg.get("comparison_baseline_label") or "").strip()
        for repetition_index in range(repetitions):
            planned_key = f"{variant_id}::r{repetition_index + 1}"
            catalog_entry = run_entries[run_entry_index[planned_key]]
            if (variant_id, repetition_index + 1) in _completed_keys:
                continue
            label = f"{experiment_id}-{variant_id}-r{repetition_index + 1}"
            cmd = [
                python_exec,
                "Testing/scripts/run_evaluation.py",
                "--corpus",
                corpus_name,
                "--skip-build",
                "--skip-prepare",
                "--pipeline",
                str(run_cfg.get("pipeline") or corpus.default_pipeline),
                "--architecture",
                str(run_cfg.get("architecture") or corpus.default_architecture),
                "--response-scope-variant",
                str(run_cfg.get("response_scope_variant") or "default"),
                "--analysis-hint-variant",
                str(run_cfg.get("analysis_hint_variant") or "default"),
                "--subagent-profile",
                str(run_cfg.get("subagent_profile") or "default"),
                "--worker-persona-profile",
                str(run_cfg.get("worker_persona_profile") or "default"),
                "--worker-role-prompt-mode",
                str(run_cfg.get("worker_role_prompt_mode") or "default"),
                "--validator-review-level",
                str(run_cfg.get("validator_review_level") or "default"),
                "--tool-profile",
                str(run_cfg.get("tool_profile") or "full"),
                "--deep-agent-request-limit",
                request_limit_env_value(deep_agent_request_limit),
                "--model-profile",
                str(run_cfg.get("model_profile") or ""),
                "--label",
                label,
                "--run-id",
                str(catalog_entry.get("run_id") or ""),
                "--run-root",
                str(catalog_entry.get("run_dir") or ""),
                "--experiment-id",
                experiment_id,
                "--variant-name",
                variant_name,
                "--changed-variable",
                str(run_cfg.get("changed_variable") or ""),
                "--comparison-baseline-id",
                comparison_baseline_id,
                "--comparison-baseline-label",
                comparison_baseline_label,
                "--replicate-index",
                str(repetition_index + 1),
                "--replicate-count",
                str(repetitions),
                "--judge-mode",
                str(run_cfg.get("judge_mode") or "agent"),
            ]
            if bool(args.prefer_unpacked_upx or run_cfg.get("prefer_upx_unpacked")):
                cmd.append("--prefer-unpacked-upx")
            if int(args.task_failure_retries or 0) > 0:
                cmd.extend(["--task-failure-retries", str(int(args.task_failure_retries))])
            if int(args.timeout_sec) > 0:
                cmd.extend(["--timeout-sec", str(int(args.timeout_sec))])
            if str(args.ghidra_install_dir or "").strip():
                cmd.extend(["--ghidra-install-dir", str(args.ghidra_install_dir).strip()])
            if str(args.ghidra_headless or "").strip():
                cmd.extend(["--ghidra-headless", str(args.ghidra_headless).strip()])
            if args.judge_model:
                cmd.extend(["--judge-model", args.judge_model])
            if args.enable_budget_guardrails:
                cmd.append("--enable-budget-guardrails")
            force_model = str(run_cfg.get("force_model") or "").strip()
            if force_model:
                cmd.extend(["--force-model", force_model])
            for sample in args.sample:
                cmd.extend(["--sample", sample])
            for task_id in args.task:
                cmd.extend(["--task", task_id])
            for difficulty in args.difficulty_filter:
                cmd.extend(["--difficulty-filter", difficulty])
            if args.enable_budget_guardrails:
                if args.max_run_input_tokens is not None:
                    cmd.extend(["--max-run-input-tokens", str(args.max_run_input_tokens)])
                if args.max_run_output_tokens is not None:
                    cmd.extend(["--max-run-output-tokens", str(args.max_run_output_tokens)])
                if args.max_run_total_tokens is not None:
                    cmd.extend(["--max-run-total-tokens", str(args.max_run_total_tokens)])
                if args.max_run_relative_cost_index is not None:
                    cmd.extend(["--max-run-relative-cost-index", str(args.max_run_relative_cost_index)])
                if args.max_run_estimated_cost_usd is not None:
                    cmd.extend(["--max-run-estimated-cost-usd", str(args.max_run_estimated_cost_usd)])
                if args.hard_max_run_estimated_cost_usd is not None:
                    cmd.extend(["--hard-max-run-estimated-cost-usd", str(args.hard_max_run_estimated_cost_usd)])
            cmd.extend(["--meta", f"model_profile={str(run_cfg.get('model_profile') or '')}"])
            cmd.extend(["--meta", f"experiment_variant_id={variant_id}"])

            child_timeout = int(args.timeout_sec) * max(1, len(evaluation_tasks)) if int(args.timeout_sec) > 0 else None
            display_label = "baseline" if bool(run_cfg.get("is_baseline")) else (
                f"{str(run_cfg.get('changed_variable') or '')}:baseline" if bool(run_cfg.get("is_family_baseline"))
                else f"{str(run_cfg.get('changed_variable') or '')}:{variant_name}"
            )
            all_child_specs.append(
                {
                    "catalog_entry": catalog_entry,
                    "concurrency_group": variant_id,
                    "display_label": display_label,
                    "repetition_index": repetition_index + 1,
                    "cmd": cmd,
                    "cwd": REPO_ROOT,
                    "timeout_sec": child_timeout,
                    "stream_output": not args.quiet_child_output,
                    "stream_prefix": f"[{display_label} r{repetition_index + 1}/{repetitions}] ",
                    "stream_heartbeat_sec": 30,
                    "stream_capture_path": "",
                }
            )

    def _on_launch(spec: Dict[str, Any]) -> None:
        entry = spec["catalog_entry"]
        timeout_value = spec.get("timeout_sec")
        timeout_label = f"{timeout_value}s" if timeout_value is not None else "disabled"
        print(
            f"[sweep] starting {spec['display_label']} replicate {spec['repetition_index']}/{repetitions} "
            f"(timeout={timeout_label})",
            file=sys.stderr,
            flush=True,
        )
        entry.update(
            {
                "status": "running",
                "ok": None,
                "command": list(spec.get("cmd") or []),
                "started_at_epoch": time.time(),
                "finished_at_epoch": None,
            }
        )
        _write_run_catalog(experiment_root, run_entries)

    def _on_complete(spec: Dict[str, Any], completed: Dict[str, Any]) -> bool:
        nonlocal experiment_budget_status
        entry = spec["catalog_entry"]
        entry.update(
            {
                "ok": bool(completed.get("ok")),
                "status": "completed" if bool(completed.get("ok")) else "failed",
                "stdout": str(completed.get("stdout") or ""),
                "stderr": str(completed.get("stderr") or ""),
                "returncode": completed.get("returncode"),
                "error": str(completed.get("error") or "").strip(),
                "finished_at_epoch": time.time(),
            }
        )
        if completed.get("ok"):
            try:
                payload = _parse_completion_payload(entry["stdout"])
                run_dir = Path(str(payload.get("run_dir") or "")).resolve()
                aggregate = read_json(run_dir / "aggregate.json")
                run_manifest = read_json(run_dir / "run_manifest.json")
                entry.update(
                    {
                        "run_id": str(payload.get("run_id") or ""),
                        "run_dir": str(run_dir),
                        "aggregate": aggregate,
                        "run_manifest": run_manifest,
                    }
                )
            except Exception as exc:
                entry["ok"] = False
                entry["status"] = "failed"
                entry["error"] = f"{type(exc).__name__}: {exc}"
        print(
            f"[sweep] finished {entry['display_label']} replicate {spec['repetition_index']}/{repetitions} "
            f"ok={entry.get('ok')}",
            file=sys.stderr,
            flush=True,
        )
        _write_run_catalog(experiment_root, run_entries)
        if entry.get("ok") and isinstance(entry.get("aggregate"), dict):
            successful_records: List[Dict[str, Any]] = []
            for existing in run_entries:
                aggregate = existing.get("aggregate") if isinstance(existing.get("aggregate"), dict) else {}
                successful_records.extend(list(aggregate.get("records") or []))
            experiment_budget_summary = summarize_record_budget(successful_records)
            experiment_budget_status = evaluate_budget_status(experiment_budget_summary, budget_config, scope="experiment")
            experiment_budget_status["aborted_early"] = False
            write_json(experiment_root / "budget_status.json", experiment_budget_status)
            if not experiment_budget_status.get("ok") and bool(budget_config.get("abort_experiment_on_budget_exceeded", True)):
                experiment_budget_status["aborted_early"] = True
                write_json(experiment_root / "budget_status.json", experiment_budget_status)
                return False
        return True

    _execute_child_run_specs(
        all_child_specs,
        max_concurrent=effective_max_concurrent_child_runs,
        max_concurrent_per_group=effective_max_concurrent_repetitions,
        group_key_fn=lambda spec: str(spec.get("concurrency_group") or ""),
        on_launch=_on_launch,
        on_complete=_on_complete,
    )

    _write_run_catalog(experiment_root, run_entries)
    write_json(experiment_root / "budget_status.json", experiment_budget_status)
    materialize_experiment_outputs(
        experiment_root=experiment_root,
        experiment_manifest=experiment_manifest,
        run_entries=run_entries,
        skip_visuals=bool(args.skip_visuals),
    )

    print(
        json.dumps(
            {
                "experiment_id": experiment_id,
                "experiment_root": str(experiment_root),
                "run_count": len(run_entries),
            },
            indent=2,
        )
    )
