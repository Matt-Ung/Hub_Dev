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
from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Callable, Dict, List, Tuple

from .artifacts import prepare_corpus_bundles
from .budgeting import (
    evaluate_budget_status,
    evaluate_projected_experiment_budget,
    resolve_budget_config,
    summarize_record_budget,
    project_experiment_budget,
)
from .building import build_corpus
from .live_progress import start_live_view_server
from .lineage import compute_lineage_id, load_lineage_payload, normalize_run_lineage_payload, refresh_lineage_index_for_run
from .output_comparison import build_task_output_comparisons
from .paths import BUNDLE_ROOT, CONFIG_ROOT, REPO_ROOT, RESULTS_ROOT, build_run_id, ensure_dir, read_json, repo_python_executable, slugify, write_json
from .preflight import _module_available_in_python, validate_run_configuration
from .result_layout import build_experiment_output_layout
from .reporting import aggregate_records
from .significance import build_significance_outputs
from .samples import build_evaluation_tasks, get_corpus_config, list_sample_binaries, load_sample_manifest
from .subprocess_utils import run_command
from .timing import build_timing_outputs
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
    run_id = f"eval-{slugify(corpus_name)}-{slugify(experiment_id)}-{slugify(variant_id)}-r{int(repetition_index)}"
    run_dir = RESULTS_ROOT / "runs" / run_id
    log_path = live_logs_dir / f"{run_id}.log" if live_logs_dir is not None else None
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
        "live_status_path": str(run_dir / "live_status.json"),
        "log_path": str(log_path) if log_path is not None else "",
        "pipeline": str(run_cfg.get("pipeline") or ""),
        "architecture": str(run_cfg.get("architecture") or ""),
        "query_variant": str(run_cfg.get("query_variant") or ""),
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
        "target_tool_hit_rate": _mean_metric(records, "metrics.target_tool_hit_rate"),
        "analysis_duration_sec": _mean_metric(records, "metrics.analysis_duration_sec"),
        "judge_duration_sec": _mean_metric(records, "metrics.judge_duration_sec"),
        "total_duration_sec": _mean_metric(records, "metrics.total_duration_sec"),
        "task_wall_clock_duration_sec": wall_clock_duration,
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
                    "query_variant": str(planned_cfg.get("query_variant") or ""),
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
            "query_variant": ((group.get("run_manifest") or {}).get("query_variant") or ""),
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
        lines.append("")

        lines.append("## Variant Summary")
        lines.append("")
        lines.append("| Variant | Variable | Comparison Baseline | Replicates | Coverage | Mean Score | Score Delta | Success Rate | Scored Rate | Produced Result Rate | Synthetic Judge Rate | Validator Blocked Rate | Worker Failure Rate | Judge Error Rate | Cost Index |")
        lines.append("|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for row in variant_rows:
            lines.append(
                "| {label} | {variable} | {baseline} | {replicates} | {coverage} | {score} | {delta} | {success} | {scored} | {produced} | {synthetic} | {blocked} | {worker_failed} | {judge_error} | {cost} |".format(
                    label=row.get("display_label", ""),
                    variable=row.get("changed_variable", "baseline") or "baseline",
                    baseline=row.get("comparison_baseline_label", "baseline") or "baseline",
                    replicates=f"{row.get('completed_repetitions', 0)}/{row.get('planned_repetitions', 0)}",
                    coverage=row.get("coverage_status", ""),
                    score=row.get("overall_score_mean", ""),
                    delta=row.get("score_delta", ""),
                    success=row.get("task_success_rate", ""),
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

    lines.append("## Drill-Down Artifacts")
    lines.append("")
    lines.append("- Executable/config/task artifact view: `by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/`")
    lines.append("- Charts: `outputs/*.png`")
    lines.append("- Timing tables: `outputs/task_timing_individual.csv`, `outputs/task_timing_summary.csv`, `outputs/task_tag_timing_summary.csv`, and `outputs/variant_timing_summary.csv`")
    lines.append("- Per-task output comparisons: `outputs/task_output_comparisons/index.html`")
    lines.append("- Per-task comparison tables: `outputs/task_output_comparisons/task_variant_summary.csv` and `outputs/task_output_comparisons/all_rows.csv`")
    lines.append("- Statistical significance tables: `significance_overall.csv`, `significance_by_difficulty.csv`, `significance_by_task.csv`, and `variable_significance_summary.csv`")
    lines.append("- Configuration lineage summary: `lineage_summary.csv`")
    lines.append("- Statistical summary note: `significance_report.md`")
    lines.append("")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def materialize_experiment_outputs(
    *,
    experiment_root: Path,
    experiment_manifest: Dict[str, Any],
    run_entries: List[Dict[str, Any]],
    skip_visuals: bool = False,
) -> Dict[str, Any]:
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
        "lineage_summary": [],
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

    lineage_rows: List[Dict[str, Any]] = []
    seen_lineages: set[str] = set()
    for entry in successful_runs:
        run_manifest = entry.get("run_manifest") if isinstance(entry.get("run_manifest"), dict) else {}
        run_dir = Path(str(entry.get("run_dir") or "")).resolve() if entry.get("run_dir") else Path()
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        lineage_id = str(run_manifest.get("config_lineage_id") or "").strip()
        if not lineage_id and run_manifest and run_dir:
            run_manifest["config_lineage_id"] = compute_lineage_id(run_manifest)
            run_manifest["config_lineage_key"] = normalize_run_lineage_payload(run_manifest)
            lineage_id = str(run_manifest.get("config_lineage_id") or "").strip()
            write_json(run_dir / "run_manifest.json", run_manifest)
            if aggregate:
                refresh_lineage_index_for_run(
                    run_dir=run_dir,
                    run_manifest=run_manifest,
                    aggregate=aggregate,
                )
        if not lineage_id or lineage_id in seen_lineages:
            continue
        seen_lineages.add(lineage_id)
        lineage_payload = load_lineage_payload(lineage_id)
        if not lineage_payload:
            continue
        lineage_aggregate = lineage_payload.get("aggregate") if isinstance(lineage_payload.get("aggregate"), dict) else {}
        lineage_key = lineage_payload.get("config_lineage_key") if isinstance(lineage_payload.get("config_lineage_key"), dict) else {}
        lineage_rows.append(
            {
                "config_lineage_id": lineage_id,
                "path": str((RESULTS_ROOT / "lineages" / f"{lineage_id}.json").resolve()),
                "run_count": lineage_payload.get("run_count"),
                "records_count": lineage_payload.get("records_count"),
                "overall_score_mean": lineage_aggregate.get("overall_score_mean"),
                "task_success_rate": lineage_aggregate.get("task_success_rate"),
                "mean_relative_cost_index": lineage_aggregate.get("mean_relative_cost_index"),
                "mean_total_duration_sec": lineage_aggregate.get("mean_total_duration_sec"),
                "mean_task_wall_clock_duration_sec": lineage_aggregate.get("mean_task_wall_clock_duration_sec"),
                "corpus": lineage_key.get("corpus"),
                "pipeline": lineage_key.get("pipeline"),
                "architecture": lineage_key.get("architecture"),
                "query_variant": lineage_key.get("query_variant"),
                "worker_persona_profile": lineage_key.get("worker_persona_profile"),
                "worker_role_prompt_mode": lineage_key.get("worker_role_prompt_mode"),
                "selected_samples": "; ".join(lineage_key.get("selected_samples") or []),
                "selected_tasks": "; ".join(lineage_key.get("selected_tasks") or []),
                "selected_difficulties": "; ".join(lineage_key.get("selected_difficulties") or []),
            }
        )
    _write_rows_csv(experiment_root / "lineage_summary.csv", lineage_rows)
    comparison_payload["lineage_summary"] = lineage_rows
    partial_comparison_payload["lineage_summary"] = lineage_rows
    write_json(experiment_root / "comparison.json", comparison_payload)
    write_json(experiment_root / "partial_comparison.json", partial_comparison_payload)

    partial_outputs_root = ensure_dir(outputs_root / "partial")
    partial_successful_runs = [
        entry for entry in successful_runs
        if str(entry.get("variant_id") or "") in partial_variant_ids
    ]

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
        coverage_note=coverage_note,
    )
    if partial_variant_rows:
        _build_experiment_report(
            experiment_manifest,
            partial_variant_rows,
            partial_task_rows,
            experiment_root / "partial_report.md",
            title="Partial Coverage Report",
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
) -> None:
    concurrency = max(1, int(max_concurrent or 1))
    allow_new_launches = True

    if concurrency <= 1:
        for spec in child_specs:
            if on_launch is not None:
                on_launch(spec)
            completed = _invoke_child_run_spec(spec, runner=runner)
            if on_complete is not None and on_complete(spec, completed) is False:
                break
        return

    future_to_spec: Dict[Any, Dict[str, Any]] = {}
    next_index = 0
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="sweep-child") as executor:
        while next_index < len(child_specs) or future_to_spec:
            while allow_new_launches and next_index < len(child_specs) and len(future_to_spec) < concurrency:
                spec = child_specs[next_index]
                next_index += 1
                if on_launch is not None:
                    on_launch(spec)
                future = executor.submit(_invoke_child_run_spec, spec, runner=runner)
                future_to_spec[future] = spec

            if not future_to_spec:
                break

            completed_futures, _ = wait(list(future_to_spec.keys()), return_when=FIRST_COMPLETED)
            for future in completed_futures:
                spec = future_to_spec.pop(future)
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


def run_experiment_sweep(argv: List[str] | None = None) -> None:
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
    parser = argparse.ArgumentParser(description="Run a baseline + one-variable-at-a-time experiment sweep across the binary analysis corpus.")
    parser.add_argument("--config", default=str(CONFIG_ROOT / "experiment_sweeps.json"))
    parser.add_argument("--corpus", choices=["prototype", "experimental"], default="")
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

    # --resume: reuse an existing experiment directory instead of creating a new one
    resume_path = str(args.resume or "").strip()
    prior_run_entries: List[Dict[str, Any]] = []
    if resume_path:
        resume_dir = Path(resume_path)
        if not resume_dir.is_dir():
            # Treat as experiment_id under RESULTS_ROOT/experiments
            resume_dir = RESULTS_ROOT / "experiments" / resume_path
        if not resume_dir.is_dir():
            raise SystemExit(f"--resume target not found: {resume_path}")
        catalog_path = resume_dir / "run_catalog.json"
        if catalog_path.exists():
            prior_catalog = read_json(catalog_path)
            prior_run_entries = [
                entry for entry in (prior_catalog.get("runs") or [])
                if entry.get("ok") and isinstance(entry.get("aggregate"), dict)
            ]
        experiment_root = resume_dir
    else:
        experiment_root = ensure_dir(RESULTS_ROOT / "experiments" / build_run_id("sweep", corpus_name, args.label))

    experiment_id = experiment_root.name
    outputs_root = ensure_dir(experiment_root / "outputs")
    live_view_dir = ensure_dir(experiment_root / "live_view")
    live_logs_dir = ensure_dir(live_view_dir / "logs")
    live_view_server = None
    live_view_thread = None
    live_view_url = ""

    selected_samples_for_manifest = list(args.sample) or list(manifest.get("sample_order") or [])
    manifest_planned_runs = [
        dict(run_cfg, prefer_upx_unpacked=True) if args.prefer_unpacked_upx else dict(run_cfg)
        for run_cfg in planned_runs
    ]
    experiment_manifest = {
        "experiment_id": experiment_id,
        "config_path": str(Path(args.config).resolve()),
        "corpus": corpus_name,
        "selected_samples": selected_samples_for_manifest,
        "selected_tasks": list(args.task),
        "selected_difficulties": list(args.difficulty_filter),
        "repetitions": repetitions,
        "max_concurrent_repetitions": max(1, int(args.max_concurrent_repetitions or 1)),
        "enable_budget_guardrails": bool(args.enable_budget_guardrails),
        "prefer_upx_unpacked": bool(args.prefer_unpacked_upx),
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
                    experiment_id=experiment_id,
                    corpus_name=corpus_name,
                    run_cfg=effective_run_cfg,
                    repetition_index=repetition_index,
                    planned_repetitions=repetitions,
                    live_logs_dir=live_logs_dir if args.live_view else None,
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
                "query_variant": str(run_cfg.get("query_variant") or "default"),
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
                    query_variant=str(run_cfg.get("query_variant") or "default"),
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
    max_concurrent_repetitions = max(1, int(args.max_concurrent_repetitions or 1))
    for run_cfg in planned_runs:
        variant_id = str(run_cfg.get("variant_id") or "variant")
        variant_name = str(run_cfg.get("variant_name") or variant_id)
        comparison_baseline_id = str(run_cfg.get("comparison_baseline_id") or "").strip()
        comparison_baseline_label = str(run_cfg.get("comparison_baseline_label") or "").strip()
        child_specs: List[Dict[str, Any]] = []
        for repetition_index in range(repetitions):
            planned_key = f"{variant_id}::r{repetition_index + 1}"
            catalog_entry = run_entries[run_entry_index[planned_key]]
            if (variant_id, repetition_index + 1) in _completed_keys:
                continue
            label = f"{experiment_id}-{variant_id}-r{repetition_index + 1}"
            cmd = [
                python_exec,
                "Testing/run_evaluation.py",
                "--corpus",
                corpus_name,
                "--skip-build",
                "--skip-prepare",
                "--pipeline",
                str(run_cfg.get("pipeline") or corpus.default_pipeline),
                "--architecture",
                str(run_cfg.get("architecture") or corpus.default_architecture),
                "--query-variant",
                str(run_cfg.get("query_variant") or "default"),
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
                "--model-profile",
                str(run_cfg.get("model_profile") or ""),
                "--label",
                label,
                "--run-id",
                str(catalog_entry.get("run_id") or ""),
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
            child_specs.append(
                {
                    "catalog_entry": catalog_entry,
                    "display_label": display_label,
                    "repetition_index": repetition_index + 1,
                    "cmd": cmd,
                    "cwd": REPO_ROOT,
                    "timeout_sec": child_timeout,
                    "stream_output": not args.quiet_child_output,
                    "stream_prefix": f"[{display_label} r{repetition_index + 1}/{repetitions}] ",
                    "stream_heartbeat_sec": 30,
                    "stream_capture_path": str(catalog_entry.get("log_path") or "").strip(),
                }
            )
        if not child_specs:
            continue

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
            child_specs,
            max_concurrent=max_concurrent_repetitions,
            on_launch=_on_launch,
            on_complete=_on_complete,
        )
        if experiment_budget_status.get("aborted_early"):
            break

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
