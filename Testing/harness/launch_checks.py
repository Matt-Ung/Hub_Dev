"""
File: launch_checks.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Compute reusable launch-readiness reports for the testing harness.

Summary:
  This module contains the machine-readable checks used by the launch doctor
  and preset preflight paths. It inspects bundle completeness, projected sweep
  scope, Python/module availability, and environment state without starting a
  paid evaluation run.
"""

from __future__ import annotations

import os
import shutil
import sys
import site
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .artifacts import _resolve_java_home, inspect_corpus_bundles
from .budgeting import evaluate_projected_experiment_budget, project_experiment_budget, resolve_budget_config
from .experiment_sweep import _build_run_plan, _load_experiment_config
from .launch_presets import resolve_launch_preset
from .paths import BUNDLE_ROOT, repo_python_executable
from .preflight import _module_available_in_python
from .samples import build_evaluation_tasks, build_planned_evaluation_tasks, list_sample_binaries, load_sample_manifest


def _projection_ceiling_comparison(projection: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    projected_usd = projection.get("projected_estimated_cost_usd")
    projected_relative = projection.get("projected_relative_cost_index")
    usd_limit = config.get("max_experiment_estimated_cost_usd")
    relative_limit = config.get("max_experiment_relative_cost_index")

    def _delta(observed: Any, limit: Any) -> float | None:
        try:
            if observed is None or limit is None:
                return None
            return round(float(observed) - float(limit), 8)
        except Exception:
            return None

    return {
        "projected_estimated_cost_usd": projected_usd,
        "configured_max_experiment_estimated_cost_usd": usd_limit,
        "estimated_cost_delta_usd": _delta(projected_usd, usd_limit),
        "projected_relative_cost_index": projected_relative,
        "configured_max_experiment_relative_cost_index": relative_limit,
        "relative_cost_delta": _delta(projected_relative, relative_limit),
    }


def check_python_modules(python_executable: str, modules: Iterable[str]) -> Dict[str, Any]:
    executable = str(python_executable or "").strip() or sys.executable
    module_results: Dict[str, bool] = {}
    for module_name in modules:
        module_results[str(module_name)] = bool(_module_available_in_python(executable, str(module_name)))
    missing = [name for name, present in module_results.items() if not present]
    return {
        "python_executable": executable,
        "modules": module_results,
        "missing": missing,
        "ok": not missing,
    }


def check_command_available(command_name: str) -> Dict[str, Any]:
    normalized = str(command_name or "").strip()
    resolved = shutil.which(normalized) if normalized else None
    return {
        "command": normalized,
        "path": str(resolved or ""),
        "ok": bool(resolved),
    }


def _expected_sample_names(manifest: Dict[str, Any], selected_samples: Iterable[str], selected_difficulties: Iterable[str]) -> List[str]:
    requested = [str(item).strip() for item in (selected_samples or []) if str(item).strip()]
    if requested:
        return requested
    difficulty_filter = {str(item).strip().lower() for item in (selected_difficulties or []) if str(item).strip()}
    ordered = list(manifest.get("sample_order") or [])
    if not difficulty_filter:
        return ordered
    selected: List[str] = []
    samples = manifest.get("samples") if isinstance(manifest.get("samples"), dict) else {}
    for name in ordered:
        meta = samples.get(name) if isinstance(samples, dict) else {}
        difficulty = str((meta or {}).get("difficulty") or "unknown").strip().lower()
        if difficulty in difficulty_filter:
            selected.append(name)
    return selected


"""
Function: build_bundle_integrity_report
Inputs:
  - corpus_name: logical corpus identifier.
  - selected_samples / selected_task_ids / selected_difficulties: optional
    narrowing filters.
  - bundle_root: optional explicit bundle root override.
Description:
  Compare the selected corpus scope against built binaries and prepared bundle
  directories to determine whether the scope is ready and fresh for analysis.
Outputs:
  Returns a dictionary containing missing binaries, stale or incomplete bundle
  details, task counts, and an overall readiness flag.
Side Effects:
  Reads corpus manifests, build outputs, and bundle directories from disk.
"""
def build_bundle_integrity_report(
    *,
    corpus_name: str,
    selected_samples: Iterable[str] | None = None,
    selected_task_ids: Iterable[str] | None = None,
    selected_difficulties: Iterable[str] | None = None,
    bundle_root: Path | None = None,
) -> Dict[str, Any]:
    manifest = load_sample_manifest(corpus_name)
    expected_names = _expected_sample_names(manifest, selected_samples or [], selected_difficulties or [])
    sample_paths = list_sample_binaries(
        corpus_name,
        selected=selected_samples,
        difficulty_filters=selected_difficulties,
        manifest=manifest,
    )
    present_names = [path.name for path in sample_paths]
    missing_binaries = [name for name in expected_names if name not in set(present_names)]
    tasks = build_evaluation_tasks(
        corpus_name,
        sample_paths,
        manifest=manifest,
        selected_task_ids=selected_task_ids,
        selected_difficulties=selected_difficulties,
    ) if sample_paths else build_planned_evaluation_tasks(
        corpus_name,
        manifest=manifest,
        selected_samples=selected_samples,
        selected_task_ids=selected_task_ids,
        selected_difficulties=selected_difficulties,
    )
    readiness = inspect_corpus_bundles(corpus_name, sample_paths, output_root=bundle_root or (BUNDLE_ROOT / corpus_name))
    missing_required_by_sample: Dict[str, List[str]] = {}
    stale_by_sample: Dict[str, List[str]] = {}
    for item in readiness.get("results") or []:
        missing_required = [str(entry) for entry in (item.get("missing_required") or []) if str(entry)]
        if missing_required:
            missing_required_by_sample[str(item.get("sample") or "")] = missing_required
        stale_reasons = [str(entry) for entry in (item.get("stale_reasons") or []) if str(entry)]
        if stale_reasons:
            stale_by_sample[str(item.get("sample") or "")] = stale_reasons
    return {
        "corpus": corpus_name,
        "bundle_root": str((bundle_root or (BUNDLE_ROOT / corpus_name)).resolve()),
        "expected_samples": expected_names,
        "present_samples": present_names,
        "missing_binaries": missing_binaries,
        "sample_count": len(sample_paths),
        "task_count": len(tasks),
        "bundle_readiness": readiness,
        "missing_required_by_sample": missing_required_by_sample,
        "stale_by_sample": stale_by_sample,
        "ok": (not missing_binaries) and bool(readiness.get("ready_for_analysis")) and bool(readiness.get("fresh_for_analysis")),
    }


def build_sweep_projection_report(
    *,
    corpus_name: str,
    selected_samples: Iterable[str] | None = None,
    selected_task_ids: Iterable[str] | None = None,
    selected_difficulties: Iterable[str] | None = None,
    variable_filters: Iterable[str] | None = None,
    repetitions_override: int | None = None,
    budget_config: Dict[str, Any] | None = None,
    config_path: str = "",
) -> Dict[str, Any]:
    manifest = load_sample_manifest(corpus_name)
    sample_paths = list_sample_binaries(
        corpus_name,
        selected=selected_samples,
        difficulty_filters=selected_difficulties,
        manifest=manifest,
    )
    tasks = build_evaluation_tasks(
        corpus_name,
        sample_paths,
        manifest=manifest,
        selected_task_ids=selected_task_ids,
        selected_difficulties=selected_difficulties,
    ) if sample_paths else build_planned_evaluation_tasks(
        corpus_name,
        manifest=manifest,
        selected_samples=selected_samples,
        selected_task_ids=selected_task_ids,
        selected_difficulties=selected_difficulties,
    )
    sweep_config = _load_experiment_config(Path(config_path).resolve()) if str(config_path or "").strip() else _load_experiment_config()
    _, planned_runs, repetitions = _build_run_plan(
        sweep_config,
        variable_filters=list(variable_filters or []),
        corpus_override=corpus_name,
    )
    if repetitions_override is not None and int(repetitions_override) > 0:
        repetitions = int(repetitions_override)
    child_runs = len(planned_runs) * repetitions
    resolved_budget = budget_config or resolve_budget_config()
    projection = project_experiment_budget(
        child_runs=child_runs,
        tasks_per_child_run=len(tasks),
        config=resolved_budget,
    )
    projection_status = evaluate_projected_experiment_budget(projection, resolved_budget)
    return {
        "corpus": corpus_name,
        "planned_configuration_groups": len(planned_runs),
        "repetitions": repetitions,
        "child_runs": child_runs,
        "tasks_per_child_run": len(tasks),
        "estimated_agent_plus_judge_api_calls": child_runs * len(tasks),
        "budget_config": resolved_budget,
        "projection": projection,
        "projection_status": projection_status,
        "ceiling_comparison": _projection_ceiling_comparison(projection, resolved_budget),
        "ok": bool(projection_status.get("ok")),
        "has_warnings": bool(projection_status.get("warnings")),
    }


def build_launch_preset_projection_report(
    preset_name: str,
    *,
    budget_config: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    preset = resolve_launch_preset(preset_name)
    runner = str(preset.get("runner") or "sweep").strip().lower()
    if runner != "sweep":
        return {
            "preset": preset_name,
            "runner": runner,
            "ok": False,
            "error": f"Budget projection is only implemented for sweep presets; got {runner!r}.",
        }
    return {
        "preset": preset_name,
        "runner": runner,
        **build_sweep_projection_report(
            corpus_name=str(preset.get("corpus") or "experimental"),
            selected_samples=list(preset.get("samples") or []),
            selected_task_ids=list(preset.get("tasks") or []),
            selected_difficulties=list(preset.get("difficulty_filters") or []),
            variable_filters=list(preset.get("variables") or []),
            repetitions_override=int(preset.get("repetitions") or 0),
            config_path=str(preset.get("config") or ""),
            budget_config=budget_config
            or resolve_budget_config(
                max_run_input_tokens=preset.get("max_run_input_tokens"),
                max_run_output_tokens=preset.get("max_run_output_tokens"),
                max_run_total_tokens=preset.get("max_run_total_tokens"),
                max_run_relative_cost_index=preset.get("max_run_relative_cost_index"),
                max_run_estimated_cost_usd=preset.get("max_run_estimated_cost_usd"),
                hard_max_run_estimated_cost_usd=preset.get("hard_max_run_estimated_cost_usd"),
                max_experiment_relative_cost_index=preset.get("max_experiment_relative_cost_index"),
                max_experiment_estimated_cost_usd=preset.get("max_experiment_estimated_cost_usd"),
                hard_max_experiment_estimated_cost_usd=preset.get("hard_max_experiment_estimated_cost_usd"),
            ),
        ),
    }


"""
Function: resolve_launch_environment
Inputs:
  - explicit_judge_model: optional judge-model override that should take
    precedence over `EVAL_JUDGE_MODEL`.
Description:
  Snapshot the effective Python, model, and Ghidra-related environment that
  the harness will use when launching real runs.
Outputs:
  Returns a dictionary describing interpreter selection, model settings, and
  environment-variable availability.
Side Effects:
  Reads environment variables and local Python installation metadata.
"""
def resolve_launch_environment(explicit_judge_model: str = "") -> Dict[str, Any]:
    current_python = sys.executable
    preferred_python = repo_python_executable()
    sys_prefix = sys.prefix
    sys_base_prefix = getattr(sys, "base_prefix", sys.prefix)
    in_virtualenv = Path(sys_prefix).resolve() != Path(sys_base_prefix).resolve()
    agent_model = str(os.environ.get("OPENAI_MODEL_ID") or "").strip()
    judge_model = str(explicit_judge_model or os.environ.get("EVAL_JUDGE_MODEL") or "").strip()
    forced_model = str(os.environ.get("DEEP_FORCE_MODEL_ID") or "").strip()
    effective_agent_model = forced_model or agent_model
    detected_java_home = _resolve_java_home()
    return {
        "current_python": current_python,
        "preferred_python": preferred_python,
        "same_interpreter": Path(current_python).resolve() == Path(preferred_python).resolve(),
        "sys_prefix": sys_prefix,
        "sys_base_prefix": sys_base_prefix,
        "in_virtualenv": in_virtualenv,
        "virtual_env_envvar": str(os.environ.get("VIRTUAL_ENV") or "").strip(),
        "site_packages": list(site.getsitepackages()),
        "user_site": str(site.getusersitepackages()),
        "openai_api_key_set": bool(os.environ.get("OPENAI_API_KEY")),
        "agent_model": agent_model,
        "forced_model": forced_model,
        "effective_agent_model": effective_agent_model,
        "judge_model": judge_model,
        "judge_model_set": bool(judge_model),
        "judge_model_distinct": bool(judge_model) and (judge_model != effective_agent_model),
        "ghidra_install_dir_set": bool(str(os.environ.get("GHIDRA_INSTALL_DIR") or "").strip()),
        "ghidra_headless_set": bool(str(os.environ.get("GHIDRA_HEADLESS") or "").strip()),
        "ghidra_java_home_set": bool(str(os.environ.get("GHIDRA_JAVA_HOME") or "").strip()),
        "detected_java_home": detected_java_home,
        "ghidra_java_home_available": bool(detected_java_home),
    }
