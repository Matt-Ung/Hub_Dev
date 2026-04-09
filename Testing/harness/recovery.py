"""
File: recovery.py
Author: Matt-Ung
Last Updated: 2026-04-02
Purpose:
  Recover failed or incomplete harness tasks by launching exact-task retry runs.

Summary:
  This module inspects an existing single-run directory or sweep experiment
  directory, classifies each expected sample-task case using the canonical
  artifacts already written by the harness, and launches narrowly scoped retry
  runs that re-execute only the selected failed or unfinished tasks. Recovery
  runs always write to distinct run directories and are indexed from a recovery
  session manifest stored under the original run/experiment tree.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .paths import REPO_ROOT, ensure_dir, read_json, repo_python_executable, slugify, write_json
from .result_store import iter_record_paths as iter_case_record_paths, resolve_catalog_run_dir, resolve_task_case_dir
from .samples import (
    build_evaluation_tasks,
    list_sample_binaries,
    load_sample_manifest,
    normalize_sample_task_key,
    sample_task_key,
)
from .subprocess_utils import run_command


FAILURE_ANALYSIS_STATUSES = {
    "analysis_error",
    "worker_assignment_failed",
    "no_result",
}

VALIDATOR_BLOCKED_STATUSES = {
    "validator_blocked",
}

RETRYABLE_POLICIES: Dict[str, set[str]] = {
    "failed_only": {"failed_analysis", "failed_judge"},
    "non_completed": {
        "failed_analysis",
        "failed_judge",
        "incomplete",
        "interrupted",
        "skipped_budget",
        "missing_artifacts",
        "missing_run_artifacts",
    },
    "non_completed_including_validator_blocked": {
        "failed_analysis",
        "failed_judge",
        "validator_blocked",
        "incomplete",
        "interrupted",
        "skipped_budget",
        "missing_artifacts",
        "missing_run_artifacts",
    },
}


def _safe_json(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            return read_json(path)
    except Exception:
        return {}
    return {}


def _now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _canonical_sample_task_id(sample_name: str, task_id: str) -> str:
    return sample_task_key(sample_name, task_id)


def _normalize_sample_task_id(value: str) -> str:
    return normalize_sample_task_key(str(value or ""))


def _task_dir_for_sample_task(run_dir: Path, sample_name: str, task_id: str) -> Path:
    return resolve_task_case_dir(run_dir, sample_name, task_id)


def _iter_record_paths(run_dir: Path) -> List[Path]:
    return list(iter_case_record_paths(run_dir))


def _fallback_run_manifest(
    run_dir: Path,
    run_entry: Dict[str, Any],
    experiment_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    if not run_entry and not experiment_manifest:
        return {}
    return {
        "run_id": str(run_entry.get("run_id") or run_dir.name),
        "corpus": str(experiment_manifest.get("corpus") or run_entry.get("corpus") or ""),
        "pipeline": str(run_entry.get("pipeline") or ""),
        "architecture": str(run_entry.get("architecture") or ""),
        "response_scope_variant": str(run_entry.get("response_scope_variant") or "default"),
        "analysis_hint_variant": str(run_entry.get("analysis_hint_variant") or "default"),
        "validator_review_level": str(run_entry.get("validator_review_level") or "default"),
        "tool_profile": str(run_entry.get("tool_profile") or "full"),
        "worker_persona_profile": str(run_entry.get("worker_persona_profile") or "default"),
        "worker_role_prompt_mode": str(run_entry.get("worker_role_prompt_mode") or "default"),
        "subagent_profile": str(run_entry.get("subagent_profile") or "default"),
        "model_profile": str(run_entry.get("model_profile") or ""),
        "force_model": str(run_entry.get("force_model") or ""),
        "judge_mode": str(run_entry.get("judge_mode") or "agent"),
        "judge_model": str(run_entry.get("judge_model") or ""),
        "label": str(run_entry.get("display_label") or run_dir.name),
        "experiment_id": str(experiment_manifest.get("experiment_id") or run_entry.get("experiment_id") or ""),
        "variant_name": str(run_entry.get("variant_name") or ""),
        "changed_variable": str(run_entry.get("changed_variable") or ""),
        "comparison_baseline_id": str(run_entry.get("comparison_baseline_id") or ""),
        "comparison_baseline_label": str(run_entry.get("comparison_baseline_label") or ""),
        "replicate_index": int(run_entry.get("replicate_index") or 1),
        "replicate_count": int(experiment_manifest.get("repetitions") or run_entry.get("planned_repetitions") or 1),
        "metadata": {},
        "selected_samples": list(experiment_manifest.get("selected_samples") or []),
        "selected_tasks": list(experiment_manifest.get("selected_tasks") or []),
        "selected_task_keys": list(experiment_manifest.get("selected_task_keys") or []),
        "selected_difficulties": list(experiment_manifest.get("selected_difficulties") or []),
        "enable_budget_guardrails": False,
        "budget_config": {},
    }


def _load_run_manifest(
    run_dir: Path,
    *,
    run_entry: Dict[str, Any],
    experiment_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    run_manifest = _safe_json(run_dir / "run_manifest.json")
    if run_manifest:
        return run_manifest
    return _fallback_run_manifest(run_dir, run_entry, experiment_manifest)


def _expected_tasks_from_manifest(run_manifest: Dict[str, Any]) -> List[Dict[str, str]]:
    corpus_name = str(run_manifest.get("corpus") or "").strip()
    if not corpus_name:
        return []
    manifest = load_sample_manifest(corpus_name)
    selected_task_keys = [str(item).strip() for item in (run_manifest.get("selected_task_keys") or []) if str(item).strip()]
    selected_samples = [str(item).strip() for item in (run_manifest.get("selected_samples") or []) if str(item).strip()]
    if not selected_samples and selected_task_keys:
        selected_stems = {str(item).split("::", 1)[0].strip() for item in selected_task_keys if "::" in str(item)}
        selected_samples = [
            name
            for name in (manifest.get("sample_order") or [])
            if Path(str(name)).stem in selected_stems
        ]
    sample_paths = list_sample_binaries(
        corpus_name,
        selected=selected_samples,
        difficulty_filters=list(run_manifest.get("selected_difficulties") or []),
        manifest=manifest,
    )
    tasks = build_evaluation_tasks(
        corpus_name,
        sample_paths,
        manifest=manifest,
        selected_task_ids=list(run_manifest.get("selected_tasks") or []),
        selected_task_keys=selected_task_keys,
        selected_difficulties=list(run_manifest.get("selected_difficulties") or []),
    )
    return [
        {
            "sample": task.sample_name,
            "task_id": task.task_id,
            "task_name": task.task_name,
            "sample_task_id": _canonical_sample_task_id(task.sample_name, task.task_id),
            "source": "manifest",
        }
        for task in tasks
    ]


def _expected_tasks_from_live_status(live_status: Dict[str, Any]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for entry in (live_status.get("tasks") or []):
        sample_name = str(entry.get("sample") or "").strip()
        task_id = str(entry.get("task_id") or "").strip()
        if not sample_name or not task_id:
            continue
        rows.append(
            {
                "sample": sample_name,
                "task_id": task_id,
                "task_name": str(entry.get("task_name") or task_id).strip() or task_id,
                "sample_task_id": _canonical_sample_task_id(sample_name, task_id),
                "source": "live_status",
            }
        )
    return rows


def _expected_tasks_from_records(run_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for record_path in _iter_record_paths(run_dir):
        record = _safe_json(record_path)
        sample_name = str(record.get("sample") or "").strip()
        task_id = str(record.get("task_id") or "").strip()
        if not sample_name or not task_id:
            continue
        rows.append(
            {
                "sample": sample_name,
                "task_id": task_id,
                "task_name": str(record.get("task_name") or task_id).strip() or task_id,
                "sample_task_id": _canonical_sample_task_id(sample_name, task_id),
                "source": "record",
            }
        )
    return rows


def _resolve_expected_tasks(run_dir: Path, run_manifest: Dict[str, Any], live_status: Dict[str, Any]) -> List[Dict[str, str]]:
    ordered: List[Dict[str, str]] = []
    seen: set[str] = set()
    for source_rows in (
        _expected_tasks_from_manifest(run_manifest),
        _expected_tasks_from_live_status(live_status),
        _expected_tasks_from_records(run_dir),
    ):
        for row in source_rows:
            key = str(row.get("sample_task_id") or "").strip()
            if not key or key in seen:
                continue
            seen.add(key)
            ordered.append(row)
    return ordered


def _task_entry_map(live_status: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    mapping: Dict[str, Dict[str, Any]] = {}
    for entry in (live_status.get("tasks") or []):
        sample_name = str(entry.get("sample") or "").strip()
        task_id = str(entry.get("task_id") or "").strip()
        raw_id = str(entry.get("sample_task_id") or "").strip()
        keys = {
            _normalize_sample_task_id(raw_id),
            _canonical_sample_task_id(sample_name, task_id),
        }
        for key in keys:
            if key:
                mapping[key] = dict(entry)
    return mapping


def _retryable_for_policy(classification: str, retry_policy: str) -> bool:
    allowed = RETRYABLE_POLICIES.get(retry_policy) or RETRYABLE_POLICIES["non_completed"]
    return classification in allowed


def _classify_task(
    *,
    task_spec: Dict[str, str],
    task_entry: Dict[str, Any],
    record: Dict[str, Any],
    agent_payload: Dict[str, Any],
    judge_payload: Dict[str, Any],
    run_manifest: Dict[str, Any],
    run_live_status: str,
) -> Tuple[str, str]:
    task_status = str(task_entry.get("status") or "").strip().lower()
    metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
    analysis_status = str(metrics.get("analysis_status") or agent_payload.get("status") or task_status or "").strip().lower()
    judge_status = str(metrics.get("judge_status") or judge_payload.get("status") or task_entry.get("judge_status") or "").strip().lower()
    failure_reason = str(metrics.get("failure_reason") or agent_payload.get("failure_reason") or agent_payload.get("error") or judge_payload.get("error") or "").strip()
    judge_mode = str(run_manifest.get("judge_mode") or "agent").strip().lower() or "agent"
    if record:
        if analysis_status in VALIDATOR_BLOCKED_STATUSES or judge_status in VALIDATOR_BLOCKED_STATUSES:
            return "validator_blocked", failure_reason or analysis_status or judge_status or "validator_blocked"
        if analysis_status in FAILURE_ANALYSIS_STATUSES:
            return "failed_analysis", failure_reason or analysis_status
        if judge_status == "judge_error":
            return "failed_judge", failure_reason or "judge_error"
        if judge_mode == "agent" and not judge_payload and judge_status in {"", "not_run"}:
            return "missing_artifacts", "record.json exists but judge_result.json is missing"
        return "completed", analysis_status or "completed"

    if task_status in VALIDATOR_BLOCKED_STATUSES or judge_status in VALIDATOR_BLOCKED_STATUSES:
        return "validator_blocked", failure_reason or task_status or judge_status or "validator_blocked"
    if task_status in FAILURE_ANALYSIS_STATUSES or task_status.startswith("failed"):
        return "failed_analysis", failure_reason or task_status
    if judge_status == "judge_error":
        return "failed_judge", failure_reason or "judge_error"
    if task_status.startswith("not_run_budget_exceeded"):
        return "skipped_budget", task_status
    if task_status == "running":
        if run_live_status == "running":
            return "active", "task is still marked running in live_status.json"
        return "interrupted", "task was marked running but no canonical record was written"
    if task_status in {"pending", "not started", "not_started", ""}:
        if run_live_status == "running":
            return "active", "run is still active"
        return "incomplete", task_status or "no record.json found"
    return "missing_artifacts", task_status or "no canonical record.json found"


def inspect_run_recovery(
    run_dir: Path,
    *,
    run_entry: Dict[str, Any] | None = None,
    experiment_manifest: Dict[str, Any] | None = None,
    retry_policy: str = "non_completed",
) -> Dict[str, Any]:
    run_dir = run_dir.resolve()
    entry = dict(run_entry or {})
    experiment_meta = dict(experiment_manifest or {})
    run_manifest = _load_run_manifest(run_dir, run_entry=entry, experiment_manifest=experiment_meta)
    live_status = _safe_json(run_dir / "live_status.json")
    aggregate = _safe_json(run_dir / "aggregate.json")
    live_status_text = str(live_status.get("status") or aggregate.get("terminal_status") or entry.get("status") or "unknown").strip().lower()
    task_entries = _task_entry_map(live_status)
    expected_tasks = _resolve_expected_tasks(run_dir, run_manifest, live_status)
    tasks: List[Dict[str, Any]] = []
    for spec in expected_tasks:
        sample_name = str(spec.get("sample") or "").strip()
        task_id = str(spec.get("task_id") or "").strip()
        sample_task_id = str(spec.get("sample_task_id") or "").strip()
        sample_dir = _task_dir_for_sample_task(run_dir, sample_name, task_id)
        record_path = sample_dir / "record.json"
        agent_path = sample_dir / "agent_result.json"
        judge_path = sample_dir / "judge_result.json"
        record = _safe_json(record_path)
        agent_payload = _safe_json(agent_path)
        judge_payload = _safe_json(judge_path)
        task_entry = dict(task_entries.get(sample_task_id) or {})
        classification, reason = _classify_task(
            task_spec=spec,
            task_entry=task_entry,
            record=record,
            agent_payload=agent_payload,
            judge_payload=judge_payload,
            run_manifest=run_manifest,
            run_live_status=live_status_text,
        )
        metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
        tasks.append(
            {
                "sample": sample_name,
                "task_id": task_id,
                "task_name": str(spec.get("task_name") or task_id).strip() or task_id,
                "sample_task_id": sample_task_id,
                "classification": classification,
                "reason": reason,
                "retryable": _retryable_for_policy(classification, retry_policy),
                "analysis_status": str(metrics.get("analysis_status") or agent_payload.get("status") or task_entry.get("status") or "").strip(),
                "judge_status": str(metrics.get("judge_status") or judge_payload.get("status") or task_entry.get("judge_status") or "").strip(),
                "score": metrics.get("overall_score_0_to_100"),
                "record_path": str(record_path) if record_path.exists() else "",
                "agent_result_path": str(agent_path) if agent_path.exists() else "",
                "judge_result_path": str(judge_path) if judge_path.exists() else "",
                "source": str(spec.get("source") or ""),
            }
        )

    if not tasks and run_manifest:
        tasks = [
            {
                "sample": "",
                "task_id": "",
                "task_name": "",
                "sample_task_id": "",
                "classification": "missing_run_artifacts",
                "reason": "Unable to resolve per-task artifacts; retrying the original run scope is the safest fallback.",
                "retryable": _retryable_for_policy("missing_run_artifacts", retry_policy),
                "analysis_status": "",
                "judge_status": "",
                "score": None,
                "record_path": "",
                "agent_result_path": "",
                "judge_result_path": "",
                "source": "fallback",
            }
        ]

    counts: Dict[str, int] = {}
    for task in tasks:
        classification = str(task.get("classification") or "unknown")
        counts[classification] = counts.get(classification, 0) + 1

    retryable_tasks = [task for task in tasks if bool(task.get("retryable"))]
    return {
        "run_id": str(run_manifest.get("run_id") or entry.get("run_id") or run_dir.name),
        "run_dir": str(run_dir),
        "display_label": str(entry.get("display_label") or run_manifest.get("label") or run_dir.name),
        "run_status": live_status_text,
        "run_manifest": run_manifest,
        "aggregate": aggregate,
        "live_status": live_status,
        "tasks": tasks,
        "task_counts": counts,
        "retryable_tasks": retryable_tasks,
        "retryable_task_count": len(retryable_tasks),
    }


def _append_flag(argv: List[str], flag: str, value: Any) -> None:
    if value is None:
        return
    text = str(value).strip() if isinstance(value, str) else str(value)
    if not text:
        return
    argv.extend([flag, text])


def _parse_completion_payload(stdout: str) -> Dict[str, Any]:
    marker = "EVAL_RUN_RESULT_JSON::"
    for line in reversed(str(stdout or "").splitlines()):
        if line.startswith(marker):
            return json.loads(line[len(marker):].strip())
    raise ValueError("run_evaluation.py did not emit the EVAL_RUN_RESULT_JSON marker")


def _recovery_run_id(original_run_id: str, session_id: str) -> str:
    return f"{slugify(original_run_id)}-recovery-{slugify(session_id)}"


def build_recovery_command(
    inspection: Dict[str, Any],
    *,
    session_id: str,
    session_dir: Path,
    task_failure_retries: int = 0,
) -> Dict[str, Any]:
    run_manifest = dict(inspection.get("run_manifest") or {})
    retry_tasks = list(inspection.get("retryable_tasks") or [])
    original_run_id = str(inspection.get("run_id") or run_manifest.get("run_id") or "run").strip() or "run"
    recovery_run_id = _recovery_run_id(original_run_id, session_id)
    recovery_run_dir = ensure_dir(session_dir / "runs" / recovery_run_id)
    retry_exact_keys = [str(task.get("sample_task_id") or "").strip() for task in retry_tasks if str(task.get("sample_task_id") or "").strip()]
    retry_samples = list(dict.fromkeys(str(task.get("sample") or "").strip() for task in retry_tasks if str(task.get("sample") or "").strip()))

    command: List[str] = [
        repo_python_executable(),
        "Testing/scripts/run_evaluation.py",
        "--corpus",
        str(run_manifest.get("corpus") or "experimental"),
        "--run-id",
        recovery_run_id,
        "--run-root",
        str(recovery_run_dir),
        "--label",
        f"recovery-{original_run_id}",
        "--pipeline",
        str(run_manifest.get("pipeline") or ""),
        "--architecture",
        str(run_manifest.get("architecture") or ""),
        "--response-scope-variant",
        str(run_manifest.get("response_scope_variant") or "default"),
        "--analysis-hint-variant",
        str(run_manifest.get("analysis_hint_variant") or "default"),
        "--subagent-profile",
        str(run_manifest.get("subagent_profile") or "default"),
        "--worker-persona-profile",
        str(run_manifest.get("worker_persona_profile") or "default"),
        "--worker-role-prompt-mode",
        str(run_manifest.get("worker_role_prompt_mode") or "default"),
        "--validator-review-level",
        str(run_manifest.get("validator_review_level") or "default"),
        "--tool-profile",
        str(run_manifest.get("tool_profile") or "full"),
        *([] if not bool(run_manifest.get("prefer_upx_unpacked")) else ["--prefer-unpacked-upx"]),
        "--task-failure-retries",
        str(max(0, int(task_failure_retries if task_failure_retries > 0 else int(run_manifest.get("task_failure_retries") or 0)))),
        "--model-profile",
        str(run_manifest.get("model_profile") or ""),
        "--judge-mode",
        str(run_manifest.get("judge_mode") or "agent"),
        "--skip-build",
        "--skip-prepare",
    ]
    if str(run_manifest.get("experiment_id") or "").strip():
        command.extend(["--experiment-id", str(run_manifest.get("experiment_id") or "").strip()])
    if str(run_manifest.get("variant_name") or "").strip():
        command.extend(["--variant-name", str(run_manifest.get("variant_name") or "").strip()])
    if str(run_manifest.get("changed_variable") or "").strip():
        command.extend(["--changed-variable", str(run_manifest.get("changed_variable") or "").strip()])
    if str(run_manifest.get("comparison_baseline_id") or "").strip():
        command.extend(["--comparison-baseline-id", str(run_manifest.get("comparison_baseline_id") or "").strip()])
    if str(run_manifest.get("comparison_baseline_label") or "").strip():
        command.extend(["--comparison-baseline-label", str(run_manifest.get("comparison_baseline_label") or "").strip()])
    if int(run_manifest.get("replicate_index") or 0) > 0:
        command.extend(["--replicate-index", str(int(run_manifest.get("replicate_index") or 1))])
    if int(run_manifest.get("replicate_count") or 0) > 0:
        command.extend(["--replicate-count", str(int(run_manifest.get("replicate_count") or 1))])
    if str(run_manifest.get("judge_model") or "").strip():
        command.extend(["--judge-model", str(run_manifest.get("judge_model") or "").strip()])
    if str(run_manifest.get("force_model") or "").strip():
        command.extend(["--force-model", str(run_manifest.get("force_model") or "").strip()])
    if bool(run_manifest.get("enable_budget_guardrails")) or bool(((run_manifest.get("budget_config") or {}) if isinstance(run_manifest.get("budget_config"), dict) else {}).get("budget_guardrails_enabled")):
        command.append("--enable-budget-guardrails")
        budget_config = dict(run_manifest.get("budget_config") or {})
        for key, flag in (
            ("max_run_input_tokens", "--max-run-input-tokens"),
            ("max_run_output_tokens", "--max-run-output-tokens"),
            ("max_run_total_tokens", "--max-run-total-tokens"),
            ("max_run_relative_cost_index", "--max-run-relative-cost-index"),
            ("max_run_estimated_cost_usd", "--max-run-estimated-cost-usd"),
            ("hard_max_run_estimated_cost_usd", "--hard-max-run-estimated-cost-usd"),
        ):
            if budget_config.get(key) is not None:
                _append_flag(command, flag, budget_config.get(key))
    for sample in retry_samples:
        command.extend(["--sample", sample])
    for task_key in retry_exact_keys:
        command.extend(["--sample-task-key", task_key])

    metadata = dict(run_manifest.get("metadata") or {})
    for key, value in metadata.items():
        if str(key).strip():
            command.extend(["--meta", f"{str(key).strip()}={str(value).strip()}"])
    command.extend(["--meta", f"recovery_of={original_run_id}"])
    command.extend(["--meta", f"recovery_session={session_id}"])

    return {
        "recovery_run_id": recovery_run_id,
        "recovery_run_dir": str(recovery_run_dir),
        "retry_samples": retry_samples,
        "retry_exact_keys": retry_exact_keys,
        "command": command,
    }


def _target_scope(target_path: Path) -> Tuple[str, List[Tuple[Path, Dict[str, Any], Dict[str, Any]]]]:
    target = target_path.resolve()
    if (target / "run_catalog.json").exists():
        experiment_manifest = _safe_json(target / "experiment_manifest.json")
        catalog = _safe_json(target / "run_catalog.json")
        runs: List[Tuple[Path, Dict[str, Any], Dict[str, Any]]] = []
        for entry in (catalog.get("runs") or []):
            if not isinstance(entry, dict):
                continue
            run_dir = resolve_catalog_run_dir(target, entry)
            runs.append((run_dir, dict(entry), experiment_manifest))
        return "experiment", runs
    if (target / "run_manifest.json").exists():
        return "run", [(target, {}, {})]
    raise ValueError(f"Recovery target must be a sweep experiment directory or a single run directory: {target}")


def plan_recovery(
    target_path: Path,
    *,
    retry_policy: str = "non_completed",
) -> Dict[str, Any]:
    normalized_policy = str(retry_policy or "non_completed").strip().lower() or "non_completed"
    if normalized_policy not in RETRYABLE_POLICIES:
        raise ValueError(f"Unsupported retry_policy {retry_policy!r}. Available: {', '.join(sorted(RETRYABLE_POLICIES))}")
    scope_type, scoped_runs = _target_scope(target_path)
    inspections: List[Dict[str, Any]] = []
    total_retryable = 0
    for run_dir, run_entry, experiment_manifest in scoped_runs:
        inspection = inspect_run_recovery(
            run_dir,
            run_entry=run_entry,
            experiment_manifest=experiment_manifest,
            retry_policy=normalized_policy,
        )
        if inspection.get("retryable_task_count", 0) > 0:
            inspections.append(inspection)
            total_retryable += int(inspection.get("retryable_task_count") or 0)
    return {
        "target_path": str(target_path.resolve()),
        "scope_type": scope_type,
        "retry_policy": normalized_policy,
        "runs_examined": len(scoped_runs),
        "runs_with_retryable_tasks": len(inspections),
        "retryable_task_count": total_retryable,
        "inspections": inspections,
    }


def execute_recovery_plan(
    target_path: Path,
    *,
    retry_policy: str = "non_completed",
    plan_only: bool = False,
    quiet_child_output: bool = False,
    timeout_sec: int = 0,
    task_failure_retries: int = 0,
    max_concurrent_recovery_runs: int = 1,
) -> Dict[str, Any]:
    plan = plan_recovery(target_path, retry_policy=retry_policy)
    target = Path(str(plan.get("target_path") or target_path)).resolve()
    session_id = f"recovery-{_now_tag()}"
    session_dir = ensure_dir(target / "recovery_attempts" / session_id)
    logs_dir = ensure_dir(session_dir / "logs")
    plan["session_id"] = session_id
    plan["session_dir"] = str(session_dir)
    plan["plan_only"] = bool(plan_only)
    plan["started_at"] = datetime.now().isoformat(timespec="seconds")
    plan["max_concurrent_recovery_runs"] = max(1, int(max_concurrent_recovery_runs or 1))
    write_json(session_dir / "recovery_session.json", plan)

    launched = 0
    completed = 0
    failed = 0
    for inspection in plan.get("inspections") or []:
        command_payload = build_recovery_command(
            inspection,
            session_id=session_id,
            session_dir=session_dir,
            task_failure_retries=max(0, int(task_failure_retries or 0)),
        )
        inspection["recovery_command"] = command_payload
        if plan_only:
            continue
        launched += 1

    if not plan_only and launched > 0:
        session_lock = threading.Lock()

        def _execute_single_recovery(inspection: Dict[str, Any]) -> Dict[str, Any]:
            command_payload = dict(inspection.get("recovery_command") or {})
            recovery_run_id = str(command_payload.get("recovery_run_id") or "")
            capture_path = logs_dir / f"{recovery_run_id}.log"
            completed_payload = run_command(
                list(command_payload.get("command") or []),
                cwd=REPO_ROOT,
                timeout_sec=int(timeout_sec or 0) or None,
                stream_output=not quiet_child_output,
                stream_prefix=f"[recovery:{inspection.get('display_label')}] ",
                stream_heartbeat_sec=30,
                stream_capture_path=capture_path,
            )
            recovery_result: Dict[str, Any] = {
                "ok": bool(completed_payload.get("ok")),
                "returncode": completed_payload.get("returncode"),
                "error": str(completed_payload.get("error") or ""),
                "log_path": str(capture_path),
                "stdout_tail": "\n".join(str(completed_payload.get("stdout") or "").splitlines()[-20:]),
            }
            if completed_payload.get("ok"):
                try:
                    payload = _parse_completion_payload(str(completed_payload.get("stdout") or ""))
                    recovery_run_dir = Path(str(payload.get("run_dir") or "")).expanduser().resolve()
                    recovery_result.update(
                        {
                            "completion_payload": payload,
                            "recovery_run_dir": str(recovery_run_dir),
                            "aggregate_path": str(recovery_run_dir / "aggregate.json"),
                        }
                    )
                except Exception as exc:
                    recovery_result["ok"] = False
                    recovery_result["error"] = f"{type(exc).__name__}: {exc}"
            return {"inspection": inspection, "recovery_result": recovery_result}

        inspections = list(plan.get("inspections") or [])
        max_workers = min(max(1, int(max_concurrent_recovery_runs or 1)), len(inspections))
        if max_workers <= 1:
            for inspection in inspections:
                result_payload = _execute_single_recovery(inspection)
                recovery_result = dict(result_payload.get("recovery_result") or {})
                if recovery_result.get("ok"):
                    completed += 1
                else:
                    failed += 1
                inspection["recovery_result"] = recovery_result
                write_json(session_dir / "recovery_session.json", plan)
        else:
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="recovery-runner") as executor:
                futures = {executor.submit(_execute_single_recovery, inspection): inspection for inspection in inspections}
                for future in as_completed(futures):
                    result_payload = future.result()
                    inspection = result_payload.get("inspection") or {}
                    recovery_result = dict(result_payload.get("recovery_result") or {})
                    if recovery_result.get("ok"):
                        completed += 1
                    else:
                        failed += 1
                    with session_lock:
                        inspection["recovery_result"] = recovery_result
                        write_json(session_dir / "recovery_session.json", plan)

    plan["finished_at"] = datetime.now().isoformat(timespec="seconds")
    plan["summary"] = {
        "runs_examined": int(plan.get("runs_examined") or 0),
        "runs_with_retryable_tasks": int(plan.get("runs_with_retryable_tasks") or 0),
        "retryable_task_count": int(plan.get("retryable_task_count") or 0),
        "launched_recovery_runs": launched,
        "completed_recovery_runs": completed,
        "failed_recovery_runs": failed,
    }
    write_json(session_dir / "recovery_session.json", plan)
    return plan
