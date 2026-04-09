"""
File: recovery_rebuild.py
Author: Matt-Ung
Last Updated: 2026-04-04
Purpose:
  Rebuild a repaired experiment view by folding recovery-run outputs back into
  the original sweep results and regenerating experiment-level artifacts.

Summary:
  This module reads an existing experiment directory plus one or more recovery
  sessions, overlays recovered sample-task records onto the original child-run
  results, materializes synthetic repaired run directories, and regenerates the
  sweep summaries/graphs through the same aggregation pipeline used by the
  primary experiment runner.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .experiment_sweep import materialize_experiment_outputs
from .paths import RESULTS_ROOT, ensure_dir, read_json, slugify, write_json
from .reporting import aggregate_records, write_markdown_report, write_summary_csv
from .result_layout import build_run_output_layout
from .result_store import resolve_catalog_run_dir, resolve_task_case_dir
from .samples import normalize_sample_task_key


def _safe_json(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            return read_json(path)
    except Exception:
        return {}
    return {}


def _now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _coerce_session_payload(session_dir: Path) -> Dict[str, Any]:
    path = session_dir / "recovery_session.json" if session_dir.is_dir() else session_dir
    payload = _safe_json(path)
    if payload:
        payload["_session_path"] = str(path.resolve())
        payload["_session_dir"] = str(path.parent.resolve())
        payload["_session_id"] = str(payload.get("session_id") or path.parent.name)
    return payload


def _session_sort_key(payload: Dict[str, Any]) -> Tuple[str, str]:
    started_at = str(payload.get("started_at") or "")
    session_id = str(payload.get("_session_id") or payload.get("session_id") or "")
    return (started_at, session_id)


def _resolve_recovery_session_paths(experiment_root: Path, session_refs: Iterable[str]) -> List[Path]:
    refs = [str(item).strip() for item in session_refs if str(item).strip()]
    if refs:
        resolved: List[Path] = []
        for ref in refs:
            candidate = Path(ref).expanduser()
            if candidate.is_dir():
                session_file = candidate / "recovery_session.json"
                if not session_file.exists():
                    raise FileNotFoundError(f"Recovery session file not found under {candidate}")
                resolved.append(session_file)
                continue
            if candidate.is_file():
                resolved.append(candidate)
                continue
            session_file = experiment_root / "recovery_attempts" / ref / "recovery_session.json"
            if not session_file.exists():
                raise FileNotFoundError(f"Recovery session {ref!r} was not found under {experiment_root / 'recovery_attempts'}")
            resolved.append(session_file)
        return resolved

    attempts_root = experiment_root / "recovery_attempts"
    if not attempts_root.exists():
        return []
    session_files = sorted(
        path for path in attempts_root.glob("*/recovery_session.json")
        if path.is_file()
    )
    return session_files


def _load_recovery_sessions(experiment_root: Path, session_refs: Iterable[str]) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    for session_path in _resolve_recovery_session_paths(experiment_root, session_refs):
        payload = _coerce_session_payload(session_path)
        if not payload:
            continue
        summary = dict(payload.get("summary") or {})
        completed = int(summary.get("completed_recovery_runs") or 0)
        inspections = list(payload.get("inspections") or [])
        if completed <= 0 and not any(
            isinstance(item.get("recovery_result"), dict) and item.get("recovery_result", {}).get("ok")
            for item in inspections
            if isinstance(item, dict)
        ):
            continue
        payloads.append(payload)
    payloads.sort(key=_session_sort_key)
    return payloads


def _sample_dir_for_task(run_dir: Path, sample_task_id: str) -> Path:
    sample_name, task_id = str(sample_task_id or "").split("::", 1)
    return resolve_task_case_dir(run_dir, sample_name, task_id)


def _record_key(record: Dict[str, Any]) -> str:
    return normalize_sample_task_key(str(record.get("sample_task_id") or ""))


def _record_map(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    mapping: Dict[str, Dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        key = _record_key(record)
        if key:
            mapping[key] = dict(record)
    return mapping


def _load_run_artifacts(run_dir: Path) -> Dict[str, Any]:
    return {
        "run_manifest": _safe_json(run_dir / "run_manifest.json"),
        "aggregate": _safe_json(run_dir / "aggregate.json"),
        "live_status": _safe_json(run_dir / "live_status.json"),
        "budget_status": _safe_json(run_dir / "budget_status.json"),
    }


def _collect_recovery_replacements(session_payloads: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    replacements: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for session in session_payloads:
        session_id = str(session.get("_session_id") or session.get("session_id") or "")
        for inspection in (session.get("inspections") or []):
            if not isinstance(inspection, dict):
                continue
            recovery_result = inspection.get("recovery_result") if isinstance(inspection.get("recovery_result"), dict) else {}
            if not recovery_result or not recovery_result.get("ok"):
                continue
            recovery_run_dir = Path(str(recovery_result.get("recovery_run_dir") or "")).expanduser()
            if not recovery_run_dir.exists():
                continue
            recovery_artifacts = _load_run_artifacts(recovery_run_dir)
            recovery_records = list((recovery_artifacts.get("aggregate") or {}).get("records") or [])
            if not recovery_records:
                continue
            record_map = _record_map(recovery_records)
            if not record_map:
                continue
            original_run_id = str(inspection.get("run_id") or "").strip()
            if not original_run_id:
                continue
            full_scope_retry = any(not str(task.get("sample_task_id") or "").strip() for task in (inspection.get("retryable_tasks") or []))
            target_ids = sorted(record_map) if full_scope_retry else [
                normalize_sample_task_key(str(task.get("sample_task_id") or ""))
                for task in (inspection.get("retryable_tasks") or [])
                if str(task.get("sample_task_id") or "").strip()
            ]
            bucket = replacements.setdefault(original_run_id, {})
            for sample_task_id in target_ids:
                if sample_task_id not in record_map:
                    continue
                bucket[sample_task_id] = {
                    "sample_task_id": sample_task_id,
                    "session_id": session_id,
                    "session_dir": str(session.get("_session_dir") or ""),
                    "inspection": dict(inspection),
                    "recovery_run_dir": str(recovery_run_dir.resolve()),
                    "record": dict(record_map[sample_task_id]),
                    "recovery_run_manifest": dict(recovery_artifacts.get("run_manifest") or {}),
                    "recovery_live_status": dict(recovery_artifacts.get("live_status") or {}),
                    "recovery_budget_status": dict(recovery_artifacts.get("budget_status") or {}),
                }
    return replacements


def _copy_json_if_exists(source: Path, dest: Path) -> bool:
    if not source.exists():
        return False
    ensure_dir(dest.parent)
    shutil.copy2(source, dest)
    return True


def _write_json_payload(path: Path, payload: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _merged_task_order(original_records: List[Dict[str, Any]], merged_records: Dict[str, Dict[str, Any]]) -> List[str]:
    ordered_keys: List[str] = []
    seen: set[str] = set()
    for record in original_records:
        key = _record_key(record)
        if key and key not in seen:
            seen.add(key)
            ordered_keys.append(key)
    for key in sorted(merged_records):
        if key not in seen:
            seen.add(key)
            ordered_keys.append(key)
    return ordered_keys


def _synthesize_live_status(
    *,
    original_live_status: Dict[str, Any],
    merged_records: List[Dict[str, Any]],
    expected_task_count: int,
    session_ids: List[str],
) -> Dict[str, Any]:
    original_tasks = [
        dict(item)
        for item in (original_live_status.get("tasks") or [])
        if isinstance(item, dict)
    ]
    tasks_by_id: Dict[str, Dict[str, Any]] = {}
    ordered_ids: List[str] = []
    for task in original_tasks:
        sample_name = str(task.get("sample") or "").strip()
        task_id = str(task.get("task_id") or "").strip()
        sample_task_id = normalize_sample_task_key(str(task.get("sample_task_id") or ""))
        if not sample_task_id and sample_name and task_id:
            sample_task_id = normalize_sample_task_key(f"{sample_name}::{task_id}")
        if not sample_task_id:
            continue
        tasks_by_id[sample_task_id] = task
        ordered_ids.append(sample_task_id)

    for record in merged_records:
        key = _record_key(record)
        if not key:
            continue
        metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
        entry = dict(tasks_by_id.get(key) or {})
        entry.update(
            {
                "sample": str(record.get("sample") or entry.get("sample") or ""),
                "task_id": str(record.get("task_id") or entry.get("task_id") or ""),
                "task_name": str(record.get("task_name") or entry.get("task_name") or entry.get("task_id") or ""),
                "sample_task_id": key,
                "status": str(metrics.get("analysis_status") or entry.get("status") or "completed"),
                "judge_status": str(metrics.get("judge_status") or entry.get("judge_status") or ""),
            }
        )
        tasks_by_id[key] = entry
        if key not in ordered_ids:
            ordered_ids.append(key)

    task_rows = [tasks_by_id[key] for key in ordered_ids if key in tasks_by_id]
    completed_count = len(merged_records)
    status = "completed" if expected_task_count <= 0 or completed_count >= expected_task_count else "partial"
    message = (
        f"Rebuilt from recovery session(s): {', '.join(session_ids)}."
        if session_ids
        else "Rebuilt from original experiment records."
    )
    return {
        "status": status,
        "stage": "complete",
        "current_phase": "recovery_rebuilt",
        "current_sample": "",
        "current_task_id": "",
        "last_message": message,
        "tasks": task_rows,
    }


def _emit_sample_artifacts(
    *,
    output_run_dir: Path,
    final_records: List[Dict[str, Any]],
    source_dirs: Dict[str, Path],
) -> None:
    for record in final_records:
        sample_task_id = _record_key(record)
        if not sample_task_id:
            continue
        output_sample_dir = resolve_task_case_dir(
            output_run_dir,
            str(record.get("sample") or sample_task_id.split("::", 1)[0]),
            str(record.get("task_id") or "default_analysis"),
        )
        ensure_dir(output_sample_dir)
        source_dir = source_dirs.get(sample_task_id)
        copied_record = _copy_json_if_exists(source_dir / "record.json", output_sample_dir / "record.json") if source_dir else False
        copied_agent = _copy_json_if_exists(source_dir / "agent_result.json", output_sample_dir / "agent_result.json") if source_dir else False
        copied_judge = _copy_json_if_exists(source_dir / "judge_result.json", output_sample_dir / "judge_result.json") if source_dir else False
        if not copied_record:
            _write_json_payload(output_sample_dir / "record.json", record)
        if not copied_agent:
            _write_json_payload(output_sample_dir / "agent_result.json", dict(record.get("agent_result") or {}))
        if not copied_judge:
            _write_json_payload(output_sample_dir / "judge_result.json", dict(record.get("judge_result") or {}))


def _materialize_repaired_run(
    *,
    output_run_dir: Path,
    original_entry: Dict[str, Any],
    original_run_dir: Path | None,
    replacement_map: Dict[str, Dict[str, Any]],
    repaired_experiment_id: str,
    session_ids: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    original_run_dir = original_run_dir.resolve() if original_run_dir and original_run_dir.exists() else None
    original_artifacts = _load_run_artifacts(original_run_dir) if original_run_dir is not None else {
        "run_manifest": {},
        "aggregate": {},
        "live_status": {},
        "budget_status": {},
    }
    original_manifest = dict(original_entry.get("run_manifest") or original_artifacts.get("run_manifest") or {})
    original_aggregate = dict(original_entry.get("aggregate") or original_artifacts.get("aggregate") or {})
    original_records = list(original_aggregate.get("records") or [])
    original_record_map = _record_map(original_records)
    merged_record_map = dict(original_record_map)
    source_dirs: Dict[str, Path] = {}
    if original_run_dir is not None:
        for key in original_record_map:
            source_dirs[key] = _sample_dir_for_task(original_run_dir, key)

    applied_replacements: List[Dict[str, Any]] = []
    for sample_task_id, replacement in sorted(replacement_map.items()):
        key = normalize_sample_task_key(sample_task_id)
        record = dict(replacement.get("record") or {})
        if not key or not record:
            continue
        merged_record_map[key] = record
        source_dirs[key] = _sample_dir_for_task(Path(str(replacement.get("recovery_run_dir") or "")), key)
        applied_replacements.append(
            {
                "sample_task_id": key,
                "session_id": str(replacement.get("session_id") or ""),
                "recovery_run_dir": str(replacement.get("recovery_run_dir") or ""),
            }
        )

    order = _merged_task_order(original_records, merged_record_map)
    final_records = [merged_record_map[key] for key in order if key in merged_record_map]

    repaired_run_manifest = dict(original_manifest)
    repaired_run_manifest["experiment_id"] = repaired_experiment_id
    repaired_run_manifest["run_id"] = str(original_entry.get("run_id") or repaired_run_manifest.get("run_id") or output_run_dir.name)
    metadata = dict(repaired_run_manifest.get("metadata") or {})
    metadata["recovery_rebuilt"] = "true"
    metadata["repaired_from_experiment_id"] = str(original_manifest.get("experiment_id") or "")
    if session_ids:
        metadata["recovery_session_ids"] = ",".join(session_ids)
    repaired_run_manifest["metadata"] = metadata
    if repaired_run_manifest.get("expected_task_count") is None:
        repaired_run_manifest["expected_task_count"] = int(original_aggregate.get("expected_task_count") or len(final_records) or 0)

    repaired_aggregate = aggregate_records(repaired_run_manifest, final_records)
    repaired_aggregate["terminal_status"] = "completed" if (
        int(repaired_aggregate.get("expected_task_count") or 0) <= 0
        or int(repaired_aggregate.get("sample_count") or 0) >= int(repaired_aggregate.get("expected_task_count") or 0)
    ) else str(original_aggregate.get("terminal_status") or "partial")
    repaired_aggregate["budget_limit_reached"] = False
    repaired_aggregate["budget_warning_triggered"] = False
    repaired_aggregate["recovery_rebuilt"] = True
    repaired_aggregate["applied_replacements"] = applied_replacements
    if original_manifest.get("config_lineage_id"):
        repaired_aggregate["config_lineage_id"] = original_manifest.get("config_lineage_id")

    ensure_dir(output_run_dir)
    write_json(output_run_dir / "run_manifest.json", repaired_run_manifest)
    write_json(output_run_dir / "aggregate.json", repaired_aggregate)
    write_json(output_run_dir / "budget_status.json", dict(original_artifacts.get("budget_status") or {}))

    _emit_sample_artifacts(
        output_run_dir=output_run_dir,
        final_records=final_records,
        source_dirs=source_dirs,
    )
    live_status = _synthesize_live_status(
        original_live_status=dict(original_artifacts.get("live_status") or {}),
        merged_records=final_records,
        expected_task_count=int(repaired_aggregate.get("expected_task_count") or 0),
        session_ids=session_ids,
    )
    write_json(output_run_dir / "live_status.json", live_status)
    write_summary_csv(output_run_dir / "summary.csv", final_records, repaired_run_manifest)
    write_markdown_report(output_run_dir / "report.md", repaired_aggregate)
    result_layout = build_run_output_layout(
        run_dir=output_run_dir,
        run_manifest=repaired_run_manifest,
        aggregate=repaired_aggregate,
    )
    write_json(output_run_dir / "result_layout.json", result_layout)

    repaired_entry = dict(original_entry)
    repaired_entry.update(
        {
            "run_id": repaired_run_manifest.get("run_id"),
            "run_dir": str(output_run_dir.resolve()),
            "run_manifest": repaired_run_manifest,
            "aggregate": repaired_aggregate,
            "ok": bool(final_records),
            "status": "completed" if final_records else str(original_entry.get("status") or "failed"),
            "error": "" if final_records else str(original_entry.get("error") or ""),
            "recovery_rebuilt": True,
            "recovery_replaced_task_count": len(applied_replacements),
            "recovery_session_ids": session_ids,
        }
    )
    return repaired_entry, {
        "run_id": str(repaired_entry.get("run_id") or ""),
        "display_label": str(repaired_entry.get("display_label") or repaired_entry.get("run_id") or ""),
        "output_run_dir": str(output_run_dir.resolve()),
        "applied_replacements": applied_replacements,
        "record_count": len(final_records),
        "expected_task_count": int(repaired_aggregate.get("expected_task_count") or 0),
        "task_completion_rate": repaired_aggregate.get("task_completion_rate"),
    }


def plan_rebuilt_experiment(
    experiment_root: Path,
    *,
    recovery_sessions: Iterable[str] = (),
    output_root: Path | None = None,
    output_experiment_id: str = "",
) -> Dict[str, Any]:
    experiment_root = experiment_root.expanduser().resolve()
    experiment_manifest = _safe_json(experiment_root / "experiment_manifest.json")
    run_catalog = _safe_json(experiment_root / "run_catalog.json")
    if not experiment_manifest:
        raise FileNotFoundError(f"experiment_manifest.json not found under {experiment_root}")
    if not run_catalog:
        raise FileNotFoundError(f"run_catalog.json not found under {experiment_root}")

    sessions = _load_recovery_sessions(experiment_root, recovery_sessions)
    if not sessions:
        raise ValueError(f"No completed recovery sessions were found under {experiment_root / 'recovery_attempts'}")

    replacements = _collect_recovery_replacements(sessions)
    session_ids = [str(payload.get("_session_id") or payload.get("session_id") or "") for payload in sessions]
    resolved_output_root = (output_root or (RESULTS_ROOT / "experiments")).expanduser().resolve()
    suffix = slugify(session_ids[-1] if len(session_ids) == 1 else f"recovery-merge-{_now_tag()}") or _now_tag()
    repaired_experiment_id = str(output_experiment_id or f"{experiment_root.name}-repaired-{suffix}").strip()
    output_dir = resolved_output_root / repaired_experiment_id

    planned_runs = list(experiment_manifest.get("planned_runs") or [])
    planned_by_variant = {str(item.get("variant_id") or ""): item for item in planned_runs if isinstance(item, dict)}
    runs = [dict(item) for item in (run_catalog.get("runs") or []) if isinstance(item, dict)]
    run_plans: List[Dict[str, Any]] = []
    total_replacements = 0
    for entry in runs:
        run_id = str(entry.get("run_id") or "").strip()
        variant_id = str(entry.get("variant_id") or "").strip()
        run_dir = resolve_catalog_run_dir(experiment_root, entry) if (entry.get("run_dir") or entry.get("run_path")) else None
        applied = dict(replacements.get(run_id) or {})
        total_replacements += len(applied)
        run_plans.append(
            {
                "run_id": run_id,
                "variant_id": variant_id,
                "display_label": str(entry.get("display_label") or run_id),
                "planned_cfg": dict(planned_by_variant.get(variant_id) or {}),
                "original_run_dir": str(run_dir.resolve()) if run_dir and run_dir.exists() else "",
                "replaced_task_ids": sorted(applied),
                "replacement_count": len(applied),
            }
        )

    return {
        "source_experiment_root": str(experiment_root),
        "source_experiment_id": str(experiment_manifest.get("experiment_id") or experiment_root.name),
        "output_root": str(resolved_output_root),
        "output_experiment_id": repaired_experiment_id,
        "output_experiment_root": str(output_dir),
        "recovery_session_ids": session_ids,
        "recovery_session_paths": [str(payload.get("_session_path") or "") for payload in sessions],
        "session_count": len(sessions),
        "run_count": len(runs),
        "replaced_task_count": total_replacements,
        "run_plans": run_plans,
    }


def rebuild_experiment_from_recovery(
    experiment_root: Path,
    *,
    recovery_sessions: Iterable[str] = (),
    output_root: Path | None = None,
    output_experiment_id: str = "",
    overwrite: bool = False,
    skip_visuals: bool = False,
    plan_only: bool = False,
) -> Dict[str, Any]:
    experiment_root = experiment_root.expanduser().resolve()
    experiment_manifest = _safe_json(experiment_root / "experiment_manifest.json")
    run_catalog = _safe_json(experiment_root / "run_catalog.json")
    plan = plan_rebuilt_experiment(
        experiment_root,
        recovery_sessions=recovery_sessions,
        output_root=output_root,
        output_experiment_id=output_experiment_id,
    )
    if plan_only:
        plan["plan_only"] = True
        return plan

    output_dir = Path(str(plan.get("output_experiment_root") or "")).resolve()
    if output_dir.exists():
        if not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing repaired experiment at {output_dir}")
        shutil.rmtree(output_dir)
    ensure_dir(output_dir)

    sessions = _load_recovery_sessions(experiment_root, recovery_sessions)
    replacements = _collect_recovery_replacements(sessions)
    session_ids = [str(payload.get("_session_id") or payload.get("session_id") or "") for payload in sessions]

    repaired_experiment_id = str(plan.get("output_experiment_id") or output_dir.name)
    repaired_manifest = dict(experiment_manifest)
    repaired_manifest["experiment_id"] = repaired_experiment_id
    repaired_manifest["source_experiment_id"] = str(experiment_manifest.get("experiment_id") or experiment_root.name)
    repaired_manifest["source_experiment_root"] = str(experiment_root)
    repaired_manifest["recovery_session_ids"] = session_ids
    repaired_manifest["recovery_session_paths"] = [str(payload.get("_session_path") or "") for payload in sessions]
    repaired_manifest["recovery_rebuilt"] = True
    write_json(output_dir / "experiment_manifest.json", repaired_manifest)

    repaired_run_entries: List[Dict[str, Any]] = []
    rebuild_runs_root = ensure_dir(output_dir / "rebuilt_runs")
    run_summaries: List[Dict[str, Any]] = []
    for entry in (run_catalog.get("runs") or []):
        if not isinstance(entry, dict):
            continue
        run_id = str(entry.get("run_id") or "").strip()
        run_dir = resolve_catalog_run_dir(experiment_root, entry) if (entry.get("run_dir") or entry.get("run_path")) else None
        output_run_dir = rebuild_runs_root / (slugify(run_id) or f"run-{len(repaired_run_entries) + 1:03d}")
        repaired_entry, run_summary = _materialize_repaired_run(
            output_run_dir=output_run_dir,
            original_entry=entry,
            original_run_dir=run_dir,
            replacement_map=dict(replacements.get(run_id) or {}),
            repaired_experiment_id=repaired_experiment_id,
            session_ids=session_ids,
        )
        repaired_run_entries.append(repaired_entry)
        run_summaries.append(run_summary)

    outputs_summary = materialize_experiment_outputs(
        experiment_root=output_dir,
        experiment_manifest=repaired_manifest,
        run_entries=repaired_run_entries,
        skip_visuals=bool(skip_visuals),
    )

    rebuild_manifest = {
        "source_experiment_id": str(experiment_manifest.get("experiment_id") or experiment_root.name),
        "source_experiment_root": str(experiment_root),
        "repaired_experiment_id": repaired_experiment_id,
        "repaired_experiment_root": str(output_dir),
        "recovery_session_ids": session_ids,
        "recovery_session_paths": [str(payload.get("_session_path") or "") for payload in sessions],
        "session_count": len(sessions),
        "replaced_task_count": int(plan.get("replaced_task_count") or 0),
        "runs": run_summaries,
        "outputs_summary": outputs_summary,
        "rebuilt_at": datetime.now().isoformat(timespec="seconds"),
    }
    write_json(output_dir / "recovery_rebuild_manifest.json", rebuild_manifest)
    return rebuild_manifest
