"""
File: result_layout.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Write lightweight indexes for canonical run and experiment case artifacts.

Summary:
  Earlier harness revisions mirrored every task record into a second
  `by_executable/` tree. That made raw outputs harder to reason about because
  the same case artifacts effectively lived in two places. The canonical layout
  is now the run-local `cases/<sample>/<task>/` tree, and this module only
  emits flat case indexes that point at those canonical files.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List

from .paths import ensure_dir, write_json
from .result_store import resolve_catalog_run_dir, resolve_task_case_dir, run_log_path, task_log_path, task_cases_root


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
        writer.writerows(rows)


def _row_from_record(
    *,
    run_dir: Path,
    run_entry: Dict[str, Any],
    record: Dict[str, Any],
    experiment_id: str = "",
) -> Dict[str, Any]:
    sample_name = str(record.get("sample") or "").strip()
    task_id = str(record.get("task_id") or "").strip() or "default_analysis"
    case_dir = resolve_task_case_dir(run_dir, sample_name, task_id)
    return {
        "experiment_id": str(experiment_id or run_entry.get("experiment_id") or ""),
        "run_id": str(run_entry.get("run_id") or ""),
        "run_dir": str(run_dir.resolve()),
        "variant_id": str(run_entry.get("variant_id") or ""),
        "variant_name": str(run_entry.get("variant_name") or ""),
        "display_label": str(run_entry.get("display_label") or ""),
        "changed_variable": str(run_entry.get("changed_variable") or ""),
        "replicate_index": int(run_entry.get("replicate_index") or 1),
        "config_lineage_id": str(run_entry.get("config_lineage_id") or ""),
        "sample": sample_name,
        "task_id": task_id,
        "task_name": str(record.get("task_name") or task_id),
        "sample_task_id": str(record.get("sample_task_id") or ""),
        "analysis_status": str((record.get("metrics") or {}).get("analysis_status") or ""),
        "judge_status": str((record.get("metrics") or {}).get("judge_status") or ""),
        "overall_score_0_to_100": (record.get("metrics") or {}).get("overall_score_0_to_100"),
        "case_dir": str(case_dir.resolve()) if case_dir.exists() else str(case_dir),
        "record_path": str((case_dir / "record.json").resolve()) if (case_dir / "record.json").exists() else str(case_dir / "record.json"),
        "agent_result_path": str((case_dir / "agent_result.json").resolve()) if (case_dir / "agent_result.json").exists() else str(case_dir / "agent_result.json"),
        "judge_result_path": str((case_dir / "judge_result.json").resolve()) if (case_dir / "judge_result.json").exists() else str(case_dir / "judge_result.json"),
        "task_log_path": str(task_log_path(run_dir, sample_name, task_id)),
        "run_log_path": str(run_log_path(run_dir)),
    }


def build_run_output_layout(
    *,
    run_dir: Path,
    run_manifest: Dict[str, Any],
    aggregate: Dict[str, Any],
) -> Dict[str, Any]:
    rows = [
        _row_from_record(run_dir=run_dir, run_entry=run_manifest, record=record)
        for record in list(aggregate.get("records") or [])
        if isinstance(record, dict)
    ]
    write_json(run_dir / "case_index.json", {"schema_version": "result_layout_v2", "scope": "run", "rows": rows})
    _write_rows_csv(run_dir / "case_index.csv", rows)
    return {
        "schema_version": "result_layout_v2",
        "scope": "run",
        "run_id": str(run_manifest.get("run_id") or ""),
        "run_dir": str(run_dir.resolve()),
        "cases_root": str(task_cases_root(run_dir).resolve()),
        "case_index_path": str((run_dir / "case_index.json").resolve()),
        "row_count": len(rows),
    }


def build_experiment_output_layout(
    *,
    experiment_root: Path,
    experiment_id: str,
    successful_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for entry in successful_entries:
        run_dir = resolve_catalog_run_dir(experiment_root, entry)
        if not run_dir:
            continue
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        for record in list(aggregate.get("records") or []):
            if not isinstance(record, dict):
                continue
            rows.append(
                _row_from_record(
                    run_dir=run_dir,
                    run_entry=entry,
                    record=record,
                    experiment_id=experiment_id,
                )
            )
    write_json(
        experiment_root / "case_index.json",
        {"schema_version": "result_layout_v2", "scope": "experiment", "experiment_id": experiment_id, "rows": rows},
    )
    _write_rows_csv(experiment_root / "case_index.csv", rows)
    return {
        "schema_version": "result_layout_v2",
        "scope": "experiment",
        "experiment_id": experiment_id,
        "case_index_path": str((experiment_root / "case_index.json").resolve()),
        "row_count": len(rows),
    }
