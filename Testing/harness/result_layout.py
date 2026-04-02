"""
File: result_layout.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Build inspection-oriented filesystem mirrors for run and experiment outputs.

Summary:
  This module creates the additive browsing layouts under `by_executable/`
  and related experiment folders. The canonical machine-readable records still
  live under `samples/`; this code exists to make manual comparison and
  artifact navigation easier without changing the underlying source-of-truth.
"""

from __future__ import annotations

import csv
import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .lineage import lineage_paths
from .paths import ensure_dir, read_json, slugify, write_json
from .reporting import aggregate_records


def _sample_folder_name(sample_name: str) -> str:
    """
    Function: _sample_folder_name
    Inputs:
      - sample_name: executable file name from the canonical record set.
    Description:
      Normalize the sample name into the stable top-level folder name used by
      the inspection-oriented layout.
    Outputs:
      Returns the normalized sample folder name.
    Side Effects:
      None.
    """
    name = str(sample_name or "").strip()
    return name or "unknown_sample"


def _task_folder_name(task_id: str) -> str:
    """
    Function: _task_folder_name
    Inputs:
      - task_id: manifest task identifier for one evaluation task.
    Description:
      Convert the task identifier into a filesystem-safe folder name for the
      browsing layout.
    Outputs:
      Returns the slugified task folder name.
    Side Effects:
      None.
    """
    text = str(task_id or "").strip()
    return slugify(text) or "default_analysis"


def _task_sample_slug(sample_name: str, task_id: str) -> str:
    return f"{Path(str(sample_name or '')).stem}__{str(task_id or 'default_analysis').strip() or 'default_analysis'}"


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


def _copy_if_exists(source: Path, dest: Path) -> None:
    if source.exists():
        ensure_dir(dest.parent)
        shutil.copy2(source, dest)


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except Exception:
        return None


def _without_records(aggregate: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in dict(aggregate or {}).items() if key != "records"}


def _judge_scorecard(judge_result: Dict[str, Any] | None) -> Dict[str, Any]:
    judge = judge_result if isinstance(judge_result, dict) else {}
    dimension_scores = judge.get("dimension_scores") if isinstance(judge.get("dimension_scores"), dict) else {}
    dimension_labels = judge.get("dimension_score_labels") if isinstance(judge.get("dimension_score_labels"), dict) else {}
    dimensions: Dict[str, Any] = {}
    for name in sorted(set(list(dimension_scores.keys()) + list(dimension_labels.keys()))):
        dimensions[str(name)] = {
            "score": dimension_scores.get(name),
            "label": dimension_labels.get(name),
        }
    return {
        "status": str(judge.get("status") or ""),
        "pass": bool(judge.get("pass")),
        "overall_score_0_to_100": judge.get("overall_score_0_to_100"),
        "raw_total_score": judge.get("raw_total_score"),
        "raw_total_max": judge.get("raw_total_max"),
        "confidence_0_to_1": judge.get("confidence_0_to_1"),
        "rubric_version": str(judge.get("rubric_version") or ""),
        "dimensions": dimensions,
    }


def _judge_reasoning_markdown(judge_result: Dict[str, Any] | None) -> str:
    judge = judge_result if isinstance(judge_result, dict) else {}

    def _section(title: str, values: Iterable[Any]) -> List[str]:
        items = [str(item).strip() for item in values if str(item).strip()]
        if not items:
            return []
        lines = [f"## {title}", ""]
        for item in items:
            lines.append(f"- {item}")
        lines.append("")
        return lines

    lines: List[str] = ["# Judge Reasoning", ""]
    lines.append(f"- Status: `{str(judge.get('status') or '')}`")
    lines.append(f"- Pass: `{bool(judge.get('pass'))}`")
    lines.append(f"- Overall score: `{judge.get('overall_score_0_to_100')}`")
    lines.append(f"- Confidence: `{judge.get('confidence_0_to_1')}`")
    lines.append("")

    technical_summary = str(judge.get("technical_summary") or "").strip()
    if technical_summary:
        lines.extend(["## Technical Summary", "", technical_summary, ""])

    writing_summary = str(judge.get("writing_summary") or "").strip()
    if writing_summary:
        lines.extend(["## Writing Summary", "", writing_summary, ""])

    lines.extend(_section("Strongest Points", judge.get("strongest_points") or []))
    lines.extend(_section("Missed Expected Points", judge.get("missed_expected_points") or []))
    lines.extend(_section("Unsupported Claims", judge.get("unsupported_claims") or []))
    lines.extend(_section("Tool Observations", judge.get("tool_observations") or []))
    lines.extend(_section("Follow-up Recommendations", judge.get("follow_up_recommendations") or []))
    return "\n".join(lines).rstrip() + "\n"


def _agent_raw_output_markdown(record: Dict[str, Any]) -> str:
    agent = record.get("agent_result") if isinstance(record.get("agent_result"), dict) else {}
    metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
    lines: List[str] = ["# Agent Raw Output", ""]
    lines.append(f"- Sample: `{str(record.get('sample') or '')}`")
    lines.append(f"- Task: `{str(record.get('task_name') or record.get('task_id') or '')}`")
    lines.append(f"- Analysis status: `{str(metrics.get('analysis_status') or '')}`")
    lines.append(f"- Produced result: `{bool(metrics.get('produced_result'))}`")
    lines.append("")

    query = str(record.get("task_query") or agent.get("query") or "").strip()
    if query:
        lines.extend(["## Effective Query", "", query, ""])

    failure_reason = str(metrics.get("failure_reason") or agent.get("failure_reason") or "").strip()
    if failure_reason:
        lines.extend(["## Failure Reason", "", failure_reason, ""])

    final_report = str(agent.get("final_report") or "").strip()
    if final_report:
        lines.extend(["## Final Report", "", "```text", final_report, "```", ""])

    status_log = str(agent.get("status_log") or "").strip()
    if status_log:
        lines.extend(["## Status Log", "", "```text", status_log, "```", ""])
    return "\n".join(lines).rstrip() + "\n"


def _run_slot_name(replicate_index: int, run_id: str, used: set[str]) -> str:
    base = f"run_{max(1, int(replicate_index or 1)):03d}"
    if base not in used:
        used.add(base)
        return base
    fallback = f"{base}__{slugify(run_id)}"
    used.add(fallback)
    return fallback


def _config_metadata(
    *,
    sample_name: str,
    config_lineage_id: str,
    run_entries: List[Dict[str, Any]],
    experiment_id: str = "",
) -> Dict[str, Any]:
    first = run_entries[0]
    lineage_path = lineage_paths(config_lineage_id)["lineage"] if config_lineage_id else None
    run_ids = [str(entry.get("run_id") or "") for entry in run_entries if str(entry.get("run_id") or "").strip()]
    variant_ids = sorted({str(entry.get("variant_id") or "") for entry in run_entries if str(entry.get("variant_id") or "").strip()})
    return {
        "sample": str(sample_name or ""),
        "config_lineage_id": str(config_lineage_id or ""),
        "display_label": str(first.get("display_label") or ""),
        "variant_id": str(first.get("variant_id") or ""),
        "variant_name": str(first.get("variant_name") or ""),
        "changed_variable": str(first.get("changed_variable") or ""),
        "comparison_baseline_id": str(first.get("comparison_baseline_id") or ""),
        "comparison_baseline_label": str(first.get("comparison_baseline_label") or ""),
        "experiment_id": str(experiment_id or first.get("experiment_id") or ""),
        "pipeline": str(first.get("pipeline") or ""),
        "architecture": str(first.get("architecture") or ""),
        "query_variant": str(first.get("query_variant") or ""),
        "subagent_profile": str(first.get("subagent_profile") or ""),
        "worker_persona_profile": str(first.get("worker_persona_profile") or ""),
        "worker_role_prompt_mode": str(first.get("worker_role_prompt_mode") or ""),
        "validator_review_level": str(first.get("validator_review_level") or ""),
        "tool_profile": str(first.get("tool_profile") or ""),
        "model_profile": str(first.get("model_profile") or ""),
        "force_model": str(first.get("force_model") or ""),
        "judge_mode": str(first.get("judge_mode") or ""),
        "judge_model": str(first.get("judge_model") or ""),
        "run_count": len(run_entries),
        "run_ids": run_ids,
        "variant_ids": variant_ids,
        "lineage_path": str(lineage_path.resolve()) if lineage_path and lineage_path.exists() else "",
    }


def _task_metadata(task_id: str, task_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    first = task_rows[0]
    return {
        "task_id": str(task_id or ""),
        "task_name": str(first.get("task_name") or task_id),
        "sample_task_id": str(first.get("sample_task_id") or ""),
        "difficulty": str(first.get("difficulty") or ""),
        "task_tags": list(first.get("task_tags") or []),
        "target_tools": list(first.get("target_tools") or []),
        "expected_evidence": list(first.get("expected_evidence") or []),
        "acceptance_targets": list(first.get("acceptance_targets") or []),
    }


def _summary_metadata_from_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "run_id": str(entry.get("run_id") or ""),
        "corpus": str(entry.get("corpus") or ""),
        "experiment_id": str(entry.get("experiment_id") or ""),
        "variant_name": str(entry.get("variant_name") or ""),
        "changed_variable": str(entry.get("changed_variable") or ""),
        "comparison_baseline_id": str(entry.get("comparison_baseline_id") or ""),
        "comparison_baseline_label": str(entry.get("comparison_baseline_label") or ""),
        "config_lineage_id": str(entry.get("config_lineage_id") or ""),
        "pipeline": str(entry.get("pipeline") or ""),
        "architecture": str(entry.get("architecture") or ""),
        "query_variant": str(entry.get("query_variant") or ""),
        "subagent_profile": str(entry.get("subagent_profile") or ""),
        "worker_persona_profile": str(entry.get("worker_persona_profile") or ""),
        "worker_role_prompt_mode": str(entry.get("worker_role_prompt_mode") or ""),
        "validator_review_level": str(entry.get("validator_review_level") or ""),
        "tool_profile": str(entry.get("tool_profile") or ""),
        "model_profile": str(entry.get("model_profile") or ""),
        "force_model": str(entry.get("force_model") or ""),
        "judge_mode": str(entry.get("judge_mode") or ""),
        "judge_model": str(entry.get("judge_model") or ""),
        "expected_task_count": int(entry.get("expected_task_count") or 0),
        "selected_samples": list(entry.get("selected_samples") or []),
        "selected_tasks": list(entry.get("selected_tasks") or []),
        "selected_difficulties": list(entry.get("selected_difficulties") or []),
    }


def _write_run_artifacts(
    run_slot_dir: Path,
    *,
    run_entry: Dict[str, Any],
    record: Dict[str, Any],
    sample_dir: Path | None,
) -> Dict[str, Any]:
    ensure_dir(run_slot_dir)
    run_meta = {
        "run_id": str(run_entry.get("run_id") or ""),
        "replicate_index": int(run_entry.get("replicate_index") or 1),
        "replicate_count": int(run_entry.get("replicate_count") or 1),
        "display_label": str(run_entry.get("display_label") or ""),
        "variant_id": str(run_entry.get("variant_id") or ""),
        "variant_name": str(run_entry.get("variant_name") or ""),
        "changed_variable": str(run_entry.get("changed_variable") or ""),
        "comparison_baseline_id": str(run_entry.get("comparison_baseline_id") or ""),
        "comparison_baseline_label": str(run_entry.get("comparison_baseline_label") or ""),
        "config_lineage_id": str(run_entry.get("config_lineage_id") or ""),
        "pipeline": str(run_entry.get("pipeline") or ""),
        "architecture": str(run_entry.get("architecture") or ""),
        "query_variant": str(run_entry.get("query_variant") or ""),
        "subagent_profile": str(run_entry.get("subagent_profile") or ""),
        "worker_persona_profile": str(run_entry.get("worker_persona_profile") or ""),
        "worker_role_prompt_mode": str(run_entry.get("worker_role_prompt_mode") or ""),
        "validator_review_level": str(run_entry.get("validator_review_level") or ""),
        "tool_profile": str(run_entry.get("tool_profile") or ""),
        "model_profile": str(run_entry.get("model_profile") or ""),
        "force_model": str(run_entry.get("force_model") or ""),
        "judge_mode": str(run_entry.get("judge_mode") or ""),
        "judge_model": str(run_entry.get("judge_model") or ""),
        "canonical_run_dir": str(run_entry.get("run_dir") or ""),
        "canonical_sample_dir": str(sample_dir.resolve()) if sample_dir and sample_dir.exists() else "",
        "sample": str(record.get("sample") or ""),
        "task_id": str(record.get("task_id") or ""),
        "task_name": str(record.get("task_name") or ""),
        "sample_task_id": str(record.get("sample_task_id") or ""),
        "overall_score_0_to_100": _safe_float(((record.get("metrics") or {}).get("overall_score_0_to_100"))),
        "task_success": bool(((record.get("metrics") or {}).get("task_success"))),
        "analysis_status": str(((record.get("metrics") or {}).get("analysis_status") or "")),
        "judge_status": str(((record.get("metrics") or {}).get("judge_status") or "")),
    }
    write_json(run_slot_dir / "metadata.json", run_meta)
    write_json(run_slot_dir / "judge_scorecard.json", _judge_scorecard(record.get("judge_result") if isinstance(record.get("judge_result"), dict) else {}))
    (run_slot_dir / "judge_reasoning.md").write_text(
        _judge_reasoning_markdown(record.get("judge_result") if isinstance(record.get("judge_result"), dict) else {}),
        encoding="utf-8",
    )
    (run_slot_dir / "agent_raw_output.md").write_text(_agent_raw_output_markdown(record), encoding="utf-8")

    if sample_dir and sample_dir.exists():
        _copy_if_exists(sample_dir / "agent_result.json", run_slot_dir / "agent_result.json")
        _copy_if_exists(sample_dir / "judge_result.json", run_slot_dir / "judge_result.json")
        _copy_if_exists(sample_dir / "record.json", run_slot_dir / "record.json")
    else:
        write_json(run_slot_dir / "record.json", record)
        if isinstance(record.get("agent_result"), dict):
            write_json(run_slot_dir / "agent_result.json", record["agent_result"])
        if isinstance(record.get("judge_result"), dict):
            write_json(run_slot_dir / "judge_result.json", record["judge_result"])
    return run_meta


def _config_entry_from_run_manifest(run_manifest: Dict[str, Any], *, run_id: str, run_dir: Path) -> Dict[str, Any]:
    variant_id = str((run_manifest.get("metadata") or {}).get("experiment_variant_id") or run_manifest.get("variant_name") or "").strip()
    variant_name = str(run_manifest.get("variant_name") or variant_id or "").strip()
    changed_variable = str(run_manifest.get("changed_variable") or "").strip()
    display_label = (
        "baseline"
        if variant_name == "baseline" or (not changed_variable and variant_name == "baseline")
        else f"{changed_variable}:{variant_name}"
        if changed_variable and variant_name
        else variant_name or variant_id or "run"
    )
    return {
        "run_id": str(run_id or run_manifest.get("run_id") or ""),
        "run_dir": str(run_dir.resolve()),
        "replicate_index": int(run_manifest.get("replicate_index") or 1),
        "replicate_count": int(run_manifest.get("replicate_count") or 1),
        "variant_id": variant_id,
        "variant_name": variant_name,
        "display_label": display_label,
        "changed_variable": changed_variable,
        "comparison_baseline_id": str(run_manifest.get("comparison_baseline_id") or ""),
        "comparison_baseline_label": str(run_manifest.get("comparison_baseline_label") or ""),
        "config_lineage_id": str(run_manifest.get("config_lineage_id") or ""),
        "pipeline": str(run_manifest.get("pipeline") or ""),
        "architecture": str(run_manifest.get("architecture") or ""),
        "query_variant": str(run_manifest.get("query_variant") or ""),
        "subagent_profile": str(run_manifest.get("subagent_profile") or ""),
        "worker_persona_profile": str(run_manifest.get("worker_persona_profile") or ""),
        "worker_role_prompt_mode": str(run_manifest.get("worker_role_prompt_mode") or ""),
        "validator_review_level": str(run_manifest.get("validator_review_level") or ""),
        "tool_profile": str(run_manifest.get("tool_profile") or ""),
        "model_profile": str(run_manifest.get("model_profile") or ""),
        "force_model": str(run_manifest.get("force_model") or ""),
        "judge_mode": str(run_manifest.get("judge_mode") or ""),
        "judge_model": str(run_manifest.get("judge_model") or ""),
        "expected_task_count": int(run_manifest.get("expected_task_count") or 0),
        "selected_samples": list(run_manifest.get("selected_samples") or []),
        "selected_tasks": list(run_manifest.get("selected_tasks") or []),
        "selected_difficulties": list(run_manifest.get("selected_difficulties") or []),
        "experiment_id": str(run_manifest.get("experiment_id") or ""),
        "corpus": str(run_manifest.get("corpus") or ""),
    }


def build_run_output_layout(
    *,
    run_dir: Path,
    run_manifest: Dict[str, Any],
    aggregate: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Function: build_run_output_layout
    Inputs:
      - run_dir: root directory for one completed evaluation run.
      - run_manifest: canonical run manifest describing the configuration.
      - aggregate: canonical run-level aggregate for the same run.
    Description:
      Mirror the canonical run artifacts into a manual-browsing layout grouped
      by executable and task, while keeping the run root plus `samples/` as the
      source-of-truth.
    Outputs:
      Returns a layout manifest describing what inspection-oriented files and
      directories were written under `by_executable/`.
    Side Effects:
      Creates directories and copies or renders additive inspection artifacts.
    """
    layout_root = run_dir / "by_executable"
    if layout_root.exists():
        shutil.rmtree(layout_root)
    layout_root = ensure_dir(layout_root)
    run_entry = _config_entry_from_run_manifest(run_manifest, run_id=str(run_manifest.get("run_id") or ""), run_dir=run_dir)
    config_lineage_id = str(run_manifest.get("config_lineage_id") or "")
    records = list(aggregate.get("records") or [])
    grouped_by_sample: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped_by_sample[str(record.get("sample") or "")].append(record)

    index_rows: List[Dict[str, Any]] = []
    for sample_name, sample_records in sorted(grouped_by_sample.items()):
        sample_dir = ensure_dir(layout_root / _sample_folder_name(sample_name))
        config_dir = ensure_dir(sample_dir / (config_lineage_id or "config"))
        config_summary = aggregate_records(_summary_metadata_from_entry(run_entry), sample_records)
        write_json(config_dir / "metadata.json", _config_metadata(sample_name=sample_name, config_lineage_id=config_lineage_id, run_entries=[run_entry]))
        write_json(config_dir / "aggregate_summary.json", _without_records(config_summary))

        task_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for record in sample_records:
            task_groups[str(record.get("task_id") or "default_analysis")].append(record)

        tasks_root = ensure_dir(config_dir / "tasks")
        for task_id, task_records in sorted(task_groups.items()):
            task_dir = ensure_dir(tasks_root / _task_folder_name(task_id))
            write_json(task_dir / "metadata.json", _task_metadata(task_id, task_records))
            task_summary = aggregate_records(_summary_metadata_from_entry(run_entry), task_records)
            write_json(task_dir / "aggregate_summary.json", _without_records(task_summary))
            runs_root = ensure_dir(task_dir / "runs")
            used_slots: set[str] = set()
            run_slot = _run_slot_name(int(run_entry.get("replicate_index") or 1), str(run_entry.get("run_id") or ""), used_slots)
            record = task_records[0]
            canonical_sample_dir = run_dir / "samples" / _task_sample_slug(sample_name, task_id)
            _write_run_artifacts(
                runs_root / run_slot,
                run_entry=run_entry,
                record=record,
                sample_dir=canonical_sample_dir if canonical_sample_dir.exists() else None,
            )
            index_rows.append(
                {
                    "sample": sample_name,
                    "config_lineage_id": config_lineage_id,
                    "task_id": task_id,
                    "run_slot": run_slot,
                    "run_id": run_entry.get("run_id", ""),
                    "config_path": str(config_dir.resolve()),
                    "task_path": str(task_dir.resolve()),
                    "run_path": str((runs_root / run_slot).resolve()),
                }
            )

    write_json(layout_root / "index.json", {"schema_version": "result_layout_v1", "rows": index_rows})
    _write_rows_csv(layout_root / "index.csv", index_rows)
    return {
        "schema_version": "result_layout_v1",
        "scope": "run",
        "root": str(layout_root.resolve()),
        "row_count": len(index_rows),
    }


def build_experiment_output_layout(
    *,
    experiment_root: Path,
    experiment_id: str,
    successful_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Function: build_experiment_output_layout
    Inputs:
      - experiment_root: root directory for one completed experiment sweep.
      - experiment_id: stable experiment identifier used in output metadata.
      - successful_entries: successful child-run summaries with manifests and
        aggregates attached.
    Description:
      Build the additive browsing layout for sweep outputs so experiment
      artifacts can be inspected by executable, task, and configuration family.
    Outputs:
      Returns a layout manifest describing the inspection-oriented experiment
      files written to disk.
    Side Effects:
      Creates directories and writes comparison artifacts under the experiment
      results tree.
    """
    layout_root = experiment_root / "by_executable"
    if layout_root.exists():
        shutil.rmtree(layout_root)
    layout_root = ensure_dir(layout_root)
    grouped: Dict[Tuple[str, str], List[Tuple[Dict[str, Any], Dict[str, Any]]]] = defaultdict(list)
    for entry in successful_entries:
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        run_dir = Path(str(entry.get("run_dir") or ""))
        run_manifest = entry.get("run_manifest") if isinstance(entry.get("run_manifest"), dict) else {}
        if (not run_manifest or not str(run_manifest.get("config_lineage_id") or "").strip()) and run_dir:
            manifest_path = run_dir / "run_manifest.json"
            if manifest_path.exists():
                try:
                    run_manifest = read_json(manifest_path)
                except Exception:
                    run_manifest = run_manifest if isinstance(run_manifest, dict) else {}
        run_entry = _config_entry_from_run_manifest(
            run_manifest,
            run_id=str(entry.get("run_id") or run_manifest.get("run_id") or ""),
            run_dir=run_dir,
        )
        run_entry["variant_id"] = str(entry.get("variant_id") or run_entry.get("variant_id") or "")
        run_entry["display_label"] = str(entry.get("display_label") or run_entry.get("display_label") or "")
        run_entry["changed_variable"] = str(entry.get("changed_variable") or run_entry.get("changed_variable") or "")
        run_entry["comparison_baseline_id"] = str(entry.get("comparison_baseline_id") or run_entry.get("comparison_baseline_id") or "")
        run_entry["comparison_baseline_label"] = str(entry.get("comparison_baseline_label") or run_entry.get("comparison_baseline_label") or "")
        for record in list(aggregate.get("records") or []):
            sample_name = str(record.get("sample") or "")
            config_lineage_id = str(run_entry.get("config_lineage_id") or "")
            grouped[(sample_name, config_lineage_id)].append((run_entry, record))

    index_rows: List[Dict[str, Any]] = []
    for (sample_name, config_lineage_id), rows in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
        sample_dir = ensure_dir(layout_root / _sample_folder_name(sample_name))
        config_dir = ensure_dir(sample_dir / (config_lineage_id or "config"))
        run_entries = [entry for entry, _ in rows]
        records = [record for _, record in rows]
        config_summary = aggregate_records(_summary_metadata_from_entry(run_entries[0]), records)
        write_json(
            config_dir / "metadata.json",
            _config_metadata(
                sample_name=sample_name,
                config_lineage_id=config_lineage_id,
                run_entries=run_entries,
                experiment_id=experiment_id,
            ),
        )
        write_json(config_dir / "aggregate_summary.json", _without_records(config_summary))

        task_groups: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = defaultdict(list)
        for entry, record in rows:
            task_groups[str(record.get("task_id") or "default_analysis")].append((entry, record))

        tasks_root = ensure_dir(config_dir / "tasks")
        for task_id, task_rows in sorted(task_groups.items()):
            task_dir = ensure_dir(tasks_root / _task_folder_name(task_id))
            task_records = [record for _, record in task_rows]
            write_json(task_dir / "metadata.json", _task_metadata(task_id, task_records))
            task_summary = aggregate_records(_summary_metadata_from_entry(task_rows[0][0]), task_records)
            write_json(task_dir / "aggregate_summary.json", _without_records(task_summary))
            runs_root = ensure_dir(task_dir / "runs")
            used_slots: set[str] = set()
            ordered_rows = sorted(
                task_rows,
                key=lambda item: (int(item[0].get("replicate_index") or 1), str(item[0].get("run_id") or "")),
            )
            for run_entry, record in ordered_rows:
                run_slot = _run_slot_name(int(run_entry.get("replicate_index") or 1), str(run_entry.get("run_id") or ""), used_slots)
                canonical_sample_dir = Path(str(run_entry.get("run_dir") or "")) / "samples" / _task_sample_slug(sample_name, task_id)
                _write_run_artifacts(
                    runs_root / run_slot,
                    run_entry=run_entry,
                    record=record,
                    sample_dir=canonical_sample_dir if canonical_sample_dir.exists() else None,
                )
                index_rows.append(
                    {
                        "experiment_id": experiment_id,
                        "sample": sample_name,
                        "config_lineage_id": config_lineage_id,
                        "task_id": task_id,
                        "run_slot": run_slot,
                        "run_id": run_entry.get("run_id", ""),
                        "display_label": run_entry.get("display_label", ""),
                        "config_path": str(config_dir.resolve()),
                        "task_path": str(task_dir.resolve()),
                        "run_path": str((runs_root / run_slot).resolve()),
                    }
                )

    write_json(layout_root / "index.json", {"schema_version": "result_layout_v1", "experiment_id": experiment_id, "rows": index_rows})
    _write_rows_csv(layout_root / "index.csv", index_rows)
    return {
        "schema_version": "result_layout_v1",
        "scope": "experiment",
        "experiment_id": experiment_id,
        "root": str(layout_root.resolve()),
        "row_count": len(index_rows),
    }
