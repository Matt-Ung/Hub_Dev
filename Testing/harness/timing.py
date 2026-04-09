"""
File: timing.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Aggregate timing data from run and experiment records into reporting tables.

Summary:
  This module summarizes analysis, judging, and wall-clock durations across
  runs, tasks, and higher-level experiment groupings so timing tradeoffs stay
  visible alongside quality metrics.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Dict, List, Tuple

from .paths import ensure_dir


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


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except Exception:
        return None


def _mean(values: List[float]) -> float | None:
    return round(mean(values), 6) if values else None


def _std(values: List[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return round(pstdev(values), 6)


def _task_tags(record: Dict[str, Any]) -> List[str]:
    tags = [str(item).strip() for item in (record.get("task_tags") or []) if str(item).strip()]
    return tags or ["uncategorized"]


def _prefer(primary: Any, fallback: Any) -> Any:
    return fallback if primary in {None, ""} else primary


def build_timing_outputs(
    output_dir: Path,
    *,
    run_entries: List[Dict[str, Any]],
    variant_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    output_dir = ensure_dir(output_dir)

    variant_lookup = {str(row.get("variant_id") or ""): row for row in variant_rows}
    baseline_by_variant = {
        str(row.get("variant_id") or ""): str(row.get("comparison_baseline_id") or "baseline")
        for row in variant_rows
    }

    individual_rows: List[Dict[str, Any]] = []
    task_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    tag_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    variant_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for entry in run_entries:
        aggregate = entry.get("aggregate") if isinstance(entry.get("aggregate"), dict) else {}
        variant_id = str(entry.get("variant_id") or "")
        variant_row = variant_lookup.get(variant_id) or {}
        for record in aggregate.get("records") or []:
            metrics = record.get("metrics") or {}
            sample_task_id = str(record.get("sample_task_id") or "")
            wall_clock_duration = _safe_float(metrics.get("task_wall_clock_duration_sec"))
            if wall_clock_duration is None:
                wall_clock_duration = _safe_float(metrics.get("total_duration_sec"))
            row = {
                "variant_id": variant_id,
                "display_label": str(entry.get("display_label") or variant_row.get("display_label") or variant_id),
                "changed_variable": str(entry.get("changed_variable") or variant_row.get("changed_variable") or ""),
                "config_lineage_id": str(((entry.get("run_manifest") or {}) if isinstance(entry.get("run_manifest"), dict) else {}).get("config_lineage_id") or ""),
                "run_id": str(entry.get("run_id") or ""),
                "replicate_index": int(entry.get("replicate_index") or 0),
                "sample": str(record.get("sample") or ""),
                "task_id": str(record.get("task_id") or ""),
                "task_name": str(record.get("task_name") or ""),
                "sample_task_id": sample_task_id,
                "difficulty": str(record.get("difficulty") or "unknown"),
                "task_tags": "; ".join(_task_tags(record)),
                "analysis_duration_sec": _safe_float(metrics.get("analysis_duration_sec")),
                "judge_duration_sec": _safe_float(metrics.get("judge_duration_sec")),
                "total_duration_sec": _safe_float(metrics.get("total_duration_sec")),
                "task_wall_clock_duration_sec": wall_clock_duration,
            }
            individual_rows.append(row)
            task_groups[(variant_id, sample_task_id)].append(row)
            variant_groups[variant_id].append(row)
            for tag in _task_tags(record):
                tag_groups[(variant_id, tag)].append(row)

    def _summarize_group(rows: List[Dict[str, Any]], extra: Dict[str, Any]) -> Dict[str, Any]:
        analysis_values = [value for value in (_safe_float(row.get("analysis_duration_sec")) for row in rows) if value is not None]
        judge_values = [value for value in (_safe_float(row.get("judge_duration_sec")) for row in rows) if value is not None]
        total_values = [value for value in (_safe_float(row.get("total_duration_sec")) for row in rows) if value is not None]
        wall_values = [value for value in (_safe_float(row.get("task_wall_clock_duration_sec")) for row in rows) if value is not None]
        reference = rows[0] if rows else {}
        return {
            **extra,
            "replicate_count": len(rows),
            "sample": reference.get("sample", ""),
            "task_id": reference.get("task_id", ""),
            "task_name": reference.get("task_name", ""),
            "sample_task_id": reference.get("sample_task_id", ""),
            "difficulty": reference.get("difficulty", "unknown"),
            "task_tags": reference.get("task_tags", ""),
            "mean_analysis_duration_sec": _mean(analysis_values),
            "std_analysis_duration_sec": _std(analysis_values),
            "mean_judge_duration_sec": _mean(judge_values),
            "std_judge_duration_sec": _std(judge_values),
            "mean_total_duration_sec": _mean(total_values),
            "std_total_duration_sec": _std(total_values),
            "mean_task_wall_clock_duration_sec": _mean(wall_values),
            "std_task_wall_clock_duration_sec": _std(wall_values),
        }

    task_summary_rows: List[Dict[str, Any]] = []
    for (variant_id, sample_task_id), rows in sorted(task_groups.items()):
        variant_row = variant_lookup.get(variant_id) or {}
        task_summary_rows.append(
            _summarize_group(
                rows,
                {
                    "variant_id": variant_id,
                    "display_label": str(variant_row.get("display_label") or variant_id),
                    "changed_variable": str(variant_row.get("changed_variable") or ""),
                    "comparison_baseline_id": baseline_by_variant.get(variant_id, "baseline"),
                    "config_lineage_id": str(variant_row.get("config_lineage_id") or ""),
                    "group_type": "task",
                },
            )
        )

    task_lookup = {
        (str(row.get("variant_id") or ""), str(row.get("sample_task_id") or "")): row
        for row in task_summary_rows
    }
    for row in task_summary_rows:
        baseline_id = str(row.get("comparison_baseline_id") or "baseline")
        baseline_row = task_lookup.get((baseline_id, str(row.get("sample_task_id") or ""))) or {}
        baseline_duration = _safe_float(baseline_row.get("mean_task_wall_clock_duration_sec"))
        current_duration = _safe_float(row.get("mean_task_wall_clock_duration_sec"))
        row["baseline_mean_task_wall_clock_duration_sec"] = baseline_duration
        row["task_wall_clock_delta_sec"] = (
            round(float(current_duration) - float(baseline_duration), 6)
            if current_duration is not None and baseline_duration is not None
            else None
        )

    tag_summary_rows: List[Dict[str, Any]] = []
    for (variant_id, tag), rows in sorted(tag_groups.items()):
        variant_row = variant_lookup.get(variant_id) or {}
        summary = _summarize_group(
            rows,
            {
                "variant_id": variant_id,
                "display_label": str(variant_row.get("display_label") or variant_id),
                "changed_variable": str(variant_row.get("changed_variable") or ""),
                "comparison_baseline_id": baseline_by_variant.get(variant_id, "baseline"),
                "config_lineage_id": str(variant_row.get("config_lineage_id") or ""),
                "group_type": "task_tag",
                "task_tag": tag,
            },
        )
        summary["sample"] = ""
        summary["task_id"] = ""
        summary["task_name"] = ""
        summary["sample_task_id"] = ""
        summary["task_tags"] = tag
        tag_summary_rows.append(summary)

    tag_lookup = {
        (str(row.get("variant_id") or ""), str(row.get("task_tag") or "")): row
        for row in tag_summary_rows
    }
    for row in tag_summary_rows:
        baseline_id = str(row.get("comparison_baseline_id") or "baseline")
        baseline_row = tag_lookup.get((baseline_id, str(row.get("task_tag") or ""))) or {}
        baseline_duration = _safe_float(baseline_row.get("mean_task_wall_clock_duration_sec"))
        current_duration = _safe_float(row.get("mean_task_wall_clock_duration_sec"))
        row["baseline_mean_task_wall_clock_duration_sec"] = baseline_duration
        row["task_wall_clock_delta_sec"] = (
            round(float(current_duration) - float(baseline_duration), 6)
            if current_duration is not None and baseline_duration is not None
            else None
        )

    variant_timing_rows: List[Dict[str, Any]] = []
    for row in variant_rows:
        variant_id = str(row.get("variant_id") or "")
        variant_group = variant_groups.get(variant_id) or []
        variant_group_summary = _summarize_group(variant_group, {}) if variant_group else {}
        variant_timing_rows.append(
            {
                "variant_id": variant_id,
                "display_label": row.get("display_label", ""),
                "changed_variable": row.get("changed_variable", ""),
                "comparison_baseline_id": row.get("comparison_baseline_id", ""),
                "comparison_baseline_label": row.get("comparison_baseline_label", ""),
                "config_lineage_id": row.get("config_lineage_id", ""),
                "completed_repetitions": row.get("completed_repetitions", ""),
                "mean_analysis_duration_sec": _prefer(row.get("mean_analysis_duration_sec"), variant_group_summary.get("mean_analysis_duration_sec", "")),
                "mean_judge_duration_sec": _prefer(row.get("mean_judge_duration_sec"), variant_group_summary.get("mean_judge_duration_sec", "")),
                "mean_total_duration_sec": _prefer(row.get("mean_total_duration_sec"), variant_group_summary.get("mean_total_duration_sec", "")),
                "mean_task_wall_clock_duration_sec": _prefer(row.get("mean_task_wall_clock_duration_sec"), variant_group_summary.get("mean_task_wall_clock_duration_sec", "")),
                "wall_clock_duration_stddev": _prefer(row.get("mean_task_wall_clock_duration_sec_stddev"), variant_group_summary.get("std_task_wall_clock_duration_sec", "")),
                "wall_clock_duration_delta_sec": row.get("task_wall_clock_duration_delta_sec", ""),
            }
        )

    report_lines: List[str] = []
    report_lines.append("# Timing Summary")
    report_lines.append("")
    report_lines.append("- `task_timing_individual.csv` captures one row per completed sample-task record within each run.")
    report_lines.append("- `task_timing_summary.csv` aggregates timing across replicate runs for the same configuration and sample-task.")
    report_lines.append("- `task_tag_timing_summary.csv` aggregates timing by task tag/category across replicate runs.")
    report_lines.append("")
    if task_summary_rows:
        slowest = sorted(
            [row for row in task_summary_rows if row.get("mean_task_wall_clock_duration_sec") is not None],
            key=lambda row: float(row.get("mean_task_wall_clock_duration_sec") or 0.0),
            reverse=True,
        )[:10]
        report_lines.append("## Slowest Sample-Tasks")
        report_lines.append("")
        for row in slowest:
            report_lines.append(
                f"- `{row.get('display_label')}` / `{row.get('sample_task_id')}`: "
                f"`{row.get('mean_task_wall_clock_duration_sec')}`s"
            )
        report_lines.append("")

    (output_dir / "timing_report.md").write_text("\n".join(report_lines).rstrip() + "\n", encoding="utf-8")
    _write_rows_csv(output_dir / "task_timing_individual.csv", individual_rows)
    _write_rows_csv(output_dir / "task_timing_summary.csv", task_summary_rows)
    _write_rows_csv(output_dir / "task_tag_timing_summary.csv", tag_summary_rows)
    _write_rows_csv(output_dir / "variant_timing_summary.csv", variant_timing_rows)
    return {
        "individual_rows": individual_rows,
        "task_summary_rows": task_summary_rows,
        "task_tag_summary_rows": tag_summary_rows,
        "variant_timing_rows": variant_timing_rows,
    }
