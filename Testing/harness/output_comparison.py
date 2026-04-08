from __future__ import annotations

import csv
import html
import json
from collections import defaultdict
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterable, List, Tuple

from .paths import ensure_dir, slugify, write_json


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


def _shorten(text: str, limit: int = 180) -> str:
    clean = " ".join(str(text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1].rstrip() + "…"


def _fmt_list(items: Iterable[Any]) -> str:
    values = [str(item).strip() for item in items if str(item).strip()]
    return ", ".join(values)


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except Exception:
        return None


def _variant_sort_key(row: Dict[str, Any]) -> Tuple[int, str]:
    if bool(row.get("is_baseline")):
        return (0, str(row.get("display_label") or ""))
    if bool(row.get("is_family_baseline")):
        return (1, str(row.get("display_label") or ""))
    return (2, str(row.get("display_label") or ""))


def _representative_row(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    scored_rows = [
        row for row in rows
        if _safe_float(row.get("overall_score_0_to_100")) is not None
    ]
    if scored_rows:
        target = float(median([float(_safe_float(row.get("overall_score_0_to_100")) or 0.0) for row in scored_rows]))
        return sorted(
            scored_rows,
            key=lambda row: (
                abs(float(_safe_float(row.get("overall_score_0_to_100")) or 0.0) - target),
                -int(bool(str(row.get("final_report") or "").strip())),
                -int(row.get("replicate_index") or 0),
            ),
        )[0]

    produced_rows = [row for row in rows if row.get("produced_result")]
    if produced_rows:
        return sorted(produced_rows, key=lambda row: int(row.get("replicate_index") or 0), reverse=True)[0]

    return sorted(rows, key=lambda row: int(row.get("replicate_index") or 0), reverse=True)[0]


def _detail_row(entry: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
    metrics = record.get("metrics") or {}
    judge = record.get("judge_result") or {}
    sample = str(record.get("sample") or "").strip()
    task_id = str(record.get("task_id") or "").strip()
    task_slug = f"{Path(sample).stem}__{task_id}" if sample and task_id else ""
    run_dir = Path(str(entry.get("run_dir") or "")).resolve() if entry.get("run_dir") else Path()
    sample_dir = run_dir / "samples" / task_slug if task_slug and run_dir else Path()
    return {
        "variant_id": str(entry.get("variant_id") or ""),
        "variant_name": str(entry.get("variant_name") or ""),
        "display_label": str(entry.get("display_label") or ""),
        "changed_variable": str(entry.get("changed_variable") or ""),
        "comparison_baseline_label": str(entry.get("comparison_baseline_label") or ""),
        "is_baseline": bool(entry.get("is_baseline")),
        "is_family_baseline": bool(entry.get("is_family_baseline")),
        "replicate_index": int(entry.get("replicate_index") or 0),
        "run_id": str(entry.get("run_id") or ""),
        "run_dir": str(run_dir) if run_dir else "",
        "sample": sample,
        "task_id": task_id,
        "task_name": str(record.get("task_name") or task_id),
        "sample_task_id": str(record.get("sample_task_id") or ""),
        "difficulty": str(record.get("difficulty") or "unknown"),
        "task_tags": _fmt_list(record.get("task_tags") or []),
        "target_tools": _fmt_list(record.get("target_tools") or []),
        "expected_evidence": _fmt_list(record.get("expected_evidence") or []),
        "acceptance_targets": _fmt_list(record.get("acceptance_targets") or []),
        "effective_query": str(record.get("task_query") or "").strip(),
        "analysis_status": str(metrics.get("analysis_status") or ""),
        "judge_status": str(metrics.get("judge_status") or ""),
        "judge_pass": bool(metrics.get("judge_pass")),
        "produced_result": bool(metrics.get("produced_result")),
        "task_success": bool(metrics.get("task_success")),
        "overall_score_0_to_100": _safe_float(metrics.get("overall_score_0_to_100")),
        "total_relative_cost_index": _safe_float(metrics.get("total_relative_cost_index")),
        "total_estimated_cost_usd": _safe_float(metrics.get("total_estimated_cost_usd")),
        "analysis_duration_sec": _safe_float(metrics.get("analysis_duration_sec")),
        "judge_duration_sec": _safe_float(metrics.get("judge_duration_sec")),
        "total_duration_sec": _safe_float(metrics.get("total_duration_sec")),
        "task_wall_clock_duration_sec": _safe_float(metrics.get("task_wall_clock_duration_sec")),
        "target_tool_hit_rate": _safe_float(metrics.get("target_tool_hit_rate")),
        "failure_reason": str(metrics.get("failure_reason") or ""),
        "judge_failure_reason": str(metrics.get("judge_failure_reason") or ""),
        "final_report": str((record.get("agent_result") or {}).get("final_report") or "").strip(),
        "technical_summary": str(judge.get("technical_summary") or "").strip(),
        "writing_summary": str(judge.get("writing_summary") or "").strip(),
        "strongest_points": _fmt_list(judge.get("strongest_points") or []),
        "missed_expected_points": _fmt_list(judge.get("missed_expected_points") or []),
        "follow_up_recommendations": _fmt_list(judge.get("follow_up_recommendations") or []),
        "record_path": str(sample_dir / "record.json") if sample_dir else "",
        "agent_result_path": str(sample_dir / "agent_result.json") if sample_dir else "",
        "judge_result_path": str(sample_dir / "judge_result.json") if sample_dir else "",
    }


def _render_task_markdown(sample_task_id: str, rows: List[Dict[str, Any]]) -> str:
    reference = rows[0]
    lines: List[str] = []
    lines.append(f"# {sample_task_id}")
    lines.append("")
    lines.append(f"- Sample: `{reference.get('sample', '')}`")
    lines.append(f"- Task: `{reference.get('task_name', '')}` (`{reference.get('task_id', '')}`)")
    lines.append(f"- Difficulty: `{reference.get('difficulty', '')}`")
    lines.append(f"- Tags: `{reference.get('task_tags', '')}`")
    lines.append(f"- Target tools: `{reference.get('target_tools', '')}`")
    lines.append(f"- Acceptance targets: `{reference.get('acceptance_targets', '')}`")
    lines.append("")
    lines.append("| Configuration | Replicates | Mean Score | Success Rate | Mean Cost Index | Mean Task Duration (s) | Representative Run |")
    lines.append("|---|---:|---:|---:|---:|---:|---|")

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("variant_id") or "")].append(row)

    ordered_groups = sorted(grouped.values(), key=lambda group: _variant_sort_key(group[0]))
    for group in ordered_groups:
        rep = _representative_row(group)
        scores = [_safe_float(item.get("overall_score_0_to_100")) for item in group]
        costs = [_safe_float(item.get("total_relative_cost_index")) for item in group]
        durations = [_safe_float(item.get("task_wall_clock_duration_sec")) for item in group]
        successes = [1.0 if item.get("task_success") else 0.0 for item in group]
        score_values = [value for value in scores if value is not None]
        cost_values = [value for value in costs if value is not None]
        duration_values = [value for value in durations if value is not None]
        lines.append(
            "| {label} | {replicates} | {score} | {success} | {cost} | {duration} | `{run_id}` |".format(
                label=rep.get("display_label", ""),
                replicates=len(group),
                score=round(sum(score_values) / len(score_values), 3) if score_values else "",
                success=round(sum(successes) / len(successes), 3) if successes else "",
                cost=round(sum(cost_values) / len(cost_values), 6) if cost_values else "",
                duration=round(sum(duration_values) / len(duration_values), 3) if duration_values else "",
                run_id=rep.get("run_id", ""),
            )
        )
    lines.append("")

    for group in ordered_groups:
        rep = _representative_row(group)
        lines.append(f"## {rep.get('display_label', '')}")
        lines.append("")
        lines.append(f"- Changed variable: `{rep.get('changed_variable', '') or 'baseline'}`")
        lines.append(f"- Comparison baseline: `{rep.get('comparison_baseline_label', '') or 'baseline'}`")
        lines.append(f"- Replicates captured: `{len(group)}`")
        lines.append(f"- Representative run (median-scoring when scores exist): `{rep.get('run_id', '')}`")
        lines.append(f"- Score: `{rep.get('overall_score_0_to_100', '')}`")
        lines.append(f"- Task success: `{rep.get('task_success', False)}`")
        lines.append(f"- Cost index: `{rep.get('total_relative_cost_index', '')}`")
        lines.append(f"- Task duration (s): `{rep.get('task_wall_clock_duration_sec', '')}`")
        lines.append(f"- Effective query: `{rep.get('effective_query', '')}`")
        lines.append(f"- Judge summary (model-generated): `{rep.get('technical_summary', '')}`")
        if rep.get("missed_expected_points"):
            lines.append(f"- Missed expected points: `{rep.get('missed_expected_points', '')}`")
        lines.append("")
        lines.append("### Final Report")
        lines.append("")
        lines.append("```text")
        lines.append(str(rep.get("final_report") or ""))
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_index_markdown(task_index_rows: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append("# Task Output Comparisons")
    lines.append("")
    lines.append("| Sample Task | Difficulty | Configurations | Baseline Score | Best Score | Best Configuration | Page |")
    lines.append("|---|---|---:|---:|---:|---|---|")
    for row in task_index_rows:
        lines.append(
            "| {sample_task_id} | {difficulty} | {configuration_count} | {baseline_score} | {best_score} | {best_configuration} | [{page}]({page}) |".format(
                **row
            )
        )
    lines.append("")
    lines.append("Each task page shows the effective query, representative output, judge summaries, and run ids for every configuration that produced a record.")
    return "\n".join(lines).rstrip() + "\n"


def _render_index_html(task_index_rows: List[Dict[str, Any]]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value or ""))

    body = "\n".join(
        "<tr>"
        f"<td>{esc(row['sample_task_id'])}</td>"
        f"<td>{esc(row['difficulty'])}</td>"
        f"<td>{esc(row['configuration_count'])}</td>"
        f"<td>{esc(row['baseline_score'])}</td>"
        f"<td>{esc(row['best_score'])}</td>"
        f"<td>{esc(row['best_configuration'])}</td>"
        f"<td><a href=\"{esc(row['page'])}\">open</a></td>"
        "</tr>"
        for row in task_index_rows
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Task Output Comparisons</title>
  <style>
    body {{ font-family: Georgia, serif; background: #f5f1e8; color: #231f1a; margin: 0; }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 28px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fffaf0; border: 1px solid #d9cfbe; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #d9cfbe; }}
    th {{ background: #efe7d8; }}
    a {{ color: #8a5a2b; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Task Output Comparisons</h1>
    <p>Representative outputs and summaries for each sample-task across sweep configurations.</p>
    <table>
      <thead><tr><th>Sample Task</th><th>Difficulty</th><th>Configurations</th><th>Baseline Score</th><th>Best Score</th><th>Best Configuration</th><th>Page</th></tr></thead>
      <tbody>{body}</tbody>
    </table>
  </div>
</body>
</html>
"""


def _render_task_html(sample_task_id: str, rows: List[Dict[str, Any]]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value or ""))

    reference = rows[0]
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get("variant_id") or "")].append(row)
    ordered_groups = sorted(grouped.values(), key=lambda group: _variant_sort_key(group[0]))

    summary_rows = []
    detail_sections = []
    for group in ordered_groups:
        rep = _representative_row(group)
        scores = [_safe_float(item.get("overall_score_0_to_100")) for item in group]
        costs = [_safe_float(item.get("total_relative_cost_index")) for item in group]
        successes = [1.0 if item.get("task_success") else 0.0 for item in group]
        score_values = [value for value in scores if value is not None]
        cost_values = [value for value in costs if value is not None]
        summary_rows.append(
            "<tr>"
            f"<td>{esc(rep.get('display_label'))}</td>"
            f"<td>{esc(len(group))}</td>"
            f"<td>{esc(round(sum(score_values) / len(score_values), 3) if score_values else '')}</td>"
            f"<td>{esc(round(sum(successes) / len(successes), 3) if successes else '')}</td>"
            f"<td>{esc(round(sum(cost_values) / len(cost_values), 6) if cost_values else '')}</td>"
            f"<td>{esc(rep.get('run_id'))}</td>"
            "</tr>"
        )
        detail_sections.append(
            f"""
            <section class="config-card">
              <h2>{esc(rep.get('display_label'))}</h2>
              <p><strong>Changed variable:</strong> {esc(rep.get('changed_variable') or 'baseline')}</p>
              <p><strong>Comparison baseline:</strong> {esc(rep.get('comparison_baseline_label') or 'baseline')}</p>
              <p><strong>Replicates captured:</strong> {esc(len(group))}</p>
              <p><strong>Representative run (median-scoring when scores exist):</strong> {esc(rep.get('run_id'))}</p>
              <p><strong>Score:</strong> {esc(rep.get('overall_score_0_to_100'))}</p>
              <p><strong>Task success:</strong> {esc(rep.get('task_success'))}</p>
              <p><strong>Cost index:</strong> {esc(rep.get('total_relative_cost_index'))}</p>
              <details open>
                <summary>Effective query</summary>
                <pre>{esc(rep.get('effective_query'))}</pre>
              </details>
              <details open>
                <summary>Final report</summary>
                <pre>{esc(rep.get('final_report'))}</pre>
              </details>
              <details>
                <summary>Judge notes</summary>
                <p><strong>Technical summary (model-generated):</strong> {esc(rep.get('technical_summary'))}</p>
                <p><strong>Writing summary (model-generated):</strong> {esc(rep.get('writing_summary'))}</p>
                <p><strong>Strongest points:</strong> {esc(rep.get('strongest_points'))}</p>
                <p><strong>Missed expected points:</strong> {esc(rep.get('missed_expected_points'))}</p>
                <p><strong>Follow-up recommendations:</strong> {esc(rep.get('follow_up_recommendations'))}</p>
              </details>
            </section>
            """
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{esc(sample_task_id)}</title>
  <style>
    body {{ font-family: Georgia, serif; background: #f5f1e8; color: #231f1a; margin: 0; }}
    .wrap {{ max-width: 1400px; margin: 0 auto; padding: 28px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fffaf0; border: 1px solid #d9cfbe; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #d9cfbe; vertical-align: top; }}
    th {{ background: #efe7d8; }}
    .config-card {{ background: #fffaf0; border: 1px solid #d9cfbe; border-radius: 10px; padding: 16px; margin-top: 18px; }}
    pre {{ white-space: pre-wrap; background: #fbf7ef; border: 1px solid #d9cfbe; padding: 10px; border-radius: 8px; }}
    details > summary {{ cursor: pointer; color: #8a5a2b; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{esc(sample_task_id)}</h1>
    <p><strong>Sample:</strong> {esc(reference.get('sample'))}</p>
    <p><strong>Task:</strong> {esc(reference.get('task_name'))} ({esc(reference.get('task_id'))})</p>
    <p><strong>Difficulty:</strong> {esc(reference.get('difficulty'))}</p>
    <p><strong>Tags:</strong> {esc(reference.get('task_tags'))}</p>
    <p><strong>Target tools:</strong> {esc(reference.get('target_tools'))}</p>
    <p><strong>Acceptance targets:</strong> {esc(reference.get('acceptance_targets'))}</p>

    <table>
      <thead><tr><th>Configuration</th><th>Replicates</th><th>Mean Score</th><th>Success Rate</th><th>Mean Cost Index</th><th>Representative Run</th></tr></thead>
      <tbody>{''.join(summary_rows)}</tbody>
    </table>

    {''.join(detail_sections)}
  </div>
</body>
</html>
"""


def build_task_output_comparisons(
    output_dir: Path,
    *,
    run_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    output_dir = ensure_dir(output_dir)
    tasks_dir = ensure_dir(output_dir / "tasks")

    detail_rows: List[Dict[str, Any]] = []
    for entry in run_entries:
        if not entry.get("ok") or not isinstance(entry.get("aggregate"), dict):
            continue
        aggregate = entry.get("aggregate") or {}
        for record in aggregate.get("records") or []:
            if isinstance(record, dict):
                detail_rows.append(_detail_row(entry, record))

    detail_rows.sort(
        key=lambda row: (
            str(row.get("sample_task_id") or ""),
            _variant_sort_key(row),
            int(row.get("replicate_index") or 0),
        )
    )

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in detail_rows:
        grouped[str(row.get("sample_task_id") or "")].append(row)

    task_index_rows: List[Dict[str, Any]] = []
    task_manifest: Dict[str, Any] = {}

    summary_rows: List[Dict[str, Any]] = []
    for sample_task_id, rows in sorted(grouped.items()):
        task_page_name = f"{slugify(sample_task_id)}.html"
        variant_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for row in rows:
            variant_groups[str(row.get("variant_id") or "")].append(row)
        baseline_group = variant_groups.get("baseline") or []
        baseline_scores = [_safe_float(row.get("overall_score_0_to_100")) for row in baseline_group]
        baseline_score_values = [value for value in baseline_scores if value is not None]

        best_group_label = ""
        best_group_score = None
        variants_payload: List[Dict[str, Any]] = []
        for _, group_rows in sorted(variant_groups.items(), key=lambda item: _variant_sort_key(item[1][0])):
            rep = _representative_row(group_rows)
            score_values = [_safe_float(row.get("overall_score_0_to_100")) for row in group_rows if _safe_float(row.get("overall_score_0_to_100")) is not None]
            cost_values = [_safe_float(row.get("total_relative_cost_index")) for row in group_rows if _safe_float(row.get("total_relative_cost_index")) is not None]
            mean_score = round(sum(score_values) / len(score_values), 3) if score_values else None
            mean_cost = round(sum(cost_values) / len(cost_values), 6) if cost_values else None
            success_rate = round(sum(1.0 if row.get("task_success") else 0.0 for row in group_rows) / len(group_rows), 3) if group_rows else None
            if mean_score is not None and (best_group_score is None or mean_score > best_group_score):
                best_group_score = mean_score
                best_group_label = str(rep.get("display_label") or "")
            variants_payload.append(
                {
                    "variant_id": rep.get("variant_id"),
                    "display_label": rep.get("display_label"),
                    "changed_variable": rep.get("changed_variable"),
                    "comparison_baseline_label": rep.get("comparison_baseline_label"),
                    "replicate_count": len(group_rows),
                    "mean_score": mean_score,
                    "success_rate": success_rate,
                    "mean_cost_index": mean_cost,
                    "representative": rep,
                    "replicates": group_rows,
                }
            )
            summary_rows.append(
                {
                    "sample_task_id": sample_task_id,
                    "difficulty": rep.get("difficulty"),
                    "display_label": rep.get("display_label"),
                    "changed_variable": rep.get("changed_variable"),
                    "replicate_count": len(group_rows),
                    "mean_score": mean_score,
                    "success_rate": success_rate,
                    "mean_cost_index": mean_cost,
                    "representative_run_id": rep.get("run_id"),
                    "representative_record_path": rep.get("record_path"),
                    "effective_query": rep.get("effective_query"),
                    "final_report_excerpt": _shorten(rep.get("final_report") or "", 220),
                    "technical_summary_excerpt": _shorten(rep.get("technical_summary") or "", 180),
                }
            )

        index_row = {
            "sample_task_id": sample_task_id,
            "difficulty": rows[0].get("difficulty", ""),
            "configuration_count": len(variant_groups),
            "baseline_score": round(sum(baseline_score_values) / len(baseline_score_values), 3) if baseline_score_values else "",
            "best_score": best_group_score if best_group_score is not None else "",
            "best_configuration": best_group_label,
            "page": f"tasks/{task_page_name}",
        }
        task_index_rows.append(index_row)

        task_manifest[sample_task_id] = {
            "difficulty": rows[0].get("difficulty", ""),
            "sample": rows[0].get("sample", ""),
            "task_id": rows[0].get("task_id", ""),
            "task_name": rows[0].get("task_name", ""),
            "page": index_row["page"],
            "variants": variants_payload,
        }
        (tasks_dir / f"{slugify(sample_task_id)}.md").write_text(_render_task_markdown(sample_task_id, rows), encoding="utf-8")
        (tasks_dir / task_page_name).write_text(_render_task_html(sample_task_id, rows), encoding="utf-8")

    comparison_payload = {
        "task_count": len(grouped),
        "task_index": task_index_rows,
        "tasks": task_manifest,
    }
    write_json(output_dir / "comparison_manifest.json", comparison_payload)
    _write_rows_csv(output_dir / "all_rows.csv", detail_rows)
    _write_rows_csv(output_dir / "task_variant_summary.csv", summary_rows)
    (output_dir / "index.md").write_text(_render_index_markdown(task_index_rows), encoding="utf-8")
    (output_dir / "index.html").write_text(_render_index_html(task_index_rows), encoding="utf-8")
    return {
        "ok": True,
        "output_dir": str(output_dir),
        "task_count": len(grouped),
        "row_count": len(detail_rows),
        "created_files": [
            str(output_dir / "comparison_manifest.json"),
            str(output_dir / "all_rows.csv"),
            str(output_dir / "task_variant_summary.csv"),
            str(output_dir / "index.md"),
            str(output_dir / "index.html"),
        ],
    }
