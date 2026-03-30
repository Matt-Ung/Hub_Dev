from __future__ import annotations

import csv
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional

from .costing import add_usage_snapshots, coerce_usage_snapshot
from .paths import CONFIG_ROOT, ensure_dir, read_json
from .samples import sample_task_key


def _rubric_dimensions() -> List[Dict[str, Any]]:
    try:
        rubric = read_json(CONFIG_ROOT / "binary_judge_rubric.json")
        dimensions = rubric.get("dimensions") if isinstance(rubric.get("dimensions"), list) else []
        cleaned = [dim for dim in dimensions if isinstance(dim, dict) and str(dim.get("name") or "").strip()]
        if cleaned:
            return cleaned
    except Exception:
        pass
    return [
        {"name": "evidence_grounding", "label": "Evidence Grounding"},
        {"name": "specificity", "label": "Specificity"},
        {"name": "technique_coverage", "label": "Technique Coverage"},
        {"name": "false_claim_control", "label": "False Claim Control"},
        {"name": "task_alignment", "label": "Task Alignment"},
        {"name": "report_conciseness", "label": "Report Conciseness"},
    ]


def _rubric_dimension_names() -> List[str]:
    return [str(dim.get("name") or "").strip() for dim in _rubric_dimensions() if str(dim.get("name") or "").strip()]


def _rubric_dimension_label(dim: Dict[str, Any]) -> str:
    label = str(dim.get("label") or "").strip()
    if label:
        return label
    return str(dim.get("name") or "").strip().replace("_", " ").title()


def _mean_or_none(values: Iterable[Optional[float]]) -> float | None:
    cleaned = [float(value) for value in values if value is not None]
    return round(mean(cleaned), 3) if cleaned else None


def _rate(records: List[Dict[str, Any]], predicate) -> float | None:
    if not records:
        return None
    return round(sum(1 for record in records if predicate(record)) / len(records), 3)


def _status_counts(records: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for record in records:
        status = str((record.get("metrics") or {}).get("analysis_status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _tool_usage_map(agent_result: Dict[str, Any]) -> Dict[str, int]:
    raw = ((agent_result.get("tool_usage") or {}).get("by_tool_name") or {})
    usage: Dict[str, int] = {}
    for key, value in raw.items():
        try:
            usage[str(key)] = int(value)
        except Exception:
            continue
    return usage


def _target_tool_metrics(target_tools: List[str], agent_result: Dict[str, Any]) -> Dict[str, Any]:
    usage = _tool_usage_map(agent_result)
    normalized_usage = {tool.lower(): count for tool, count in usage.items()}
    matched = [tool for tool in target_tools if tool.lower() in normalized_usage]
    return {
        "expected_target_tool_count": len(target_tools),
        "matched_target_tools": matched,
        "matched_target_tool_count": len(matched),
        "target_tool_hit_rate": round(len(matched) / len(target_tools), 6) if target_tools else None,
        "tool_calls_total": sum(usage.values()),
        "tools_used": sorted(usage.keys()),
    }


def _cost_value(section: Dict[str, Any] | None, key: str) -> float | None:
    if not isinstance(section, dict):
        return None
    value = section.get(key)
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _usage_snapshot(section: Dict[str, Any] | None) -> Dict[str, Any]:
    return coerce_usage_snapshot(section or {})


def _judge_status(judge: Dict[str, Any] | None) -> str:
    if not isinstance(judge, dict) or not judge:
        return "not_run"
    return str(judge.get("status") or ("completed" if judge.get("ok") else "judge_error"))


def _score_for_aggregate(record: Dict[str, Any]) -> float | None:
    metrics = record.get("metrics") or {}
    score = metrics.get("overall_score_0_to_100")
    try:
        if score is not None:
            return float(score)
    except Exception:
        return None
    judge = record.get("judge_result") if isinstance(record.get("judge_result"), dict) else {}
    judge_status = _judge_status(judge)
    if judge_status == "judge_error":
        return 0.0
    return None


def build_sample_record(
    sample_name: str,
    sample_meta: Dict[str, Any],
    task_meta: Dict[str, Any],
    bundle_manifest: Dict[str, Any],
    agent_result: Dict[str, Any],
    judge_result: Dict[str, Any] | None,
    task_timing: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    judge = judge_result or {}
    task_timing = dict(task_timing or {})
    task_id = str(task_meta.get("task_id") or "default_analysis").strip() or "default_analysis"
    task_name = str(task_meta.get("task_name") or task_id).strip() or task_id
    target_tools = [str(item).strip() for item in (task_meta.get("target_tools") or sample_meta.get("target_tools") or []) if str(item).strip()]
    target_tool_metrics = _target_tool_metrics(target_tools, agent_result)
    score = judge.get("overall_score_0_to_100")
    try:
        score_value = float(score) if score is not None else None
    except Exception:
        score_value = None

    agent_cost = agent_result.get("cost_estimate") if isinstance(agent_result.get("cost_estimate"), dict) else {}
    judge_cost = judge.get("cost_estimate") if isinstance(judge.get("cost_estimate"), dict) else {}
    agent_usage = _usage_snapshot((((agent_result.get("model_usage") or {}) if isinstance(agent_result.get("model_usage"), dict) else {}) or {}).get("totals"))
    judge_usage = _usage_snapshot(judge.get("usage"))
    total_usage = add_usage_snapshots(agent_usage, judge_usage)
    agent_relative_cost = _cost_value(agent_cost, "relative_cost_index")
    judge_relative_cost = _cost_value(judge_cost, "relative_cost_index")
    agent_usd = _cost_value(agent_cost, "estimated_cost_usd")
    judge_usd = _cost_value(judge_cost, "estimated_cost_usd")

    metrics = {
        "analysis_ok": bool(agent_result.get("ok")),
        "analysis_status": str(agent_result.get("status") or ("completed" if agent_result.get("ok") else "analysis_error")),
        "produced_result": bool(agent_result.get("produced_result")),
        "accepted_final_output": bool(agent_result.get("accepted_final_output")),
        "validator_blocked": str(agent_result.get("status") or "") == "validator_blocked",
        "failure_reason": str(agent_result.get("failure_reason") or agent_result.get("error") or ""),
        "validator_review_level": str(agent_result.get("validator_review_level") or "default"),
        "validation_attempts": int((((agent_result.get("validation") or {}) if isinstance(agent_result.get("validation"), dict) else {}) or {}).get("retry_count") or 0),
        "validation_max_retries": int((((agent_result.get("validation") or {}) if isinstance(agent_result.get("validation"), dict) else {}) or {}).get("max_retries") or 0),
        "judge_ok": bool(judge.get("ok")),
        "judge_status": _judge_status(judge),
        "judge_failure_reason": str(judge.get("error") or ""),
        "judge_pass": bool(judge.get("pass")),
        "scored_result": score_value is not None,
        "task_success": bool(agent_result.get("produced_result")) and bool(judge.get("pass")),
        "overall_score_0_to_100": score_value,
        "raw_total_score": judge.get("raw_total_score"),
        "raw_total_max": judge.get("raw_total_max"),
        "tool_calls_total": target_tool_metrics["tool_calls_total"],
        "tools_used": target_tool_metrics["tools_used"],
        "target_tool_hit_rate": target_tool_metrics["target_tool_hit_rate"],
        "matched_target_tools": target_tool_metrics["matched_target_tools"],
        "expected_target_tool_count": target_tool_metrics["expected_target_tool_count"],
        "matched_target_tool_count": target_tool_metrics["matched_target_tool_count"],
        "agent_input_tokens": int(agent_usage.get("input_tokens") or 0),
        "agent_output_tokens": int(agent_usage.get("output_tokens") or 0),
        "judge_input_tokens": int(judge_usage.get("input_tokens") or 0),
        "judge_output_tokens": int(judge_usage.get("output_tokens") or 0),
        "total_input_tokens": int(total_usage.get("input_tokens") or 0),
        "total_output_tokens": int(total_usage.get("output_tokens") or 0),
        "total_tokens": int(total_usage.get("input_tokens") or 0) + int(total_usage.get("output_tokens") or 0),
        "agent_relative_cost_index": agent_relative_cost,
        "judge_relative_cost_index": judge_relative_cost,
        "total_relative_cost_index": round((agent_relative_cost or 0.0) + (judge_relative_cost or 0.0), 6),
        "agent_estimated_cost_usd": agent_usd,
        "judge_estimated_cost_usd": judge_usd,
        "total_estimated_cost_usd": (
            round((agent_usd or 0.0) + (judge_usd or 0.0), 8)
            if agent_usd is not None and judge_usd is not None
            else None
        ),
        "analysis_duration_sec": (
            float(agent_result.get("duration_sec")) if agent_result.get("duration_sec") is not None else None
        ),
        "judge_duration_sec": float(judge.get("duration_sec")) if judge.get("duration_sec") is not None else None,
        "task_started_at_epoch": (
            float(task_timing.get("started_at_epoch")) if task_timing.get("started_at_epoch") is not None else None
        ),
        "task_finished_at_epoch": (
            float(task_timing.get("finished_at_epoch")) if task_timing.get("finished_at_epoch") is not None else None
        ),
        "task_wall_clock_duration_sec": (
            float(task_timing.get("wall_clock_duration_sec")) if task_timing.get("wall_clock_duration_sec") is not None else None
        ),
    }
    if metrics["analysis_duration_sec"] is not None or metrics["judge_duration_sec"] is not None:
        metrics["total_duration_sec"] = round(
            float(metrics["analysis_duration_sec"] or 0.0) + float(metrics["judge_duration_sec"] or 0.0),
            6,
        )
    else:
        metrics["total_duration_sec"] = None

    return {
        "sample": sample_name,
        "task_id": task_id,
        "task_name": task_name,
        "sample_task_id": sample_task_key(sample_name, task_id),
        "task_query": str(task_meta.get("query") or "").strip(),
        "difficulty": str(sample_meta.get("difficulty") or ""),
        "primary_techniques": list(sample_meta.get("primary_techniques") or []),
        "expected_evidence": list(task_meta.get("expected_evidence") or sample_meta.get("expected_evidence") or []),
        "acceptance_targets": list(task_meta.get("acceptance_targets") or sample_meta.get("acceptance_targets") or []),
        "task_tags": list(task_meta.get("tags") or []),
        "target_tools": target_tools,
        "bundle_manifest": bundle_manifest,
        "agent_result": agent_result,
        "judge_result": judge,
        "metrics": metrics,
    }


def _aggregate_bucket(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    scores = [_score_for_aggregate(record) for record in records]
    successes = [1.0 for record in records if record.get("metrics", {}).get("task_success")]
    judge_passes = [1.0 for record in records if record.get("metrics", {}).get("judge_pass")]
    scored_results = [1.0 for record in records if record.get("metrics", {}).get("scored_result")]
    relative_costs = [record.get("metrics", {}).get("total_relative_cost_index") for record in records]
    total_tokens = [record.get("metrics", {}).get("total_tokens") for record in records]
    tool_calls = [record.get("metrics", {}).get("tool_calls_total") for record in records]
    target_hits = [record.get("metrics", {}).get("target_tool_hit_rate") for record in records]
    analysis_durations = [record.get("metrics", {}).get("analysis_duration_sec") for record in records]
    judge_durations = [record.get("metrics", {}).get("judge_duration_sec") for record in records]
    total_durations = [record.get("metrics", {}).get("total_duration_sec") for record in records]
    task_wall_clock_durations = [
        (
            record.get("metrics", {}).get("task_wall_clock_duration_sec")
            if record.get("metrics", {}).get("task_wall_clock_duration_sec") is not None
            else record.get("metrics", {}).get("total_duration_sec")
        )
        for record in records
    ]
    return {
        "samples": len(records),
        "mean_score": _mean_or_none(scores),
        "task_success_rate": round(len(successes) / len(records), 3) if records else None,
        "judge_pass_rate": round(len(judge_passes) / len(records), 3) if records else None,
        "scored_result_rate": round(len(scored_results) / len(records), 3) if records else None,
        "produced_result_rate": _rate(records, lambda record: bool((record.get("metrics") or {}).get("produced_result"))),
        "validator_blocked_rate": _rate(records, lambda record: str((record.get("metrics") or {}).get("analysis_status") or "") == "validator_blocked"),
        "analysis_failure_rate": _rate(records, lambda record: str((record.get("metrics") or {}).get("analysis_status") or "") == "analysis_error"),
        "judge_error_rate": _rate(records, lambda record: str((record.get("metrics") or {}).get("judge_status") or "") == "judge_error"),
        "mean_relative_cost_index": _mean_or_none(relative_costs),
        "mean_total_tokens": _mean_or_none(total_tokens),
        "mean_tool_calls": _mean_or_none(tool_calls),
        "mean_target_tool_hit_rate": _mean_or_none(target_hits),
        "mean_analysis_duration_sec": _mean_or_none(analysis_durations),
        "mean_judge_duration_sec": _mean_or_none(judge_durations),
        "mean_total_duration_sec": _mean_or_none(total_durations),
        "mean_task_wall_clock_duration_sec": _mean_or_none(task_wall_clock_durations),
        "status_counts": _status_counts(records),
    }


def aggregate_records(run_metadata: Dict[str, Any], records: List[Dict[str, Any]]) -> Dict[str, Any]:
    expected_task_count = int(run_metadata.get("expected_task_count") or len(records) or 0)
    scored = [
        record
        for record in records
        if record.get("metrics", {}).get("scored_result")
    ]
    overall_scores = [_score_for_aggregate(record) for record in records]
    dimension_means: Dict[str, float] = {}
    for name in _rubric_dimension_names():
        values = [
            float((record["judge_result"].get("dimension_scores") or {}).get(name))
            for record in scored
            if (record["judge_result"].get("dimension_scores") or {}).get(name) is not None
        ]
        if values:
            dimension_means[name] = round(mean(values), 3)

    by_difficulty: Dict[str, Dict[str, Any]] = {}
    for record in records:
        difficulty = str(record.get("difficulty") or "unknown")
        bucket = by_difficulty.setdefault(difficulty, {"records": []})
        bucket["records"].append(record)
    for difficulty, bucket in list(by_difficulty.items()):
        by_difficulty[difficulty] = _aggregate_bucket(list(bucket.get("records") or []))

    by_technique: Dict[str, Dict[str, Any]] = {}
    for record in records:
        techniques = list(record.get("primary_techniques") or []) or ["unknown"]
        for technique in techniques:
            bucket = by_technique.setdefault(str(technique), {"records": []})
            bucket["records"].append(record)
    for technique, bucket in list(by_technique.items()):
        by_technique[technique] = _aggregate_bucket(list(bucket.get("records") or []))

    by_task_tag: Dict[str, Dict[str, Any]] = {}
    for record in records:
        tags = list(record.get("task_tags") or []) or ["uncategorized"]
        for tag in tags:
            bucket = by_task_tag.setdefault(str(tag), {"records": []})
            bucket["records"].append(record)
    for tag, bucket in list(by_task_tag.items()):
        by_task_tag[tag] = _aggregate_bucket(list(bucket.get("records") or []))

    return {
        "run_metadata": run_metadata,
        "sample_count": len(records),
        "expected_task_count": expected_task_count,
        "task_completion_rate": round(len(records) / expected_task_count, 3) if expected_task_count else None,
        "judged_count": len(scored),
        "scored_result_rate": round(sum(1 for record in records if record.get("metrics", {}).get("scored_result")) / len(records), 3) if records else None,
        "overall_score_mean": _mean_or_none(overall_scores),
        "task_success_rate": round(sum(1 for record in records if record.get("metrics", {}).get("task_success")) / len(records), 3) if records else None,
        "judge_pass_rate": round(sum(1 for record in records if record.get("metrics", {}).get("judge_pass")) / len(records), 3) if records else None,
        "produced_result_rate": _rate(records, lambda record: bool((record.get("metrics") or {}).get("produced_result"))),
        "validator_blocked_rate": _rate(records, lambda record: str((record.get("metrics") or {}).get("analysis_status") or "") == "validator_blocked"),
        "analysis_failure_rate": _rate(records, lambda record: str((record.get("metrics") or {}).get("analysis_status") or "") == "analysis_error"),
        "judge_error_rate": _rate(records, lambda record: str((record.get("metrics") or {}).get("judge_status") or "") == "judge_error"),
        "status_counts": _status_counts(records),
        "mean_relative_cost_index": _mean_or_none(record.get("metrics", {}).get("total_relative_cost_index") for record in records),
        "mean_total_tokens": _mean_or_none(record.get("metrics", {}).get("total_tokens") for record in records),
        "mean_tool_calls": _mean_or_none(record.get("metrics", {}).get("tool_calls_total") for record in records),
        "mean_target_tool_hit_rate": _mean_or_none(record.get("metrics", {}).get("target_tool_hit_rate") for record in records),
        "mean_analysis_duration_sec": _mean_or_none(record.get("metrics", {}).get("analysis_duration_sec") for record in records),
        "mean_judge_duration_sec": _mean_or_none(record.get("metrics", {}).get("judge_duration_sec") for record in records),
        "mean_total_duration_sec": _mean_or_none(record.get("metrics", {}).get("total_duration_sec") for record in records),
        "mean_task_wall_clock_duration_sec": _mean_or_none(
            (
                record.get("metrics", {}).get("task_wall_clock_duration_sec")
                if record.get("metrics", {}).get("task_wall_clock_duration_sec") is not None
                else record.get("metrics", {}).get("total_duration_sec")
            )
            for record in records
        ),
        "dimension_means": dimension_means,
        "by_difficulty": by_difficulty,
        "by_technique": by_technique,
        "by_task_tag": by_task_tag,
        "records": records,
    }


def write_summary_csv(path, records: List[Dict[str, Any]], run_metadata: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    dimension_fields = _rubric_dimension_names()
    fieldnames = [
        "run_id",
        "corpus",
        "experiment_id",
        "variant_name",
        "changed_variable",
        "config_lineage_id",
        "sample",
        "task_id",
        "task_name",
        "sample_task_id",
        "difficulty",
        "pipeline",
        "architecture",
        "query_variant",
        "subagent_profile",
        "worker_persona_profile",
        "validator_review_level",
        "tool_profile",
        "model_profile",
        "force_model",
        "judge_model",
        "analysis_status",
        "judge_status",
        "produced_result",
        "scored_result",
        "validator_blocked",
        "failure_reason",
        "judge_failure_reason",
        "overall_score_0_to_100",
        "judge_pass",
        "task_success",
        "raw_total_score",
        "raw_total_max",
        "tool_calls_total",
        "target_tool_hit_rate",
        "total_tokens",
        "total_relative_cost_index",
        "analysis_duration_sec",
        "judge_duration_sec",
        "total_duration_sec",
        "task_wall_clock_duration_sec",
        "tools_used",
    ]
    insert_index = fieldnames.index("tool_calls_total")
    fieldnames[insert_index:insert_index] = dimension_fields
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            judge = record.get("judge_result") or {}
            dims = judge.get("dimension_scores") or {}
            metrics = record.get("metrics") or {}
            row = {
                "run_id": run_metadata.get("run_id", ""),
                "corpus": run_metadata.get("corpus", ""),
                "experiment_id": run_metadata.get("experiment_id", ""),
                "variant_name": run_metadata.get("variant_name", ""),
                "changed_variable": run_metadata.get("changed_variable", ""),
                "config_lineage_id": run_metadata.get("config_lineage_id", ""),
                "sample": record.get("sample", ""),
                "task_id": record.get("task_id", ""),
                "task_name": record.get("task_name", ""),
                "sample_task_id": record.get("sample_task_id", ""),
                "difficulty": record.get("difficulty", ""),
                "pipeline": run_metadata.get("pipeline", ""),
                "architecture": run_metadata.get("architecture", ""),
                "query_variant": run_metadata.get("query_variant", ""),
                "subagent_profile": run_metadata.get("subagent_profile", ""),
                "worker_persona_profile": run_metadata.get("worker_persona_profile", ""),
                "validator_review_level": run_metadata.get("validator_review_level", ""),
                "tool_profile": run_metadata.get("tool_profile", ""),
                "model_profile": run_metadata.get("model_profile", ""),
                "force_model": run_metadata.get("force_model", ""),
                "judge_model": judge.get("judge_model", ""),
                "analysis_status": metrics.get("analysis_status", ""),
                "judge_status": metrics.get("judge_status", ""),
                "produced_result": metrics.get("produced_result", ""),
                "scored_result": metrics.get("scored_result", ""),
                "validator_blocked": metrics.get("validator_blocked", ""),
                "failure_reason": metrics.get("failure_reason", ""),
                "judge_failure_reason": metrics.get("judge_failure_reason", ""),
                "overall_score_0_to_100": metrics.get("overall_score_0_to_100", ""),
                "judge_pass": metrics.get("judge_pass", ""),
                "task_success": metrics.get("task_success", ""),
                "raw_total_score": metrics.get("raw_total_score", ""),
                "raw_total_max": metrics.get("raw_total_max", ""),
                "tool_calls_total": metrics.get("tool_calls_total", ""),
                "target_tool_hit_rate": metrics.get("target_tool_hit_rate", ""),
                "total_tokens": metrics.get("total_tokens", ""),
                "total_relative_cost_index": metrics.get("total_relative_cost_index", ""),
                "analysis_duration_sec": metrics.get("analysis_duration_sec", ""),
                "judge_duration_sec": metrics.get("judge_duration_sec", ""),
                "total_duration_sec": metrics.get("total_duration_sec", ""),
                "task_wall_clock_duration_sec": metrics.get("task_wall_clock_duration_sec", ""),
                "tools_used": ",".join(metrics.get("tools_used") or []),
            }
            for name in dimension_fields:
                row[name] = dims.get(name, "")
            writer.writerow(row)


def _dim_label_cell(name: str, judge: Dict[str, Any]) -> str:
    """
    Return the labelled score string for a dimension from a judge result dict.

    Prefers the pre-built ``dimension_score_labels`` entry (e.g. "Mostly
    evidenced (4/5)") produced by the judge at scoring time.  Falls back to the
    raw numeric score when the label is absent (e.g. results from an older run).
    """
    labels = judge.get("dimension_score_labels") or {}
    if labels.get(name):
        return str(labels[name])
    dims = judge.get("dimension_scores") or {}
    score = dims.get(name)
    return str(score) if score is not None else ""


def write_markdown_report(path, aggregate: Dict[str, Any]) -> None:
    lines: List[str] = []
    run_metadata = aggregate.get("run_metadata") or {}
    dimension_fields = _rubric_dimensions()
    lines.append("# Evaluation Report")
    lines.append("")
    lines.append(f"- Run ID: `{run_metadata.get('run_id', '')}`")
    lines.append(f"- Corpus: `{run_metadata.get('corpus', '')}`")
    lines.append(f"- Config lineage ID: `{run_metadata.get('config_lineage_id', '')}`")
    lines.append(f"- Pipeline: `{run_metadata.get('pipeline', '')}`")
    lines.append(f"- Architecture: `{run_metadata.get('architecture', '')}`")
    lines.append(f"- Query variant: `{run_metadata.get('query_variant', '')}`")
    lines.append(f"- Subagent profile: `{run_metadata.get('subagent_profile', '')}`")
    lines.append(f"- Worker persona profile: `{run_metadata.get('worker_persona_profile', '')}`")
    lines.append(f"- Tool profile: `{run_metadata.get('tool_profile', '')}`")
    lines.append(f"- Forced model: `{run_metadata.get('force_model', '')}`")
    lines.append(f"- Judge mode: `{run_metadata.get('judge_mode', '')}`")
    lines.append(f"- Validator review level: `{run_metadata.get('validator_review_level', '')}`")
    lines.append(f"- Model profile: `{run_metadata.get('model_profile', '')}`")
    lines.append("")
    lines.append("## Aggregate")
    lines.append("")
    lines.append(f"- Samples: `{aggregate.get('sample_count', 0)}`")
    lines.append(f"- Judged: `{aggregate.get('judged_count', 0)}`")
    lines.append(f"- Mean score: `{aggregate.get('overall_score_mean')}`")
    lines.append(f"- Task success rate: `{aggregate.get('task_success_rate')}`")
    lines.append(f"- Judge pass rate: `{aggregate.get('judge_pass_rate')}`")
    lines.append(f"- Scored result rate: `{aggregate.get('scored_result_rate')}`")
    lines.append(f"- Produced result rate: `{aggregate.get('produced_result_rate')}`")
    lines.append(f"- Validator blocked rate: `{aggregate.get('validator_blocked_rate')}`")
    lines.append(f"- Analysis failure rate: `{aggregate.get('analysis_failure_rate')}`")
    lines.append(f"- Judge error rate: `{aggregate.get('judge_error_rate')}`")
    lines.append(f"- Mean relative cost index: `{aggregate.get('mean_relative_cost_index')}`")
    lines.append(f"- Mean total tokens: `{aggregate.get('mean_total_tokens')}`")
    lines.append(f"- Mean tool calls: `{aggregate.get('mean_tool_calls')}`")
    lines.append(f"- Mean analysis duration (s): `{aggregate.get('mean_analysis_duration_sec')}`")
    lines.append(f"- Mean judge duration (s): `{aggregate.get('mean_judge_duration_sec')}`")
    lines.append(f"- Mean recorded task duration (s): `{aggregate.get('mean_total_duration_sec')}`")
    lines.append(f"- Mean wall-clock task duration (s): `{aggregate.get('mean_task_wall_clock_duration_sec')}`")
    lines.append("- Executable/config artifact view: `by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/`")
    lines.append(f"- Status counts: `{aggregate.get('status_counts', {})}`")
    lines.append("")
    lines.append("## Per-Sample-Task Scores")
    lines.append("")
    lines.append("| Sample | Task | Difficulty | Analysis Status | Judge Status | Score | Task Success | Cost Index | Task Duration (s) |")
    lines.append("|---|---|---|---|---|---:|---|---:|---:|")
    for record in aggregate.get("records") or []:
        metrics = record.get("metrics") or {}
        lines.append(
            "| {sample} | {task} | {difficulty} | {status} | {judge_status} | {score} | {success} | {cost} | {duration} |".format(
                sample=record.get("sample", ""),
                task=record.get("task_name", "") or record.get("task_id", ""),
                difficulty=record.get("difficulty", ""),
                status=metrics.get("analysis_status", ""),
                judge_status=metrics.get("judge_status", ""),
                score=metrics.get("overall_score_0_to_100", ""),
                success=metrics.get("task_success", ""),
                cost=metrics.get("total_relative_cost_index", ""),
                duration=metrics.get("task_wall_clock_duration_sec", metrics.get("total_duration_sec", "")),
            )
        )

    # ------------------------------------------------------------------
    # Dimension Scores — labelled table
    # Shows "Label (score/max)" per dimension so the reader can interpret
    # each score without consulting the rubric separately.
    # Falls back to raw numeric scores for results that pre-date labels.
    # ------------------------------------------------------------------
    records_with_judge = [
        record for record in (aggregate.get("records") or [])
        if isinstance(record.get("judge_result"), dict)
        and (
            record["judge_result"].get("dimension_score_labels")
            or record["judge_result"].get("dimension_scores")
        )
    ]
    if records_with_judge:
        lines.append("")
        lines.append("## Dimension Scores")
        lines.append("")
        header = ["Sample", "Task"] + [_rubric_dimension_label(dim) for dim in dimension_fields]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join(["---"] * len(header)) + "|")
        for record in records_with_judge:
            judge = record.get("judge_result") or {}
            row = [
                str(record.get("sample", "")),
                str(record.get("task_name", "") or record.get("task_id", "")),
            ]
            row.extend(_dim_label_cell(str(dim.get("name") or ""), judge) for dim in dimension_fields)
            lines.append("| " + " | ".join(row) + " |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
