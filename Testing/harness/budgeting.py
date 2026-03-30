from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .costing import add_usage_snapshots, coerce_usage_snapshot
from .paths import CONFIG_ROOT, read_json


def load_budget_guardrails() -> Dict[str, Any]:
    path = CONFIG_ROOT / "budget_guardrails.json"
    if not path.exists():
        return {"version": "budget_guardrails_v1", "defaults": {}}
    return read_json(path)


def resolve_budget_config(
    *,
    max_run_input_tokens: int | None = None,
    max_run_output_tokens: int | None = None,
    max_run_total_tokens: int | None = None,
    max_run_relative_cost_index: float | None = None,
    max_run_estimated_cost_usd: float | None = None,
    max_experiment_relative_cost_index: float | None = None,
    max_experiment_estimated_cost_usd: float | None = None,
) -> Dict[str, Any]:
    raw = load_budget_guardrails()
    defaults = dict((raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}) or {})
    overrides = {
        "max_run_input_tokens": max_run_input_tokens,
        "max_run_output_tokens": max_run_output_tokens,
        "max_run_total_tokens": max_run_total_tokens,
        "max_run_relative_cost_index": max_run_relative_cost_index,
        "max_run_estimated_cost_usd": max_run_estimated_cost_usd,
        "max_experiment_relative_cost_index": max_experiment_relative_cost_index,
        "max_experiment_estimated_cost_usd": max_experiment_estimated_cost_usd,
    }
    for key, value in overrides.items():
        if value is not None:
            defaults[key] = value
    return defaults


def _float_or_none(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _usage_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    agent_usage = {}
    judge_usage = {}
    if isinstance(record.get("agent_result"), dict):
        model_usage = record["agent_result"].get("model_usage")
        if isinstance(model_usage, dict):
            agent_usage = model_usage.get("totals") or {}
    if isinstance(record.get("judge_result"), dict):
        judge_usage = record["judge_result"].get("usage") or {}
    return add_usage_snapshots(agent_usage, judge_usage)


def summarize_record_budget(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    usage_total = coerce_usage_snapshot({})
    relative_cost = 0.0
    estimated_cost_usd = 0.0
    usd_complete = True
    for record in records:
        usage_total = add_usage_snapshots(usage_total, _usage_from_record(record))
        metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
        rel = _float_or_none(metrics.get("total_relative_cost_index"))
        if rel is not None:
            relative_cost += rel
        usd = _float_or_none(metrics.get("total_estimated_cost_usd"))
        if usd is None:
            usd_complete = False
        else:
            estimated_cost_usd += usd
    total_tokens = int(usage_total.get("input_tokens") or 0) + int(usage_total.get("output_tokens") or 0)
    return {
        "usage": usage_total,
        "input_tokens": int(usage_total.get("input_tokens") or 0),
        "output_tokens": int(usage_total.get("output_tokens") or 0),
        "total_tokens": total_tokens,
        "relative_cost_index": round(relative_cost, 6),
        "estimated_cost_usd": round(estimated_cost_usd, 8) if usd_complete else None,
    }


def evaluate_budget_status(summary: Dict[str, Any], config: Dict[str, Any], *, scope: str) -> Dict[str, Any]:
    exceeded: List[str] = []
    observed = {
        "input_tokens": _int_or_none(summary.get("input_tokens")),
        "output_tokens": _int_or_none(summary.get("output_tokens")),
        "total_tokens": _int_or_none(summary.get("total_tokens")),
        "relative_cost_index": _float_or_none(summary.get("relative_cost_index")),
        "estimated_cost_usd": _float_or_none(summary.get("estimated_cost_usd")),
    }
    checks = {
        "max_run_input_tokens" if scope == "run" else None: observed["input_tokens"],
        "max_run_output_tokens" if scope == "run" else None: observed["output_tokens"],
        "max_run_total_tokens" if scope == "run" else None: observed["total_tokens"],
        "max_run_relative_cost_index" if scope == "run" else None: observed["relative_cost_index"],
        "max_run_estimated_cost_usd" if scope == "run" else None: observed["estimated_cost_usd"],
        "max_experiment_relative_cost_index" if scope == "experiment" else None: observed["relative_cost_index"],
        "max_experiment_estimated_cost_usd" if scope == "experiment" else None: observed["estimated_cost_usd"],
    }
    for key, observed_value in checks.items():
        if not key or observed_value is None:
            continue
        limit = config.get(key)
        if limit is None:
            continue
        try:
            if float(observed_value) > float(limit):
                exceeded.append(f"{key}: observed={observed_value} limit={limit}")
        except Exception:
            continue
    return {
        "scope": scope,
        "ok": not exceeded,
        "exceeded": exceeded,
        "observed": observed,
        "limits": {
            key: config.get(key)
            for key in (
                "max_run_input_tokens",
                "max_run_output_tokens",
                "max_run_total_tokens",
                "max_run_relative_cost_index",
                "max_run_estimated_cost_usd",
                "max_experiment_relative_cost_index",
                "max_experiment_estimated_cost_usd",
            )
            if config.get(key) is not None
        },
    }


def project_experiment_budget(*, child_runs: int, tasks_per_child_run: int, config: Dict[str, Any]) -> Dict[str, Any]:
    projected_relative_cost_per_sample_task = _float_or_none(config.get("projected_relative_cost_per_sample_task")) or 0.0
    projected_estimated_cost_usd_per_sample_task = _float_or_none(config.get("projected_estimated_cost_usd_per_sample_task"))
    sample_task_runs = max(0, int(child_runs)) * max(0, int(tasks_per_child_run))
    projected_relative = round(sample_task_runs * projected_relative_cost_per_sample_task, 6)
    projected_usd = (
        round(sample_task_runs * projected_estimated_cost_usd_per_sample_task, 8)
        if projected_estimated_cost_usd_per_sample_task is not None
        else None
    )
    return {
        "child_runs": int(child_runs),
        "tasks_per_child_run": int(tasks_per_child_run),
        "sample_task_runs": sample_task_runs,
        "projected_relative_cost_index": projected_relative,
        "projected_estimated_cost_usd": projected_usd,
        "heuristics": {
            "projected_relative_cost_per_sample_task": projected_relative_cost_per_sample_task,
            "projected_estimated_cost_usd_per_sample_task": projected_estimated_cost_usd_per_sample_task,
        },
    }


def evaluate_projected_experiment_budget(projection: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    exceeded: List[str] = []
    projected_relative = _float_or_none(projection.get("projected_relative_cost_index"))
    projected_usd = _float_or_none(projection.get("projected_estimated_cost_usd"))
    rel_limit = _float_or_none(config.get("max_experiment_relative_cost_index"))
    usd_limit = _float_or_none(config.get("max_experiment_estimated_cost_usd"))
    if projected_relative is not None and rel_limit is not None and projected_relative > rel_limit:
        exceeded.append(f"projected_relative_cost_index: projected={projected_relative} limit={rel_limit}")
    if projected_usd is not None and usd_limit is not None and projected_usd > usd_limit:
        exceeded.append(f"projected_estimated_cost_usd: projected={projected_usd} limit={usd_limit}")
    return {
        "ok": not exceeded,
        "exceeded": exceeded,
        "projection": projection,
    }
