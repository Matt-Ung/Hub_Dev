"""
File: budgeting.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Resolve budget guardrails and evaluate projected run or experiment cost
  against them.

Summary:
  This module turns declarative budget config into normalized launch-time
  ceilings, combines them with usage snapshots or heuristic projections, and
  reports whether a run or experiment remains within the configured bounds.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .costing import add_usage_snapshots, coerce_usage_snapshot
from .paths import CONFIG_ROOT, read_json

_BUDGET_LIMIT_KEYS = (
    "max_run_input_tokens",
    "max_run_output_tokens",
    "max_run_total_tokens",
    "max_run_relative_cost_index",
    "max_run_estimated_cost_usd",
    "hard_max_run_estimated_cost_usd",
    "max_experiment_relative_cost_index",
    "max_experiment_estimated_cost_usd",
    "hard_max_experiment_estimated_cost_usd",
)

_BUDGET_ABORT_KEYS = (
    "abort_on_run_budget_exceeded",
    "abort_experiment_on_budget_exceeded",
)


def load_budget_guardrails() -> Dict[str, Any]:
    path = CONFIG_ROOT / "budget_guardrails.json"
    if not path.exists():
        return {"version": "budget_guardrails_v1", "defaults": {}}
    return read_json(path)


def resolve_budget_config(
    *,
    enable_budget_guardrails: bool = False,
    max_run_input_tokens: int | None = None,
    max_run_output_tokens: int | None = None,
    max_run_total_tokens: int | None = None,
    max_run_relative_cost_index: float | None = None,
    max_run_estimated_cost_usd: float | None = None,
    hard_max_run_estimated_cost_usd: float | None = None,
    max_experiment_relative_cost_index: float | None = None,
    max_experiment_estimated_cost_usd: float | None = None,
    hard_max_experiment_estimated_cost_usd: float | None = None,
) -> Dict[str, Any]:
    raw = load_budget_guardrails()
    defaults = dict((raw.get("defaults") if isinstance(raw.get("defaults"), dict) else {}) or {})
    overrides = {
        "max_run_input_tokens": max_run_input_tokens,
        "max_run_output_tokens": max_run_output_tokens,
        "max_run_total_tokens": max_run_total_tokens,
        "max_run_relative_cost_index": max_run_relative_cost_index,
        "max_run_estimated_cost_usd": max_run_estimated_cost_usd,
        "hard_max_run_estimated_cost_usd": hard_max_run_estimated_cost_usd,
        "max_experiment_relative_cost_index": max_experiment_relative_cost_index,
        "max_experiment_estimated_cost_usd": max_experiment_estimated_cost_usd,
        "hard_max_experiment_estimated_cost_usd": hard_max_experiment_estimated_cost_usd,
    }
    for key, value in overrides.items():
        if value is not None:
            defaults[key] = value
    defaults["budget_guardrails_enabled"] = bool(enable_budget_guardrails)
    if not enable_budget_guardrails:
        for key in _BUDGET_LIMIT_KEYS:
            defaults[key] = None
        for key in _BUDGET_ABORT_KEYS:
            defaults[key] = False
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


def _budget_rule_specs(scope: str) -> List[tuple[str, str, str]]:
    if scope == "run":
        return [
            ("max_run_input_tokens", "input_tokens", "hard"),
            ("max_run_output_tokens", "output_tokens", "hard"),
            ("max_run_total_tokens", "total_tokens", "hard"),
            ("max_run_relative_cost_index", "relative_cost_index", "hard"),
            ("max_run_estimated_cost_usd", "estimated_cost_usd", "warning"),
            ("hard_max_run_estimated_cost_usd", "estimated_cost_usd", "hard"),
        ]
    if scope == "experiment":
        return [
            ("max_experiment_relative_cost_index", "relative_cost_index", "hard"),
            ("max_experiment_estimated_cost_usd", "estimated_cost_usd", "warning"),
            ("hard_max_experiment_estimated_cost_usd", "estimated_cost_usd", "hard"),
        ]
    raise ValueError(f"Unsupported budget scope {scope!r}")


def evaluate_budget_status(summary: Dict[str, Any], config: Dict[str, Any], *, scope: str) -> Dict[str, Any]:
    observed = {
        "input_tokens": _int_or_none(summary.get("input_tokens")),
        "output_tokens": _int_or_none(summary.get("output_tokens")),
        "total_tokens": _int_or_none(summary.get("total_tokens")),
        "relative_cost_index": _float_or_none(summary.get("relative_cost_index")),
        "estimated_cost_usd": _float_or_none(summary.get("estimated_cost_usd")),
    }
    hard_exceeded: List[str] = []
    warnings: List[str] = []
    for key, observed_key, severity in _budget_rule_specs(scope):
        observed_value = observed.get(observed_key)
        if observed_value is None:
            continue
        limit = config.get(key)
        if limit is None:
            continue
        try:
            if float(observed_value) > float(limit):
                message = f"{key}: observed={observed_value} limit={limit}"
                if severity == "warning":
                    warnings.append(message)
                else:
                    hard_exceeded.append(message)
        except Exception:
            continue
    return {
        "scope": scope,
        "ok": not hard_exceeded,
        "warnings_ok": not warnings,
        "exceeded": hard_exceeded,
        "hard_exceeded": hard_exceeded,
        "warnings": warnings,
        "all_exceeded": [*hard_exceeded, *warnings],
        "observed": observed,
        "limits": {
            key: config.get(key)
            for key in (
                "max_run_input_tokens",
                "max_run_output_tokens",
                "max_run_total_tokens",
                "max_run_relative_cost_index",
                "max_run_estimated_cost_usd",
                "hard_max_run_estimated_cost_usd",
                "max_experiment_relative_cost_index",
                "max_experiment_estimated_cost_usd",
                "hard_max_experiment_estimated_cost_usd",
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
    hard_exceeded: List[str] = []
    warnings: List[str] = []
    projected_relative = _float_or_none(projection.get("projected_relative_cost_index"))
    projected_usd = _float_or_none(projection.get("projected_estimated_cost_usd"))
    rel_limit = _float_or_none(config.get("max_experiment_relative_cost_index"))
    advisory_usd_limit = _float_or_none(config.get("max_experiment_estimated_cost_usd"))
    hard_usd_limit = _float_or_none(config.get("hard_max_experiment_estimated_cost_usd"))
    if projected_relative is not None and rel_limit is not None and projected_relative > rel_limit:
        hard_exceeded.append(f"projected_relative_cost_index: projected={projected_relative} limit={rel_limit}")
    if projected_usd is not None and advisory_usd_limit is not None and projected_usd > advisory_usd_limit:
        warnings.append(f"projected_estimated_cost_usd: projected={projected_usd} limit={advisory_usd_limit}")
    if projected_usd is not None and hard_usd_limit is not None and projected_usd > hard_usd_limit:
        hard_exceeded.append(f"hard_projected_estimated_cost_usd: projected={projected_usd} limit={hard_usd_limit}")
    return {
        "ok": not hard_exceeded,
        "warnings_ok": not warnings,
        "exceeded": hard_exceeded,
        "hard_exceeded": hard_exceeded,
        "warnings": warnings,
        "all_exceeded": [*hard_exceeded, *warnings],
        "projection": projection,
    }
