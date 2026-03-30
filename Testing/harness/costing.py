from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .paths import CONFIG_ROOT, read_json


_USAGE_KEYS = (
    "requests",
    "tool_calls",
    "input_tokens",
    "cache_write_tokens",
    "cache_read_tokens",
    "input_audio_tokens",
    "cache_audio_read_tokens",
    "output_tokens",
)


def empty_usage_snapshot() -> Dict[str, Any]:
    return {**{key: 0 for key in _USAGE_KEYS}, "details": {}}


def coerce_usage_snapshot(raw: Any) -> Dict[str, Any]:
    snapshot = empty_usage_snapshot()
    if isinstance(raw, dict):
        source = raw
    else:
        source = {}
        for key in _USAGE_KEYS:
            source[key] = getattr(raw, key, 0)
        source["details"] = getattr(raw, "details", {})

    for key in _USAGE_KEYS:
        try:
            snapshot[key] = int(source.get(key) or 0)
        except Exception:
            snapshot[key] = 0

    details = source.get("details")
    if isinstance(details, dict):
        normalized: Dict[str, int] = {}
        for key, value in details.items():
            try:
                normalized[str(key)] = int(value)
            except Exception:
                continue
        snapshot["details"] = normalized
    return snapshot


def add_usage_snapshots(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    out = coerce_usage_snapshot(left)
    rhs = coerce_usage_snapshot(right)
    for key in _USAGE_KEYS:
        out[key] = int(out.get(key) or 0) + int(rhs.get(key) or 0)
    details = dict(out.get("details") or {})
    for key, value in (rhs.get("details") or {}).items():
        details[str(key)] = int(details.get(str(key), 0) or 0) + int(value or 0)
    out["details"] = details
    return out


def merge_usage_snapshots(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    total = empty_usage_snapshot()
    for item in items:
        total = add_usage_snapshots(total, item)
    return total


def load_model_cost_profiles() -> Dict[str, Any]:
    return read_json(CONFIG_ROOT / "model_cost_profiles.json")


def estimate_usage_cost(usage: Dict[str, Any], model_id: str, profiles: Dict[str, Any] | None = None) -> Dict[str, Any]:
    usage_snapshot = coerce_usage_snapshot(usage)
    profiles = profiles or load_model_cost_profiles()
    model_profiles = profiles.get("models") if isinstance(profiles.get("models"), dict) else {}
    fallback = profiles.get("fallback") if isinstance(profiles.get("fallback"), dict) else {}
    selected = model_profiles.get(str(model_id or "").strip()) or fallback

    rel_in = float(selected.get("relative_input_cost_per_1k") or 1.0)
    rel_out = float(selected.get("relative_output_cost_per_1k") or 1.0)

    input_tokens = int(usage_snapshot.get("input_tokens") or 0)
    cache_write_tokens = int(usage_snapshot.get("cache_write_tokens") or 0)
    cache_read_tokens = int(usage_snapshot.get("cache_read_tokens") or 0)
    output_tokens = int(usage_snapshot.get("output_tokens") or 0)

    relative_cost_index = round(
        ((input_tokens + cache_write_tokens + cache_read_tokens) / 1000.0) * rel_in
        + (output_tokens / 1000.0) * rel_out,
        6,
    )

    usd_estimate = None
    input_usd_per_1m = selected.get("usd_input_per_1m_tokens")
    output_usd_per_1m = selected.get("usd_output_per_1m_tokens")
    if input_usd_per_1m is not None and output_usd_per_1m is not None:
        usd_estimate = round(
            ((input_tokens + cache_write_tokens + cache_read_tokens) / 1_000_000.0) * float(input_usd_per_1m)
            + (output_tokens / 1_000_000.0) * float(output_usd_per_1m),
            8,
        )

    return {
        "model_id": str(model_id or ""),
        "usage": usage_snapshot,
        "relative_cost_index": relative_cost_index,
        "estimated_cost_usd": usd_estimate,
    }


def estimate_event_costs(events: List[Dict[str, Any]], profiles: Dict[str, Any] | None = None) -> Dict[str, Any]:
    profiles = profiles or load_model_cost_profiles()
    by_model: Dict[str, Dict[str, Any]] = {}
    for event in events or []:
        model_id = str(event.get("model") or "").strip() or "unknown"
        usage_snapshot = coerce_usage_snapshot(event.get("usage") or {})
        bucket = by_model.setdefault(model_id, empty_usage_snapshot())
        by_model[model_id] = add_usage_snapshots(bucket, usage_snapshot)

    models: List[Dict[str, Any]] = []
    relative_total = 0.0
    usd_total = 0.0
    usd_complete = True
    for model_id, usage_snapshot in sorted(by_model.items()):
        estimate = estimate_usage_cost(usage_snapshot, model_id, profiles=profiles)
        models.append(estimate)
        relative_total += float(estimate.get("relative_cost_index") or 0.0)
        if estimate.get("estimated_cost_usd") is None:
            usd_complete = False
        else:
            usd_total += float(estimate.get("estimated_cost_usd") or 0.0)

    return {
        "models": models,
        "usage_totals": merge_usage_snapshots(item.get("usage") or {} for item in models),
        "relative_cost_index": round(relative_total, 6),
        "estimated_cost_usd": round(usd_total, 8) if usd_complete and models else None,
    }
