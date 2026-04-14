"""
File: pipeline.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Execute the configured multi-agent workflow one stage at a time.

Summary:
  This module implements the runtime execution engine for the workflow system.
  It coordinates stage transitions, parses planner and validator outputs,
  schedules host-managed worker assignments, merges worker results, and
  produces the final report returned to the app and testing harness.
"""

import asyncio
from datetime import datetime
import hashlib
import html
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from pydantic_ai import ModelMessage
try:
    from pydantic_ai.usage import UsageLimits
except Exception:  # pragma: no cover - lightweight test stubs may not expose submodules
    class UsageLimits:  # type: ignore[override]
        def __init__(self, *, request_limit: int | None = None, **_: Any) -> None:
            self.request_limit = request_limit

from .config import (
    DEEP_AGENT_REQUEST_LIMIT,
    DEFAULT_SHELL_EXECUTION_MODE,
    HOST_PARALLEL_WORKER_EXECUTION,
    GHIDRA_CHANGE_PROPOSALS_END,
    GHIDRA_CHANGE_PROPOSALS_START,
    MAX_PARALLEL_WORKERS,
    MAX_VALIDATION_REPLAN_RETRIES,
    PLANNER_WORK_ITEMS_END,
    PLANNER_WORK_ITEMS_START,
    SERIAL_HOST_WORKER_ARCHETYPES,
    VALIDATION_DECISION_END,
    VALIDATION_DECISION_START,
    YARA_RULE_PROPOSALS_END,
    YARA_RULE_PROPOSALS_START,
    get_stage_kind_metadata,
    stage_kind_flag,
    _normalize_shell_execution_mode,
    _normalize_validator_review_level,
)
from .runtime import (
    MultiAgentRuntime,
    _ACTIVE_PIPELINE_STAGE,
    _ACTIVE_PIPELINE_STATE,
    _enter_mcp_toolsets_async,
    _LIVE_TOOL_LOG_STATE,
    _direct_mcp_tool_call_sync,
    _find_mcp_server_by_marker,
    _parse_jsonish_tool_result,
    _close_mcp_toolsets_async,
    build_host_worker_assignment_executor,
    build_loop_local_host_worker_runtime,
    build_stage_prompt,
    expand_architecture_slots,
    expand_architecture_names,
    normalize_ghidra_change_proposal,
    prepare_ghidra_change_operation,
    run_deterministic_presweeps_sync,
)
from .shared_state import (
    _append_tool_log_entries,
    _annotate_unapproved_ghidra_aliases,
    _empty_parent_input,
    _make_parent_input_callback,
    _new_shared_state,
    _sanitize_user_facing_output,
    _store_ui_snapshot,
    append_status,
    append_tool_log_delta,
    compact_shared_state,
    get_role_history,
    set_role_history,
    update_validated_sample_path,
    update_validated_sample_path_from_messages,
)


class PipelineCancelled(RuntimeError):
    pass


_GENERIC_YARA_STRINGS = {
    "this program cannot be run in dos mode",
    ".text",
    ".rdata",
    ".data",
    "rich",
    "mz",
    "pe",
    "error",
    "help",
}

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

_ASYNC_TASK_MANAGEMENT_TOOL_NAMES = (
    "check_task",
    "wait_tasks",
    "list_active_tasks",
    "answer_subagent",
)
_STAGE_MAX_TRANSIENT_RETRIES = 2
_STAGE_RETRY_BACKOFF_SECONDS = (1.0, 3.0)
_HOST_WORKER_MAX_TRANSIENT_RETRIES = 2
_HOST_WORKER_RETRY_BACKOFF_SECONDS = (1.0, 3.0)
_HOST_WORKER_STAGE_FAILED_SUBSET_RETRIES = 1
_HOST_WORKER_STAGE_RETRY_BACKOFF_SECONDS = (2.0,)


def _current_usage_limits() -> UsageLimits | None:
    request_limit = DEEP_AGENT_REQUEST_LIMIT
    if request_limit is None:
        return None
    return UsageLimits(request_limit=int(request_limit))


def _supports_usage_limits_type_error(error: TypeError) -> bool:
    message = str(error or "")
    return "usage_limits" in message and "unexpected keyword" in message


def _stage_agent_run_sync(agent: Any, prompt: str, *, message_history: Any, deps: Any) -> Any:
    usage_limits = _current_usage_limits()
    if usage_limits is None:
        return agent.run_sync(prompt, message_history=message_history, deps=deps)
    try:
        return agent.run_sync(
            prompt,
            message_history=message_history,
            deps=deps,
            usage_limits=usage_limits,
        )
    except TypeError as error:
        if not _supports_usage_limits_type_error(error):
            raise
        return agent.run_sync(prompt, message_history=message_history, deps=deps)


async def _stage_agent_run_async(agent: Any, prompt: str, *, message_history: Any, deps: Any) -> Any:
    usage_limits = _current_usage_limits()
    if usage_limits is None:
        return await agent.run(prompt, message_history=message_history, deps=deps)
    try:
        return await agent.run(
            prompt,
            message_history=message_history,
            deps=deps,
            usage_limits=usage_limits,
        )
    except TypeError as error:
        if not _supports_usage_limits_type_error(error):
            raise
        return await agent.run(prompt, message_history=message_history, deps=deps)
_HOST_WORKER_NON_RETRYABLE_ERROR_MARKERS = (
    "status_code: 400",
    "invalid_request_error",
    "context_length_exceeded",
    "could not parse the json body",
    "input tokens exceed the configured limit",
    "validationerror",
    "unexpectedmodelbehavior",
    "usagelimitexceeded",
    "request_limit of 50",
)
_HOST_WORKER_RETRYABLE_ERROR_MARKERS = (
    "remoteprotocolerror",
    "readerror",
    "peer closed connection",
    "incomplete chunked read",
    "server disconnected",
    "connection reset",
    "connection aborted",
    "apiconnectionerror",
    "connecttimeout",
    "readtimeout",
    "timeout",
    "timed out",
    "429",
    "rate limit",
    "too many requests",
    "ratelimit",
    "internalservererror",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "status_code: 500",
    "status_code: 502",
    "status_code: 503",
    "status_code: 504",
)
_RATE_LIMIT_ERROR_MARKERS = (
    "429",
    "rate limit",
    "too many requests",
    "ratelimit",
)
_TIMEOUT_ERROR_MARKERS = (
    "connecttimeout",
    "readtimeout",
    "timeout",
    "timed out",
    "gateway timeout",
)
_TRANSIENT_TRANSPORT_ERROR_MARKERS = (
    "remoteprotocolerror",
    "readerror",
    "peer closed connection",
    "incomplete chunked read",
    "server disconnected",
    "connection reset",
    "connection aborted",
    "apiconnectionerror",
    "service unavailable",
    "bad gateway",
    "internalservererror",
    "status_code: 500",
    "status_code: 502",
    "status_code: 503",
    "status_code: 504",
)
_INVALID_REQUEST_ERROR_MARKERS = (
    "status_code: 400",
    "invalid_request_error",
)
_INVALID_JSON_BODY_ERROR_MARKERS = (
    "could not parse the json body",
    "json payload",
)
_CONTEXT_LENGTH_ERROR_MARKERS = (
    "context_length_exceeded",
    "input tokens exceed the configured limit",
    "messages resulted in",
)
_USAGE_LIMIT_ERROR_MARKERS = (
    "usagelimitexceeded",
    "request_limit of 50",
)
_CANCELLATION_ERROR_MARKERS = (
    "pipeline canceled by user",
    "pipeline cancelled by user",
    "cancellederror",
    "cancelled by user",
    "canceled by user",
)


def _retry_backoff_sec(retry_index: int, schedule: Tuple[float, ...]) -> float:
    if retry_index < len(schedule):
        return float(schedule[retry_index])
    last = float(schedule[-1])
    growth = 2 ** max(0, retry_index - len(schedule) + 1)
    return float(min(8.0, last * growth))


def _empty_usage_snapshot() -> Dict[str, Any]:
    return {**{key: 0 for key in _USAGE_KEYS}, "details": {}}


def _coerce_usage_snapshot(raw: Any) -> Dict[str, Any]:
    snapshot = _empty_usage_snapshot()
    if raw is None:
        return snapshot
    source = raw if isinstance(raw, dict) else {key: getattr(raw, key, 0) for key in _USAGE_KEYS}
    if not isinstance(raw, dict):
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


def _result_usage_snapshot(result: Any) -> Dict[str, Any]:
    usage_attr = getattr(result, "usage", None)
    usage = usage_attr() if callable(usage_attr) else usage_attr
    return _coerce_usage_snapshot(usage)


def _merge_usage_snapshots(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    merged = _coerce_usage_snapshot(left)
    rhs = _coerce_usage_snapshot(right)
    for key in _USAGE_KEYS:
        merged[key] = int(merged.get(key) or 0) + int(rhs.get(key) or 0)
    details = dict(merged.get("details") or {})
    for key, value in (rhs.get("details") or {}).items():
        details[str(key)] = int(details.get(str(key), 0) or 0) + int(value or 0)
    merged["details"] = details
    return merged


def _record_model_usage(
    state: Dict[str, Any],
    *,
    phase: str,
    stage_name: str,
    model: str,
    usage: Dict[str, Any],
    slot_name: str = "",
    work_item_id: str = "",
) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    usage_snapshot = _coerce_usage_snapshot(usage)
    if not any(int(usage_snapshot.get(key) or 0) for key in _USAGE_KEYS) and not (usage_snapshot.get("details") or {}):
        return
    shared["model_usage_totals"] = _merge_usage_snapshots(shared.get("model_usage_totals") or {}, usage_snapshot)
    stage_bucket = dict((shared.get("model_usage_by_stage") or {}).get(stage_name) or _empty_usage_snapshot())
    stage_bucket = _merge_usage_snapshots(stage_bucket, usage_snapshot)
    shared.setdefault("model_usage_by_stage", {})[stage_name] = stage_bucket
    shared.setdefault("model_usage_events", []).append(
        {
            "phase": str(phase or ""),
            "stage_name": str(stage_name or ""),
            "model": str(model or ""),
            "slot_name": str(slot_name or ""),
            "work_item_id": str(work_item_id or ""),
            "usage": usage_snapshot,
        }
    )


def _error_text(error: Exception | str) -> str:
    if isinstance(error, Exception):
        return f"{type(error).__name__}: {error}"
    return str(error or "").strip()


def _classify_runtime_error(error: Exception | str) -> Dict[str, Any]:
    text = _error_text(error)
    lowered = text.lower()

    category = "unknown"
    retryable = False

    if _is_async_task_management_misuse_error(error):
        category = "async_task_tool_misuse"
    elif any(marker in lowered for marker in _CANCELLATION_ERROR_MARKERS):
        category = "cancelled"
    elif any(marker in lowered for marker in _USAGE_LIMIT_ERROR_MARKERS):
        category = "usage_limit_exceeded"
    elif any(marker in lowered for marker in _CONTEXT_LENGTH_ERROR_MARKERS):
        category = "context_length_exceeded"
    elif any(marker in lowered for marker in _INVALID_REQUEST_ERROR_MARKERS):
        if any(marker in lowered for marker in _INVALID_JSON_BODY_ERROR_MARKERS):
            category = "invalid_request_payload"
            retryable = True
        else:
            category = "invalid_request"
    elif any(marker in lowered for marker in _RATE_LIMIT_ERROR_MARKERS):
        category = "rate_limit"
        retryable = True
    elif any(marker in lowered for marker in _TIMEOUT_ERROR_MARKERS):
        category = "timeout"
        retryable = True
    elif any(marker in lowered for marker in _TRANSIENT_TRANSPORT_ERROR_MARKERS):
        category = "transient_transport"
        retryable = True

    return {
        "error_text": text,
        "category": category,
        "retryable": retryable,
    }


def _is_async_task_management_misuse_error(error: Exception | str) -> bool:
    text = _error_text(error).lower()
    if not any(tool_name in text for tool_name in _ASYNC_TASK_MANAGEMENT_TOOL_NAMES):
        return False
    return any(
        marker in text
        for marker in (
            "exceeded max retries count",
            "validation error for",
            "field required",
            "input_value={}",
        )
    )


def _with_sync_only_retry_guidance(prompt: str) -> str:
    guidance = (
        "Retry correction:\n"
        "- Async task-management tools (`check_task`, `wait_tasks`, `list_active_tasks`, `answer_subagent`) are disabled for this retry.\n"
        "- Do not call them.\n"
        "- Execute synchronously within this stage.\n"
        "- If you need help from a configured subagent, make a normal synchronous delegation and wait for the response before continuing.\n"
    )
    return f"{str(prompt or '').rstrip()}\n\n{guidance}"


def _short_sha256(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", "ignore")).hexdigest()[:12]


def _build_stage_request_fingerprint(
    *,
    stage: Any,
    stage_prompt: str,
    old_history: List[ModelMessage],
    attempt: int,
) -> Dict[str, Any]:
    history_items = list(old_history or [])
    history_serialized = "\n".join(f"{type(item).__name__}:{str(item)}" for item in history_items)
    prompt_text = str(stage_prompt or "")
    model_name = str(
        getattr(stage, "model", "")
        or getattr(getattr(stage, "agent", None), "model_name", "")
        or getattr(getattr(stage, "agent", None), "model", "")
        or ""
    ).strip()
    fingerprint = {
        "stage_name": str(getattr(stage, "name", "") or "").strip(),
        "attempt": int(attempt),
        "model_name": model_name,
        "prompt_chars": len(prompt_text),
        "prompt_sha256": _short_sha256(prompt_text),
        "history_messages": len(history_items),
        "history_chars": len(history_serialized),
        "history_sha256": _short_sha256(history_serialized) if history_serialized else "",
    }
    fingerprint["fingerprint_id"] = _short_sha256(json.dumps(fingerprint, sort_keys=True))
    return fingerprint


def _run_stage_agent_sync_with_guardrails(
    *,
    stage: Any,
    stage_prompt: str,
    old_history: List[ModelMessage],
    state: Dict[str, Any],
) -> Any:
    max_attempts = 1 + max(0, int(_STAGE_MAX_TRANSIENT_RETRIES))
    attempt = 1
    async_misuse_retry_used = False
    shared = state.setdefault("shared_state", {})

    while True:
        request_fingerprint = _build_stage_request_fingerprint(
            stage=stage,
            stage_prompt=stage_prompt,
            old_history=old_history,
            attempt=attempt,
        )
        shared["last_stage_request_fingerprint"] = dict(request_fingerprint)
        try:
            return _stage_agent_run_sync(
                stage.agent,
                stage_prompt,
                message_history=old_history if old_history else None,
                deps=stage.deps,
            )
        except Exception as error:
            classification = _classify_runtime_error(error)
            shared["last_stage_request_fingerprint"] = {
                **dict(request_fingerprint),
                "error_category": str(classification.get("category") or ""),
                "retryable": bool(classification.get("retryable")),
            }
            if classification["category"] == "async_task_tool_misuse" and not async_misuse_retry_used:
                async_misuse_retry_used = True
                append_status(
                    state,
                    (
                        f"Stage retry triggered: {stage.name} attempted async task-management tooling "
                        "without a valid async task context; retrying synchronously without prior history."
                    ),
                )
                retry_result = _stage_agent_run_sync(
                    stage.agent,
                    _with_sync_only_retry_guidance(stage_prompt),
                    message_history=None,
                    deps=stage.deps,
                )
                append_status(
                    state,
                    f"Stage retry recovered: {stage.name} completed after async task-management misuse.",
                )
                return retry_result
            allowed_attempts = max_attempts
            if classification["category"] == "invalid_request_payload":
                # Some malformed-body 400s appear to come from intermittent client
                # request serialization rather than deterministic prompt content.
                # Give them one guarded replay before failing the task.
                allowed_attempts = min(max_attempts, 2)
            if classification["retryable"] and attempt < allowed_attempts and not bool(state.get("cancel_requested")):
                backoff_sec = _retry_backoff_sec(attempt - 1, _STAGE_RETRY_BACKOFF_SECONDS)
                append_status(
                    state,
                    (
                        f"Stage transient failure: {stage.name} attempt {attempt}/{max_attempts} "
                        f"category={classification['category']} request_fp={request_fingerprint['fingerprint_id']} "
                        f"({classification['error_text']}); "
                        f"retrying in {backoff_sec:.1f}s"
                    ),
                )
                time.sleep(backoff_sec)
                attempt += 1
                continue
            raise


def _is_retryable_host_worker_error(error: Exception | str) -> bool:
    lowered = _error_text(error).lower()
    if any(marker in lowered for marker in _HOST_WORKER_NON_RETRYABLE_ERROR_MARKERS):
        return False
    if any(marker in lowered for marker in _HOST_WORKER_RETRYABLE_ERROR_MARKERS):
        return True
    return bool(_classify_runtime_error(error).get("retryable"))


def _host_worker_retry_backoff_sec(retry_index: int) -> float:
    return _retry_backoff_sec(retry_index, _HOST_WORKER_RETRY_BACKOFF_SECONDS)


def _worker_result_retryable(result: Dict[str, Any]) -> bool:
    if bool(result.get("retryable")):
        return True
    return _is_retryable_host_worker_error(str(result.get("error") or ""))


def _host_worker_stage_retry_backoff_sec(retry_index: int) -> float:
    return _retry_backoff_sec(retry_index, _HOST_WORKER_STAGE_RETRY_BACKOFF_SECONDS)


def _extract_yara_section(rule_text: str, section_name: str) -> str:
    pattern = re.compile(
        rf"(?ims)^\s*{re.escape(section_name)}\s*:\s*(.*?)(?=^\s*(?:meta|strings|condition)\s*:|\Z)"
    )
    match = pattern.search(str(rule_text or ""))
    return match.group(1) if match else ""


def _assess_yara_rule_specificity(rule_text: str) -> Tuple[bool, str]:
    text = str(rule_text or "")
    lower = text.lower()
    if "condition:" not in lower:
        return False, "rule is missing a condition section"

    strings_body = _extract_yara_section(text, "strings")
    condition_body = _extract_yara_section(text, "condition").lower()
    quoted_strings = [match.group(1) for match in re.finditer(r'"((?:\\.|[^"\\])*)"', strings_body)]
    hex_patterns = re.findall(r"\{[^}]+\}", strings_body)
    import_calls = re.findall(r"pe\.(?:imports?|imphash)\s*\(", condition_body)

    meaningful_strings = []
    for raw_value in quoted_strings:
        value = raw_value.encode("utf-8", "ignore").decode("unicode_escape", "ignore").strip().lower()
        if len(value) < 5:
            continue
        if value in _GENERIC_YARA_STRINGS:
            continue
        if "dos mode" in value:
            continue
        meaningful_strings.append(value)

    generic_condition_markers = [
        "uint16(0) == 0x5a4d",
        "uint32(0) == 0x464c457f",
        "pe.number_of_sections",
        "pe.entry_point",
        "pe.machine",
    ]
    generic_condition_hits = sum(1 for marker in generic_condition_markers if marker in condition_body)
    signal_count = len(meaningful_strings) + len(hex_patterns) + len(import_calls)

    if signal_count < 2:
        return False, "rule is too generic; expected at least two distinct behavior anchors such as unique strings, hex patterns, or import-based conditions"
    if generic_condition_hits and signal_count <= generic_condition_hits:
        return False, "rule is dominated by generic PE/startup checks rather than sample-specific behavior anchors"
    return True, ""


def _check_cancel_requested(state: Dict[str, Any], *, location: str = "") -> None:
    if bool((state or {}).get("cancel_requested")):
        detail = f" ({location})" if location else ""
        raise PipelineCancelled(f"Pipeline canceled by user{detail}")

def _stage_progress_from_pipeline_definition(
    pipeline_definition: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    progress: List[Dict[str, Any]] = []
    for raw_stage in list(pipeline_definition or []):
        architecture = list(raw_stage.get("architecture") or [])
        progress.append(
            {
                "stage_name": str(raw_stage["name"]),
                "stage_kind": str(raw_stage["stage_kind"]),
                "subagents": expand_architecture_names(architecture),
                "status": "pending",
                "started_at_epoch": None,
                "finished_at_epoch": None,
                "duration_sec": None,
                "error": "",
            }
        )
    return progress


def _seed_pipeline_stage_progress(
    state: Dict[str, Any],
    stages: List[Tuple[str, str, List[str]]],
) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    shared["pipeline_stage_progress"] = [
        {
            "stage_name": stage_name,
            "stage_kind": stage_kind,
            "subagents": list(subagents),
            "status": "pending",
            "started_at_epoch": None,
            "finished_at_epoch": None,
            "duration_sec": None,
            "error": "",
        }
        for stage_name, stage_kind, subagents in stages
    ]


def _set_pipeline_stage_status(
    state: Dict[str, Any],
    stage_name: str,
    *,
    stage_kind: Optional[str] = None,
    subagents: Optional[List[str]] = None,
    status: str,
    error: str = "",
) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    progress = shared.setdefault("pipeline_stage_progress", [])
    entry = next((item for item in progress if item.get("stage_name") == stage_name), None)
    if entry is None:
        entry = {
            "stage_name": stage_name,
            "stage_kind": stage_kind or "",
            "subagents": list(subagents or []),
            "status": "pending",
            "started_at_epoch": None,
            "finished_at_epoch": None,
            "duration_sec": None,
            "error": "",
        }
        progress.append(entry)

    if stage_kind is not None:
        entry["stage_kind"] = stage_kind
    if subagents is not None:
        entry["subagents"] = list(subagents)

    now = time.time()
    entry["status"] = status
    entry["error"] = error or ""

    if status == "running":
        if entry.get("started_at_epoch") is None:
            entry["started_at_epoch"] = now
        entry["finished_at_epoch"] = None
        entry["duration_sec"] = None
        _store_ui_snapshot(state=state)
        return

    if status in {"completed", "failed"}:
        if entry.get("started_at_epoch") is None:
            entry["started_at_epoch"] = now
        entry["finished_at_epoch"] = now
        entry["duration_sec"] = max(0.0, now - float(entry["started_at_epoch"]))
    _store_ui_snapshot(state=state)


def _format_elapsed(seconds: Optional[float]) -> str:
    if seconds is None:
        return "--:--"
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours:d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _strip_optional_json_fence(raw: str) -> str:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def extract_planned_work_items(text: str) -> Tuple[List[Dict[str, Any]], str]:
    payload = ""
    marker_re = re.compile(
        rf"{re.escape(PLANNER_WORK_ITEMS_START)}\s*(.*?)\s*{re.escape(PLANNER_WORK_ITEMS_END)}",
        flags=re.DOTALL,
    )
    marker_match = marker_re.search(text or "")
    if marker_match:
        payload = marker_match.group(1)
    else:
        fenced_json_re = re.compile(r"```json\s*(\[[\s\S]*?\])\s*```", flags=re.IGNORECASE)
        fenced_match = fenced_json_re.search(text or "")
        if fenced_match:
            payload = fenced_match.group(1)
        else:
            return [], "planner output did not include a parseable work-item block"

    payload = _strip_optional_json_fence(payload)
    try:
        parsed = json.loads(payload)
    except Exception as e:
        return [], f"planner work-item JSON parse failed: {type(e).__name__}: {e}"

    if isinstance(parsed, dict):
        parsed = parsed.get("work_items")
    if not isinstance(parsed, list):
        return [], "planner work-item block must decode to a JSON array"

    normalized: List[Dict[str, Any]] = []
    for idx, raw_item in enumerate(parsed, start=1):
        if not isinstance(raw_item, dict):
            continue
        item_id = " ".join(str(raw_item.get("id") or f"W{idx}").split()) or f"W{idx}"
        objective = " ".join(
            str(
                raw_item.get("objective")
                or raw_item.get("title")
                or raw_item.get("description")
                or f"Work item {idx}"
            ).split()
        )

        roles_raw = raw_item.get("recommended_roles") or raw_item.get("roles") or []
        if isinstance(roles_raw, str):
            recommended_roles = [" ".join(roles_raw.split())] if roles_raw.strip() else []
        else:
            recommended_roles = [
                " ".join(str(role).split())
                for role in roles_raw
                if str(role).strip()
            ]

        evidence_raw = raw_item.get("evidence_targets") or raw_item.get("artifacts") or raw_item.get("targets") or []
        if isinstance(evidence_raw, str):
            evidence_targets = [" ".join(evidence_raw.split())] if evidence_raw.strip() else []
        else:
            evidence_targets = [
                " ".join(str(target).split())
                for target in evidence_raw
                if str(target).strip()
            ]

        normalized.append(
            {
                "id": item_id,
                "objective": objective,
                "recommended_roles": recommended_roles,
                "evidence_targets": evidence_targets,
            }
        )

    if not normalized:
        return [], "planner work-item block was present but empty"
    return normalized, ""


def update_planned_work_items_from_planner_output(state: Dict[str, Any], planner_output: str) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    items, error = extract_planned_work_items(planner_output)
    shared["planned_work_items"] = items
    shared["planned_work_item_status"] = {
        str(item.get("id") or ""): {
            "status": "planned",
            "slot_name": "",
            "started_at_epoch": None,
            "finished_at_epoch": None,
            "duration_sec": None,
            "error": "",
        }
        for item in items
        if str(item.get("id") or "").strip()
    }
    shared["planned_work_items_parse_error"] = error
    if items:
        append_status(state, f"Planner work items parsed: {len(items)}")
    elif error:
        append_status(state, f"Planner work-item parse warning: {error}")
    _store_ui_snapshot(state=state)


def _set_planned_work_item_status(
    state: Dict[str, Any],
    work_item_id: str,
    status: str,
    *,
    slot_name: str = "",
    error: str = "",
    started_at_epoch: Optional[float] = None,
    finished_at_epoch: Optional[float] = None,
    duration_sec: Optional[float] = None,
) -> None:
    normalized_id = str(work_item_id or "").strip()
    if not normalized_id:
        return
    shared = state.setdefault("shared_state", _new_shared_state())
    status_map = shared.setdefault("planned_work_item_status", {})
    entry = dict(status_map.get(normalized_id) or {})
    entry["status"] = str(status or "planned").strip() or "planned"
    if slot_name:
        entry["slot_name"] = slot_name
    elif "slot_name" not in entry:
        entry["slot_name"] = ""
    if error or "error" in entry:
        entry["error"] = str(error or "").strip()
    if started_at_epoch is not None:
        entry["started_at_epoch"] = started_at_epoch
    elif "started_at_epoch" not in entry:
        entry["started_at_epoch"] = None
    if finished_at_epoch is not None:
        entry["finished_at_epoch"] = finished_at_epoch
    elif "finished_at_epoch" not in entry:
        entry["finished_at_epoch"] = None
    if duration_sec is not None:
        entry["duration_sec"] = float(duration_sec)
    elif "duration_sec" not in entry:
        entry["duration_sec"] = None
    status_map[normalized_id] = entry
    _store_ui_snapshot(state=state)


def _planned_work_item_badge(status: str) -> Tuple[str, str]:
    normalized = str(status or "").strip().lower()
    if normalized == "blocked":
        return "#a61b29", "blocked"
    if normalized == "completed":
        return "#1b6e3a", "completed"
    if normalized == "in_execution":
        return "#0b57d0", "in execution"
    if normalized == "validated":
        return "#1b6e3a", "validated"
    if normalized == "under_review":
        return "#0b57d0", "under review"
    if normalized == "reporting":
        return "#0b57d0", "reporting"
    if normalized == "drafting":
        return "#0b57d0", "drafting"
    if normalized == "preflight":
        return "#0b57d0", "preflight"
    if normalized == "context_ready":
        return "#5f6368", "context ready"
    return "#5f6368", "planned"


def _display_planned_work_item_status(
    progress: List[Dict[str, Any]],
    item_state: Optional[Dict[str, Any]],
) -> Tuple[str, str]:
    item_status = str((item_state or {}).get("status") or "").strip().lower()
    report_status = _first_progress_status_by_flag(progress, "finalizes_report")
    validation_status = _first_progress_status_by_flag(progress, "runs_validation_gate")
    worker_status = _first_progress_status_by_flag(progress, "supports_parallel_assignments")

    if item_status == "blocked":
        return _planned_work_item_badge("blocked")

    if report_status == "completed":
        return _planned_work_item_badge("completed")
    if report_status == "running" and item_status == "completed":
        return _planned_work_item_badge("reporting")
    if validation_status == "completed" and item_status == "completed":
        return _planned_work_item_badge("validated")
    if validation_status == "running" and item_status == "completed":
        return _planned_work_item_badge("under_review")
    if worker_status == "completed":
        return _planned_work_item_badge("completed")
    if worker_status == "running":
        if item_status in {"completed", "in_execution", "blocked"}:
            return _planned_work_item_badge(item_status)
        return _planned_work_item_badge("planned")

    _, tone, label = _planner_work_item_rollup(progress)
    return tone, label


def extract_ghidra_change_proposals(text: str) -> Tuple[List[Dict[str, Any]], str, bool]:
    payloads: List[str] = []
    marker_re = re.compile(
        rf"{re.escape(GHIDRA_CHANGE_PROPOSALS_START)}\s*(.*?)\s*{re.escape(GHIDRA_CHANGE_PROPOSALS_END)}",
        flags=re.DOTALL,
    )
    for match in marker_re.finditer(text or ""):
        payloads.append(match.group(1))

    if not payloads:
        return [], "", False

    normalized: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    for block_index, payload in enumerate(payloads, start=1):
        payload = _strip_optional_json_fence(payload)
        try:
            parsed = json.loads(payload)
        except Exception as e:
            return [], f"ghidra change JSON parse failed: {type(e).__name__}: {e}", True

        if isinstance(parsed, dict):
            parsed = parsed.get("changes") or parsed.get("proposals") or []
        if not isinstance(parsed, list):
            return [], "ghidra change block must decode to a JSON array", True

        for idx, raw_item in enumerate(parsed, start=1):
            if not isinstance(raw_item, dict):
                continue
            proposal_id = " ".join(str(raw_item.get("id") or f"C{block_index}_{idx}").split()) or f"C{block_index}_{idx}"
            while proposal_id in seen_ids:
                proposal_id = f"{proposal_id}_{idx}"
            seen_ids.add(proposal_id)

            normalized_item = normalize_ghidra_change_proposal(raw_item)
            action = " ".join(str(normalized_item.get("action") or "").split()).lower()
            target_kind = " ".join(str(normalized_item.get("target_kind") or "").split()).lower()
            evidence, evidence_missing, evidence_source = _extract_ghidra_proposal_evidence(raw_item)
            proposal = {
                "id": proposal_id,
                "action": action,
                "target_kind": target_kind,
                "function_address": " ".join(str(normalized_item.get("function_address") or "").split()),
                "function_name": " ".join(str(normalized_item.get("function_name") or "").split()),
                "address": " ".join(str(normalized_item.get("address") or "").split()),
                "current_name": " ".join(str(normalized_item.get("current_name") or "").split()),
                "proposed_name": " ".join(str(normalized_item.get("proposed_name") or "").split()),
                "variable_name": " ".join(str(normalized_item.get("variable_name") or "").split()),
                "current_type": " ".join(str(normalized_item.get("current_type") or "").split()),
                "proposed_type": " ".join(str(normalized_item.get("proposed_type") or "").split()),
                "prototype": str(normalized_item.get("prototype") or "").strip(),
                "comment": str(normalized_item.get("comment") or "").strip(),
                "summary": " ".join(str(raw_item.get("summary") or raw_item.get("objective") or "").split()),
                "rationale": " ".join(str(raw_item.get("rationale") or raw_item.get("reason") or "").split()),
                "evidence": evidence,
                "evidence_missing": evidence_missing,
                "evidence_source": evidence_source,
                "status": "pending",
                "source_stage": " ".join(str(raw_item.get("source_stage") or "").split()),
                "raw": raw_item,
            }
            normalized.append(proposal)

    if not normalized:
        return [], "", True
    return normalized, "", True


def _normalized_proposal_field(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _proposal_semantic_signature(proposal: Dict[str, Any]) -> str:
    target_locator = (
        _normalized_proposal_field(proposal.get("function_address"))
        or _normalized_proposal_field(proposal.get("address"))
        or _normalized_proposal_field(proposal.get("function_name"))
    )
    current_state = (
        _normalized_proposal_field(proposal.get("current_name"))
        or _normalized_proposal_field(proposal.get("variable_name"))
        or _normalized_proposal_field(proposal.get("current_type"))
    )
    desired_state = (
        _normalized_proposal_field(proposal.get("proposed_name"))
        or _normalized_proposal_field(proposal.get("proposed_type"))
        or _normalized_proposal_field(proposal.get("prototype"))
        or _normalized_proposal_field(proposal.get("comment"))
    )
    return "|".join(
        [
            _normalized_proposal_field(proposal.get("action")),
            _normalized_proposal_field(proposal.get("target_kind")),
            target_locator,
            current_state,
            desired_state,
        ]
    )


def _proposal_conflict_signature(proposal: Dict[str, Any]) -> str:
    action = _normalized_proposal_field(proposal.get("action"))
    target_kind = _normalized_proposal_field(proposal.get("target_kind"))
    action_family = action
    if action in {"rename_function_by_address", "rename_function"}:
        action_family = "rename_function"
    target_locator = (
        _normalized_proposal_field(proposal.get("function_address"))
        or _normalized_proposal_field(proposal.get("address"))
        or _normalized_proposal_field(proposal.get("function_name"))
    )
    subtarget = ""
    if action in {"rename_variable", "set_local_variable_type"}:
        subtarget = _normalized_proposal_field(proposal.get("variable_name"))
    return "|".join([action_family, target_kind, target_locator, subtarget])


def _merge_unique_string_lists(*values: Any) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for value in values:
        for item in _normalize_string_list(value):
            key = item.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out


def _merge_ghidra_proposal_records(
    existing: Dict[str, Any],
    incoming: Dict[str, Any],
    *,
    stage_kind: str,
) -> Dict[str, Any]:
    stage_meta = get_stage_kind_metadata(stage_kind)
    merged = dict(existing)
    for key in (
        "action",
        "target_kind",
        "function_address",
        "function_name",
        "address",
        "current_name",
        "proposed_name",
        "variable_name",
        "current_type",
        "proposed_type",
        "prototype",
        "comment",
        "summary",
        "rationale",
        "evidence_missing",
        "evidence_source",
        "can_apply",
        "apply_reason",
        "apply_tool_name",
        "apply_tool_args",
        "result_text",
        "error",
    ):
        incoming_value = incoming.get(key)
        if incoming_value in (None, "", {}, []):
            continue
        if key in {"summary", "rationale"} and len(str(incoming_value)) < len(str(merged.get(key) or "")):
            continue
        merged[key] = incoming_value

    merged["evidence"] = _merge_unique_string_lists(existing.get("evidence"), incoming.get("evidence"))
    merged["evidence_missing"] = not bool(merged.get("evidence")) or bool(
        existing.get("evidence_missing") and incoming.get("evidence_missing")
    )
    if not merged["evidence_missing"]:
        merged["evidence_source"] = "structured"
    else:
        merged["evidence_source"] = str(
            incoming.get("evidence_source")
            or existing.get("evidence_source")
            or "missing"
        )
    merged["source_stages"] = _merge_unique_string_lists(existing.get("source_stages"), incoming.get("source_stage"))
    merged["dedupe_alias_ids"] = _merge_unique_string_lists(
        existing.get("dedupe_alias_ids"),
        [alias for alias in [incoming.get("id"), existing.get("id")] if alias and alias != existing.get("id")],
    )
    merged["source_stage"] = str(
        incoming.get("source_stage")
        or existing.get("source_stage")
        or (stage_kind if stage_meta["finalizes_report"] else "")
    )
    merged["signature"] = str(incoming.get("signature") or existing.get("signature") or "")
    merged["conflict_signature"] = str(
        incoming.get("conflict_signature") or existing.get("conflict_signature") or ""
    )
    merged.setdefault("status", str(existing.get("status") or "pending"))
    return merged


def update_ghidra_change_proposals_from_stage_output(
    state: Dict[str, Any],
    stage_output: str,
    *,
    stage_name: str,
    stage_kind: str,
) -> None:
    stage_meta = get_stage_kind_metadata(stage_kind)
    proposals, error, found_block = extract_ghidra_change_proposals(stage_output)
    if not found_block and not error and not stage_meta["finalizes_report"]:
        return

    shared = state.setdefault("shared_state", _new_shared_state())
    shared["ghidra_change_parse_error"] = error
    if error:
        append_status(state, f"Ghidra change parse warning from {stage_name}: {error}")
        _store_ui_snapshot(state=state)
        return

    existing: Dict[str, Dict[str, Any]] = {}
    dropped_existing = 0
    for item in (shared.get("ghidra_change_draft_proposals") or shared.get("ghidra_change_proposals") or []):
        if not isinstance(item, dict):
            continue
        normalized_existing = normalize_ghidra_change_proposal(item)
        prepared_existing = prepare_ghidra_change_operation(normalized_existing)
        if not prepared_existing.get("can_apply"):
            dropped_existing += 1
            continue
        normalized_existing["can_apply"] = True
        normalized_existing["apply_reason"] = str(prepared_existing.get("reason") or "")
        normalized_existing["apply_tool_name"] = str(prepared_existing.get("tool_name") or "")
        normalized_existing["apply_tool_args"] = dict(prepared_existing.get("tool_args") or {})
        normalized_existing["summary"] = str(
            normalized_existing.get("summary") or prepared_existing.get("summary") or normalized_existing.get("id") or "proposal"
        )
        existing[str(normalized_existing.get("id") or "")] = normalized_existing
    for item in existing.values():
        if "signature" not in item:
            item["signature"] = _proposal_semantic_signature(item)
        if "conflict_signature" not in item:
            item["conflict_signature"] = _proposal_conflict_signature(item)
    existing_by_signature = {
        str((item.get("signature") or _proposal_semantic_signature(item) or "")): item_id
        for item_id, item in existing.items()
        if str((item.get("signature") or _proposal_semantic_signature(item) or ""))
    }
    existing_by_conflict = {
        str((item.get("conflict_signature") or _proposal_conflict_signature(item) or "")): item_id
        for item_id, item in existing.items()
        if str((item.get("conflict_signature") or _proposal_conflict_signature(item) or ""))
        and str(item.get("status") or "pending") == "pending"
    }
    dropped_incoming: List[str] = []
    for proposal in proposals:
        proposal = normalize_ghidra_change_proposal(proposal)
        proposal_id = str(proposal.get("id") or "")
        prepared = prepare_ghidra_change_operation(proposal)
        if not prepared.get("can_apply"):
            dropped_incoming.append(
                f"{proposal_id or str(proposal.get('summary') or 'proposal')}: {str(prepared.get('reason') or 'not directly mappable to a supported Ghidra MCP edit')}"
            )
            continue
        proposal_signature = _proposal_semantic_signature(proposal)
        proposal_conflict_signature = _proposal_conflict_signature(proposal)
        resolved_id = proposal_id or ""
        if resolved_id not in existing and proposal_signature in existing_by_signature:
            resolved_id = existing_by_signature[proposal_signature]
        elif (
            resolved_id not in existing
            and proposal_conflict_signature
            and proposal_conflict_signature in existing_by_conflict
        ):
            resolved_id = existing_by_conflict[proposal_conflict_signature]
        merged = dict(existing.get(resolved_id) or {})
        merged.update(proposal)
        merged["source_stage"] = stage_name
        merged["signature"] = proposal_signature
        merged["conflict_signature"] = proposal_conflict_signature
        merged["can_apply"] = bool(prepared.get("can_apply"))
        merged["apply_reason"] = str(prepared.get("reason") or "")
        merged["apply_tool_name"] = str(prepared.get("tool_name") or "")
        merged["apply_tool_args"] = dict(prepared.get("tool_args") or {})
        merged["summary"] = str(merged.get("summary") or prepared.get("summary") or proposal_id)
        merged.setdefault("result_text", "")
        merged.setdefault("error", "")
        merged.setdefault("status", "pending")
        merged["source_stages"] = _merge_unique_string_lists(merged.get("source_stages"), stage_name)
        merged["dedupe_alias_ids"] = _merge_unique_string_lists(
            merged.get("dedupe_alias_ids"),
            [proposal_id] if proposal_id and proposal_id != resolved_id else [],
        )
        if resolved_id and resolved_id in existing:
            merged = _merge_ghidra_proposal_records(existing[resolved_id], merged, stage_kind=stage_kind)
            existing.pop(resolved_id, None)
        existing[proposal_id or resolved_id or f"proposal_{len(existing) + 1}"] = merged
        if proposal_signature:
            existing_by_signature[proposal_signature] = proposal_id or resolved_id or f"proposal_{len(existing)}"
        if proposal_conflict_signature:
            existing_by_conflict[proposal_conflict_signature] = proposal_id or resolved_id or f"proposal_{len(existing)}"

    merged_proposals = list(existing.values())
    weak_evidence_count = sum(1 for item in merged_proposals if bool(item.get("evidence_missing")))
    shared["ghidra_change_draft_proposals"] = merged_proposals
    if dropped_existing:
        append_status(
            state,
            f"Pruned {dropped_existing} stale non-applicable Ghidra proposal(s) before updating the approval queue."
        )
    if dropped_incoming:
        preview = "; ".join(dropped_incoming[:3])
        if len(dropped_incoming) > 3:
            preview += f"; +{len(dropped_incoming) - 3} more"
        append_status(
            state,
            f"Dropped {len(dropped_incoming)} non-applicable Ghidra proposal(s) from {stage_name}: {preview}"
        )
    if stage_meta["finalizes_report"]:
        shared["ghidra_change_proposals"] = merged_proposals
        shared["ghidra_change_queue_finalized"] = True
        append_status(state, f"Ghidra change queue finalized after {stage_name}: {len(merged_proposals)} proposal(s)")
    else:
        shared["ghidra_change_queue_finalized"] = False
        shared["ghidra_change_proposals"] = []
        append_status(state, f"Ghidra change draft proposals parsed from {stage_name}: {len(proposals)}")
    if weak_evidence_count:
        append_status(
            state,
            f"Ghidra proposal evidence warning from {stage_name}: {weak_evidence_count} proposal(s) lacked structured evidence.",
        )
    _store_ui_snapshot(state=state)


def extract_yara_rule_proposals(text: str) -> Tuple[List[Dict[str, Any]], str, bool]:
    payloads: List[str] = []
    marker_re = re.compile(
        rf"{re.escape(YARA_RULE_PROPOSALS_START)}\s*(.*?)\s*{re.escape(YARA_RULE_PROPOSALS_END)}",
        flags=re.DOTALL,
    )
    for match in marker_re.finditer(text or ""):
        payloads.append(match.group(1))

    if not payloads:
        return [], "", False

    normalized: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    for block_index, payload in enumerate(payloads, start=1):
        payload = _strip_optional_json_fence(payload)
        try:
            parsed = json.loads(payload)
        except Exception as e:
            return [], f"yara rule JSON parse failed: {type(e).__name__}: {e}", True

        if isinstance(parsed, dict):
            parsed = parsed.get("rules") or parsed.get("proposals") or []
        if not isinstance(parsed, list):
            return [], "yara rule block must decode to a JSON array", True

        for idx, raw_item in enumerate(parsed, start=1):
            if not isinstance(raw_item, dict):
                continue
            proposal_id = " ".join(str(raw_item.get("id") or f"Y{block_index}_{idx}").split()) or f"Y{block_index}_{idx}"
            while proposal_id in seen_ids:
                proposal_id = f"{proposal_id}_{idx}"
            seen_ids.add(proposal_id)

            rule_text = str(raw_item.get("rule_text") or raw_item.get("text") or "").strip()
            if not rule_text:
                continue
            normalized.append(
                {
                    "id": proposal_id,
                    "summary": " ".join(str(raw_item.get("summary") or raw_item.get("name") or "Generated YARA rule").split()),
                    "filename": " ".join(str(raw_item.get("filename") or "").split()),
                    "rule_text": rule_text,
                    "rationale": " ".join(str(raw_item.get("rationale") or raw_item.get("reason") or "").split()),
                    "overwrite": bool(raw_item.get("overwrite")),
                    "status": "pending",
                }
            )

    if not normalized:
        return [], "", True
    return normalized, "", True


def update_generated_yara_rules_from_stage_output(
    state: Dict[str, Any],
    runtime: MultiAgentRuntime,
    stage_output: str,
    *,
    stage_name: str,
    stage_kind: str,
) -> None:
    stage_meta = get_stage_kind_metadata(stage_kind)
    if not stage_meta["finalizes_report"]:
        return

    proposals, error, found_block = extract_yara_rule_proposals(stage_output)
    if not found_block and not error:
        return

    shared = state.setdefault("shared_state", _new_shared_state())
    shared["generated_yara_rule_parse_error"] = error
    if error:
        append_status(state, f"YARA rule parse warning from {stage_name}: {error}")
        _store_ui_snapshot(state=state)
        return

    existing = list(shared.get("generated_yara_rules") or [])
    existing_signatures = {
        "|".join(
            [
                " ".join(str(item.get("filename") or "").lower().split()),
                " ".join(str(item.get("rule_text") or "").lower().split()),
            ]
        )
        for item in existing
        if isinstance(item, dict)
    }

    server_available = _find_mcp_server_by_marker(runtime, "yara") is not None
    for proposal in proposals:
        signature = "|".join(
            [
                " ".join(str(proposal.get("filename") or "").lower().split()),
                " ".join(str(proposal.get("rule_text") or "").lower().split()),
            ]
        )
        if signature in existing_signatures:
            continue

        record = dict(proposal)
        record["source_stage"] = stage_name
        if not server_available:
            record["status"] = "failed"
            record["error"] = "YARA MCP server is not configured."
            existing.append(record)
            continue

        specificity_ok, specificity_error = _assess_yara_rule_specificity(str(proposal.get("rule_text") or ""))
        if not specificity_ok:
            record["status"] = "failed"
            record["error"] = specificity_error
            append_status(state, f"YARA rule rejected from {stage_name}: {specificity_error}")
            existing.append(record)
            existing_signatures.add(signature)
            continue

        write_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="yara",
            tool_name="yaraWriteRule",
            tool_args={
                "rule_text": str(proposal.get("rule_text") or ""),
                "filename": str(proposal.get("filename") or ""),
                "overwrite": bool(proposal.get("overwrite")),
                "validate": True,
                "timeout_sec": 20,
            },
        )
        parsed_result = _parse_jsonish_tool_result(write_result.get("result"))
        if isinstance(parsed_result, dict) and parsed_result.get("ok"):
            record["status"] = "written"
            record["rule_path"] = str(parsed_result.get("rule_path") or "")
            record["index_path"] = str(parsed_result.get("index_path") or "")
            record["validation_warning"] = str(parsed_result.get("validation_warning") or "")
            append_status(state, f"YARA rule written from {stage_name}: {record.get('rule_path') or record.get('summary')}")
        else:
            record["status"] = "failed"
            record["error"] = str(
                (parsed_result or {}).get("error")
                if isinstance(parsed_result, dict)
                else write_result.get("error")
                or "YARA rule write failed."
            ).strip()
            append_status(state, f"YARA rule write failed from {stage_name}: {record['error']}")
        existing.append(record)
        existing_signatures.add(signature)

    shared["generated_yara_rules"] = existing
    _store_ui_snapshot(state=state)


def _normalize_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        normalized = " ".join(value.split())
        return [normalized] if normalized else []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            normalized = " ".join(str(item).split())
            if normalized:
                out.append(normalized)
        return out
    normalized = " ".join(str(value).split())
    return [normalized] if normalized else []


def _normalize_evidence_item(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        labeled_fields = (
            ("function_address", "function"),
            ("function_name", "function_name"),
            ("address", "address"),
            ("string", "string"),
            ("decoded_string", "decoded_string"),
            ("api", "api"),
            ("import", "import"),
            ("xref", "xref"),
            ("rule", "rule"),
            ("offset", "offset"),
        )
        free_text_fields = (
            "fact",
            "evidence",
            "excerpt",
            "artifact",
            "observation",
            "detail",
            "summary",
            "description",
            "note",
            "reason",
            "rationale",
        )
        parts: List[str] = []
        for key, label in labeled_fields:
            normalized = _normalize_string_list(value.get(key))
            if normalized:
                parts.extend(f"{label}: {item}" for item in normalized)
        for key in free_text_fields:
            for item in _normalize_string_list(value.get(key)):
                if item not in parts:
                    parts.append(item)
        return parts
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            out.extend(_normalize_evidence_item(item))
        return out
    return _normalize_string_list(value)


def _extract_ghidra_proposal_evidence(raw_item: Dict[str, Any]) -> Tuple[List[str], bool, str]:
    evidence_sources = (
        raw_item.get("evidence"),
        raw_item.get("evidence_targets"),
        raw_item.get("supporting_evidence"),
        raw_item.get("artifacts"),
        raw_item.get("support"),
        raw_item.get("proof"),
        raw_item.get("observations"),
        raw_item.get("anchors"),
        raw_item.get("citations"),
        raw_item.get("basis"),
    )
    evidence = _merge_unique_string_lists(*(_normalize_evidence_item(source) for source in evidence_sources))
    if evidence:
        return evidence, False, "structured"

    rationale = " ".join(str(raw_item.get("rationale") or raw_item.get("reason") or "").split())
    if rationale:
        return [f"Rationale fallback: {rationale}"], True, "rationale_fallback"

    return [], True, "missing"


def extract_validation_gate(text: str, *, required_signoffs: int) -> Tuple[Dict[str, Any], str]:
    payload = ""
    marker_re = re.compile(
        rf"{re.escape(VALIDATION_DECISION_START)}\s*(.*?)\s*{re.escape(VALIDATION_DECISION_END)}",
        flags=re.DOTALL,
    )
    marker_match = marker_re.search(text or "")
    if marker_match:
        payload = marker_match.group(1)
    else:
        fenced_json_re = re.compile(r"```json\s*(\{[\s\S]*?\})\s*```", flags=re.IGNORECASE)
        fenced_match = fenced_json_re.search(text or "")
        if fenced_match:
            payload = fenced_match.group(1)
        else:
            return {}, "validator output did not include a parseable validation block"

    payload = _strip_optional_json_fence(payload)
    try:
        parsed = json.loads(payload)
    except Exception as e:
        return {}, f"validator gate JSON parse failed: {type(e).__name__}: {e}"

    if not isinstance(parsed, dict):
        return {}, "validator gate block must decode to a JSON object"

    raw_decision = " ".join(str(parsed.get("decision") or parsed.get("status") or parsed.get("result") or "").split()).lower()
    accepted_aliases = {"accept", "accepted", "approve", "approved", "pass", "passed", "signoff", "signed_off"}
    rejected_aliases = {"reject", "rejected", "deny", "denied", "fail", "failed"}
    if raw_decision in accepted_aliases:
        accepted = True
    elif raw_decision in rejected_aliases:
        accepted = False
    else:
        return {}, f"validator decision must be accept/reject, got {raw_decision or '<missing>'!r}"

    parsed_required = parsed.get("required_signoffs")
    if parsed_required is None:
        required = max(1, required_signoffs)
    else:
        try:
            required = max(1, int(parsed_required))
        except Exception:
            required = max(1, required_signoffs)

    parsed_signoff_count = parsed.get("signoff_count")
    if parsed_signoff_count is None:
        signoff_count = required if accepted else 0
    else:
        try:
            signoff_count = max(0, int(parsed_signoff_count))
        except Exception:
            signoff_count = required if accepted else 0

    rejection_reasons = _normalize_string_list(parsed.get("rejection_reasons") or parsed.get("reasons"))
    planner_fixes = _normalize_string_list(parsed.get("planner_fixes") or parsed.get("required_fixes") or parsed.get("fixes"))
    accepted_findings = _normalize_string_list(parsed.get("accepted_findings") or parsed.get("confirmed_findings"))
    rejected_findings = _normalize_string_list(parsed.get("rejected_findings") or parsed.get("weak_findings"))
    out_of_scope_work_items = _normalize_string_list(
        parsed.get("out_of_scope_work_items") or parsed.get("planner_defects") or parsed.get("unsupported_work_items")
    )
    summary = " ".join(str(parsed.get("summary") or parsed.get("validator_summary") or "").split())

    if accepted and signoff_count < required:
        accepted = False
        rejection_reasons.append(
            f"validator signoff threshold not met ({signoff_count}/{required})"
        )

    return {
        "decision": "accept" if accepted else "reject",
        "accepted": accepted,
        "signoff_count": signoff_count,
        "required_signoffs": required,
        "accepted_findings": accepted_findings,
        "rejected_findings": rejected_findings,
        "out_of_scope_work_items": out_of_scope_work_items,
        "rejection_reasons": rejection_reasons,
        "planner_fixes": planner_fixes,
        "summary": summary,
    }, ""


def _format_validation_feedback(gate: Dict[str, Any], raw_output: str, parse_error: str = "") -> str:
    lines: List[str] = []
    if parse_error:
        lines.append(f"Validation gate parse issue: {parse_error}")
    decision = str(gate.get("decision") or "").strip()
    if decision:
        lines.append(f"Validation decision: {decision}")
    signoff_count = gate.get("signoff_count")
    required_signoffs = gate.get("required_signoffs")
    if signoff_count is not None and required_signoffs is not None:
        lines.append(f"Validator signoff count: {signoff_count}/{required_signoffs}")
    summary = str(gate.get("summary") or "").strip()
    if summary:
        lines.append(f"Summary: {summary}")
    reasons = gate.get("rejection_reasons") or []
    if reasons:
        lines.append("Rejection reasons:")
        lines.extend(f"- {item}" for item in reasons)
    out_of_scope = gate.get("out_of_scope_work_items") or []
    if out_of_scope:
        lines.append("Out-of-scope work items:")
        lines.extend(f"- {item}" for item in out_of_scope)
    fixes = gate.get("planner_fixes") or []
    if fixes:
        lines.append("Planner fixes:")
        lines.extend(f"- {item}" for item in fixes)
    if not lines:
        lines.append("Validation gate rejected without structured feedback.")
    if raw_output and not summary and not reasons and not fixes:
        lines.extend(["Raw validator output:", raw_output.strip()])
    return "\n".join(lines).strip()


def _latest_pipeline_output_by_kind(shared: Dict[str, Any], stage_kind: str) -> str:
    outputs = shared.get("pipeline_stage_outputs") or []
    for entry in reversed(outputs):
        if str(entry.get("stage_kind") or "").strip() != stage_kind:
            continue
        return str(entry.get("output_text") or "").strip()
    return ""


def _build_validation_failure_fallback_output(
    state: Dict[str, Any],
    gate: Dict[str, Any],
    raw_validator_output: str,
    parse_error: str = "",
) -> str:
    shared = state.setdefault("shared_state", _new_shared_state())
    worker_output = _latest_pipeline_output_by_kind(shared, "workers")
    planner_output = _latest_pipeline_output_by_kind(shared, "planner")
    preflight_output = _latest_pipeline_output_by_kind(shared, "preflight")
    validation_feedback = _format_validation_feedback(gate, raw_validator_output, parse_error)

    sections: List[str] = [
        "Validation did not pass after the configured retry budget.",
        "Returning the best available analysis gathered so far, followed by validator caveats.",
    ]

    accepted_findings = _normalize_string_list(gate.get("accepted_findings"))
    if accepted_findings:
        sections.extend(
            [
                "",
                "Still-usable findings:",
                "\n".join(f"- {item}" for item in accepted_findings),
            ]
        )

    best_available = worker_output or planner_output or preflight_output
    if best_available:
        label = "Latest worker analysis" if worker_output else "Latest collected analysis"
        sections.extend(["", f"{label}:", _sanitize_user_facing_output(best_available)])

    sections.extend(["", "Validator caveats:", validation_feedback])

    out_of_scope = _normalize_string_list(gate.get("out_of_scope_work_items"))
    if out_of_scope:
        sections.extend(
            [
                "",
                "Out-of-scope or non-blocking items:",
                "\n".join(f"- {item}" for item in out_of_scope),
            ]
        )

    return "\n".join(part for part in sections if part is not None).strip()


def _reset_pipeline_stages_to_pending(state: Dict[str, Any], stage_names: List[str]) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    progress = shared.setdefault("pipeline_stage_progress", [])
    target_names = set(stage_names)
    for entry in progress:
        if str(entry.get("stage_name") or "") not in target_names:
            continue
        entry["status"] = "pending"
        entry["started_at_epoch"] = None
        entry["finished_at_epoch"] = None
        entry["duration_sec"] = None
        entry["error"] = ""
    _store_ui_snapshot(state=state)


def _clear_stage_role_histories(state: Dict[str, Any], stage_names: List[str]) -> None:
    histories = state.setdefault("role_histories", {})
    for stage_name in stage_names:
        histories.pop(f"pipeline_{stage_name}", None)


def _first_progress_status_by_flag(progress: List[Dict[str, Any]], flag: str) -> str:
    for item in progress:
        stage_kind = str(item.get("stage_kind") or "").strip()
        if stage_kind and stage_kind_flag(stage_kind, flag):
            return str(item.get("status") or "")
    return ""


def _first_progress_entry_by_flag(progress: List[Dict[str, Any]], flag: str) -> Dict[str, Any]:
    return next(
        (
            item
            for item in progress
            if stage_kind_flag(str(item.get("stage_kind") or "").strip(), flag)
        ),
        {},
    )


def _planner_work_item_rollup(progress: List[Dict[str, Any]]) -> Tuple[str, str, str]:
    if any(str(item.get("status") or "pending") == "failed" for item in progress):
        return "☒", "#a61b29", "blocked"
    report_status = _first_progress_status_by_flag(progress, "finalizes_report")
    validation_status = _first_progress_status_by_flag(progress, "runs_validation_gate")
    worker_status = _first_progress_status_by_flag(progress, "supports_parallel_assignments")
    planner_status = _first_progress_status_by_flag(progress, "parses_planner_work_items")
    preflight_status = next(
        (str(item.get("status") or "") for item in progress if str(item.get("stage_kind") or "").strip() == "preflight"),
        "",
    )
    if report_status == "completed":
        return "☑", "#1b6e3a", "completed"
    if report_status == "running":
        return "☑", "#0b57d0", "reporting"
    if validation_status == "completed":
        return "☑", "#1b6e3a", "validated"
    if validation_status == "running":
        return "☑", "#0b57d0", "under review"
    if worker_status == "completed":
        return "☑", "#1b6e3a", "executed"
    if worker_status == "running":
        return "☐", "#0b57d0", "in execution"
    if planner_status == "completed":
        return "☐", "#5f6368", "planned"
    if planner_status == "running":
        return "☐", "#0b57d0", "drafting"
    if preflight_status == "completed":
        return "☐", "#5f6368", "context ready"
    if preflight_status == "running":
        return "☐", "#0b57d0", "preflight"
    return "☐", "#5f6368", "pending"


def render_planned_work_items_panel(state: Dict[str, Any]) -> str:
    shared = (state or {}).get("shared_state") or {}
    items = shared.get("planned_work_items") or []
    item_status_map = shared.get("planned_work_item_status") or {}
    parse_error = str(shared.get("planned_work_items_parse_error") or "").strip()
    progress = shared.get("pipeline_stage_progress") or []
    planner_status = _first_progress_status_by_flag(progress, "parses_planner_work_items")
    preflight_status = next(
        (str(item.get("status") or "") for item in progress if str(item.get("stage_kind") or "").strip() == "preflight"),
        "",
    )
    if not items and not parse_error:
        waiting_message = "Planner work items will appear after the planning stage completes."
        if preflight_status == "running":
            waiting_message = "Preflight stage is running. Planner work items will appear after minimal context gathering and planning complete."
        elif planner_status == "running":
            waiting_message = "Planning stage is running. Planner work items will appear here once parsed."
        return (
            "<div style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #fbfbfc; margin-bottom: 12px;'>"
            "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
            "<strong>Planned Work Items</strong>"
            "<span style='color: #5f6368; font-size: 12px;'>host-managed checklist parsed from planner output</span>"
            "</div>"
            f"<div style='margin-top: 8px; color: #5f6368;'>{html.escape(waiting_message)}</div>"
            "</div>"
        )

    rows: List[str] = []
    for item in items:
        item_id = html.escape(str(item.get("id") or ""))
        objective = html.escape(str(item.get("objective") or ""))
        raw_item_id = str(item.get("id") or "")
        tone, status_label = _display_planned_work_item_status(progress, item_status_map.get(raw_item_id))
        roles = ", ".join(item.get("recommended_roles") or []) or "unspecified"
        targets = item.get("evidence_targets") or []
        targets_html = "".join(
            f"<div style='margin-top: 2px; color: #5f6368;'>- {html.escape(str(target))}</div>"
            for target in targets
        ) or "<div style='margin-top: 2px; color: #5f6368;'>- none specified</div>"

        rows.append(
            "<div style='border: 1px solid #d5d8dd; border-radius: 10px; padding: 10px 12px; margin-top: 8px;'>"
            f"<div style='display: flex; justify-content: space-between; gap: 12px; align-items: center;'>"
            f"<div style='font-size: 15px;'><strong>{item_id}</strong> <span style='color: #202124;'>{objective}</span></div>"
            f"<div style='color: {tone}; text-transform: uppercase; font-size: 12px; letter-spacing: 0.04em;'>{status_label}</div>"
            "</div>"
            f"<div style='margin-top: 4px; color: #5f6368;'>recommended roles: {html.escape(roles)}</div>"
            "<div style='margin-top: 6px; color: #202124; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em;'>"
            "evidence targets</div>"
            f"{targets_html}"
            "</div>"
        )

    error_html = ""
    if parse_error:
        error_html = (
            "<div style='margin-top: 8px; padding: 8px 10px; border: 1px solid #f3c3c7; border-radius: 8px; "
            "background: #fff5f5; color: #a61b29;'>"
            f"{html.escape(parse_error)}</div>"
        )

    return (
        "<div style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #fbfbfc; margin-bottom: 12px;'>"
        "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
        "<strong>Planned Work Items</strong>"
        "<span style='color: #5f6368; font-size: 12px;'>host-managed checklist parsed from planner output</span>"
        "</div>"
        + error_html
        + "".join(rows)
        + "</div>"
    )


def render_validation_gate_panel(state: Dict[str, Any]) -> str:
    shared = (state or {}).get("shared_state") or {}
    progress = shared.get("pipeline_stage_progress") or []
    validator_entry = _first_progress_entry_by_flag(progress, "runs_validation_gate")
    planner_entry = _first_progress_entry_by_flag(progress, "parses_planner_work_items")
    worker_entry = _first_progress_entry_by_flag(progress, "supports_parallel_assignments")

    validation_history = shared.get("validation_history") or []
    retry_count = int(shared.get("validation_retry_count") or 0)
    max_retries = int(shared.get("validation_max_retries") or MAX_VALIDATION_REPLAN_RETRIES)
    last_decision = str(shared.get("validation_last_decision") or "").strip().lower()
    replan_feedback = str(shared.get("validation_replan_feedback") or "").strip()
    latest = validation_history[-1] if validation_history else {}
    signoff_count = latest.get("signoff_count")
    required_signoffs = latest.get("required_signoffs")
    validator_status = str(validator_entry.get("status") or "pending")
    planner_status = str(planner_entry.get("status") or "pending")
    worker_status = str(worker_entry.get("status") or "pending")

    tone = "#5f6368"
    badge_bg = "#f1f3f4"
    headline = "Awaiting validation"
    detail = "Validator gate has not run yet."

    if not validator_entry:
        headline = "No validation stage"
        detail = "This pipeline reports directly without a validator gate."

    if validator_entry and validator_status == "running":
        tone = "#0b57d0"
        badge_bg = "#e8f0fe"
        headline = "Validation in progress"
        detail = "Validators are reviewing worker evidence."
    elif validator_entry and last_decision == "accept":
        tone = "#1b6e3a"
        badge_bg = "#e6f4ea"
        headline = "Validation accepted"
        if signoff_count is not None and required_signoffs is not None:
            detail = f"Validator signoff: {signoff_count}/{required_signoffs}"
        else:
            detail = "Validated findings are cleared for reporting."
    elif validator_entry and last_decision == "reject":
        if retry_count < max_retries and planner_status in {"running", "pending"}:
            tone = "#b06000"
            badge_bg = "#fef7e0"
            headline = f"Replanning ({retry_count}/{max_retries})"
            detail = "Planner is revising the work plan based on validator feedback."
        elif retry_count < max_retries and worker_status in {"running", "pending"}:
            tone = "#b06000"
            badge_bg = "#fef7e0"
            headline = f"Retry in progress ({retry_count}/{max_retries})"
            detail = "Workers are addressing validator feedback."
        else:
            tone = "#a61b29"
            badge_bg = "#fce8e6"
            headline = "Validation rejected"
            detail = "Validation did not clear the findings for reporting."

    summary_lines: List[str] = []
    if validation_history:
        latest_attempt = int(latest.get("attempt") or retry_count)
        summary_lines.append(f"Latest review attempt: {latest_attempt}/{max_retries}")
        if signoff_count is not None and required_signoffs is not None:
            summary_lines.append(f"Signoffs: {signoff_count}/{required_signoffs}")
    else:
        summary_lines.append(f"Retry budget: {retry_count}/{max_retries}")

    feedback_html = ""
    if replan_feedback:
        feedback_html = (
            "<div style='margin-top: 10px;'>"
            "<div style='font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #5f6368;'>"
            "Latest validator feedback</div>"
            "<pre style='margin-top: 6px; white-space: pre-wrap; overflow-x: auto; background: #ffffff; border: 1px solid #d5d8dd; "
            "border-radius: 8px; padding: 10px; color: #202124; font-size: 12px;'>"
            f"{html.escape(replan_feedback)}</pre>"
            "</div>"
        )

    history_html = ""
    if validation_history:
        rows: List[str] = []
        for item in reversed(validation_history[-3:]):
            attempt = int(item.get("attempt") or 0)
            decision = html.escape(str(item.get("decision") or "unknown"))
            signoffs = item.get("signoff_count")
            required = item.get("required_signoffs")
            reason_bits = item.get("rejection_reasons") or []
            if not reason_bits:
                reason_bits = item.get("out_of_scope_work_items") or []
            reason_text = html.escape("; ".join(str(x) for x in reason_bits[:2])) if reason_bits else ""
            meta = decision
            if signoffs is not None and required is not None:
                meta = f"{meta} ({signoffs}/{required})"
            rows.append(
                "<div style='margin-top: 6px; padding-top: 6px; border-top: 1px solid #e0e3e7;'>"
                f"<div style='font-size: 12px; color: #202124;'><strong>Attempt {attempt}</strong> - {meta}</div>"
                + (f"<div style='margin-top: 2px; color: #5f6368; font-size: 12px;'>{reason_text}</div>" if reason_text else "")
                + "</div>"
            )
        history_html = (
            "<div style='margin-top: 10px;'>"
            "<div style='font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #5f6368;'>"
            "Recent validation history</div>"
            + "".join(rows)
            + "</div>"
        )

    return (
        "<div style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #fbfbfc; margin-bottom: 12px;'>"
        "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
        "<strong>Validation Gate</strong>"
        f"<span style='padding: 2px 8px; border-radius: 999px; background: {badge_bg}; color: {tone}; font-size: 12px;'>{html.escape(headline)}</span>"
        "</div>"
        f"<div style='margin-top: 8px; color: #202124;'>{html.escape(detail)}</div>"
        f"<div style='margin-top: 6px; color: #5f6368; font-size: 12px;'>{html.escape(' | '.join(summary_lines))}</div>"
        + feedback_html
        + history_html
        + "</div>"
    )


def render_automation_status_panel(state: Dict[str, Any]) -> str:
    shared = (state or {}).get("shared_state") or {}
    status = str(shared.get("automation_status") or "").strip().lower() or "idle"
    reason = str(shared.get("automation_last_reason") or shared.get("automation_rerun_reason") or "").strip()
    source = str(shared.get("automation_last_source") or shared.get("automation_trigger_source") or "").strip()
    program_key = str(shared.get("automation_last_program_key") or shared.get("automation_program_key") or "").strip()
    detail = str(shared.get("automation_last_detail") or "").strip()
    last_at = str(shared.get("automation_last_at") or "").strip()
    auto_triage_status = str(shared.get("auto_triage_status") or "").strip().lower()
    auto_triage_error = str(shared.get("auto_triage_last_error") or "").strip()
    auto_triage_last_run_at = str(shared.get("auto_triage_last_run_at") or "").strip()
    history = list(shared.get("automation_history") or [])

    tone = "#5f6368"
    badge_bg = "#f1f3f4"
    headline = "Idle"
    detail_line = "No automation triggers have been recorded in this server session yet."

    if status in {"accepted", "running"}:
        tone = "#0b57d0"
        badge_bg = "#e8f0fe"
        headline = "Trigger accepted"
        detail_line = "Ghidra automation metadata was accepted and automated triage is queued or running."
    elif status == "skipped":
        tone = "#b06000"
        badge_bg = "#fef7e0"
        headline = "Trigger skipped"
        detail_line = "The latest automation trigger was received but not run."
    elif status == "busy":
        tone = "#b06000"
        badge_bg = "#fef7e0"
        headline = "Trigger deferred"
        detail_line = "A trigger arrived while another workflow was already active."
    elif status == "succeeded":
        tone = "#1b6e3a"
        badge_bg = "#e6f4ea"
        headline = "Auto-triage completed"
        detail_line = "The latest accepted automation run completed successfully."
    elif status == "failed":
        tone = "#a61b29"
        badge_bg = "#fce8e6"
        headline = "Auto-triage failed"
        detail_line = "The latest accepted automation run failed."
    elif status == "canceled":
        tone = "#8a3b12"
        badge_bg = "#fff7e6"
        headline = "Auto-triage canceled"
        detail_line = "The latest accepted automation run was canceled or detached."

    summary_bits: List[str] = []
    if source:
        summary_bits.append(f"source: {source}")
    if program_key:
        summary_bits.append(f"program: {program_key}")
    if last_at:
        summary_bits.append(f"last event: {last_at}")

    auto_triage_html = ""
    if auto_triage_status:
        auto_triage_html = (
            "<div style='margin-top: 10px;'>"
            "<div style='font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #5f6368;'>"
            "Latest auto-triage result</div>"
            f"<div style='margin-top: 4px; color: #202124;'>status: {html.escape(auto_triage_status)}"
            + (f" | finished: {html.escape(auto_triage_last_run_at)}" if auto_triage_last_run_at else "")
            + "</div>"
            + (
                "<div style='margin-top: 4px; color: #a61b29; font-size: 12px;'>"
                f"{html.escape(auto_triage_error)}</div>"
                if auto_triage_error
                else ""
            )
            + "</div>"
        )

    history_html = ""
    if history:
        rows: List[str] = []
        for item in reversed(history[-4:]):
            item_status = html.escape(str(item.get("status") or "unknown"))
            item_reason = html.escape(str(item.get("reason") or ""))
            item_detail = html.escape(str(item.get("detail") or ""))
            item_at = html.escape(str(item.get("at") or ""))
            rows.append(
                "<div style='margin-top: 6px; padding-top: 6px; border-top: 1px solid #e0e3e7;'>"
                f"<div style='font-size: 12px; color: #202124;'><strong>{item_status}</strong>"
                + (f" - {item_reason}" if item_reason else "")
                + (f" <span style='color: #5f6368;'>({item_at})</span>" if item_at else "")
                + "</div>"
                + (
                    f"<div style='margin-top: 2px; color: #5f6368; font-size: 12px;'>{item_detail}</div>"
                    if item_detail
                    else ""
                )
                + "</div>"
            )
        history_html = (
            "<div style='margin-top: 10px;'>"
            "<div style='font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #5f6368;'>"
            "Recent automation events</div>"
            + "".join(rows)
            + "</div>"
        )

    return (
        "<div style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #fbfbfc; margin-bottom: 12px;'>"
        "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
        "<strong>Automation Status</strong>"
        f"<span style='padding: 2px 8px; border-radius: 999px; background: {badge_bg}; color: {tone}; font-size: 12px;'>{html.escape(headline)}</span>"
        "</div>"
        f"<div style='margin-top: 8px; color: #202124;'>{html.escape(detail_line)}</div>"
        + (
            f"<div style='margin-top: 6px; color: #5f6368; font-size: 12px;'>{html.escape(' | '.join(summary_bits))}</div>"
            if summary_bits
            else ""
        )
        + (
            f"<div style='margin-top: 6px; color: #202124; font-size: 12px;'><strong>reason:</strong> {html.escape(reason)}</div>"
            if reason
            else ""
        )
        + (
            f"<div style='margin-top: 4px; color: #5f6368; font-size: 12px;'>{html.escape(detail)}</div>"
            if detail
            else ""
        )
        + auto_triage_html
        + history_html
        + "</div>"
    )


def get_pending_ghidra_change_proposal(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    shared = (state or {}).get("shared_state") or {}
    if not bool(shared.get("ghidra_change_queue_finalized")):
        return None
    for proposal in shared.get("ghidra_change_proposals") or []:
        if str(proposal.get("status") or "pending") == "pending":
            return proposal
    return None


def get_pending_ghidra_change_count(state: Dict[str, Any]) -> int:
    shared = (state or {}).get("shared_state") or {}
    if not bool(shared.get("ghidra_change_queue_finalized")):
        return 0
    return sum(
        1
        for proposal in (shared.get("ghidra_change_proposals") or [])
        if str(proposal.get("status") or "pending") == "pending"
    )


def render_ghidra_change_queue_panel(state: Dict[str, Any]) -> str:
    shared = (state or {}).get("shared_state") or {}
    proposals = list(shared.get("ghidra_change_proposals") or [])
    draft_proposals = list(shared.get("ghidra_change_draft_proposals") or [])
    queue_finalized = bool(shared.get("ghidra_change_queue_finalized"))
    parse_error = str(shared.get("ghidra_change_parse_error") or "").strip()
    pending = get_pending_ghidra_change_proposal(state)
    pending_count = sum(1 for item in proposals if str(item.get("status") or "pending") == "pending")

    if not proposals and not parse_error:
        waiting_detail = "No pending Ghidra rename/type/comment proposals for this run yet."
        waiting_badge = "approval-required edits appear here after proposal parsing"
        if draft_proposals and not queue_finalized:
            waiting_detail = (
                "Draft Ghidra change proposals have been collected from earlier stages. "
                "The visible approval queue will populate after the reporter finalizes the run."
            )
            waiting_badge = "waiting for reporter finalization"
        return (
            "<div data-ghidra-pending-count='0' style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #fbfbfc; margin-bottom: 12px;'>"
            "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
            "<strong>Ghidra Change Queue</strong>"
            f"<span style='color: #5f6368; font-size: 12px;'>{html.escape(waiting_badge)}</span>"
            "</div>"
            f"<div style='margin-top: 8px; color: #5f6368;'>{html.escape(waiting_detail)}</div>"
            "</div>"
        )

    error_html = ""
    if parse_error:
        error_html = (
            "<div style='margin-top: 8px; padding: 8px 10px; border: 1px solid #f3c3c7; border-radius: 8px; "
            "background: #fff5f5; color: #a61b29;'>"
            f"{html.escape(parse_error)}</div>"
        )

    pending_html = ""
    if pending:
        evidence = pending.get("evidence") or []
        evidence_missing = bool(pending.get("evidence_missing"))
        evidence_source = str(pending.get("evidence_source") or "").strip()
        if not evidence and isinstance(pending.get("raw"), dict):
            derived_evidence, derived_missing, derived_source = _extract_ghidra_proposal_evidence(
                pending.get("raw") or {}
            )
            evidence = derived_evidence
            evidence_missing = derived_missing
            if not evidence_source:
                evidence_source = derived_source
        evidence_html = "".join(
            f"<div style='margin-top: 2px; color: #5f6368;'>- {html.escape(str(item))}</div>"
            for item in evidence[:5]
        ) or "<div style='margin-top: 2px; color: #5f6368;'>- none supplied</div>"
        current_name = str(pending.get("current_name") or pending.get("variable_name") or pending.get("current_type") or "").strip()
        proposed_name = str(pending.get("proposed_name") or pending.get("proposed_type") or pending.get("prototype") or "").strip()
        summary = html.escape(str(pending.get("summary") or pending.get("id") or "proposal"))
        rationale = html.escape(str(pending.get("rationale") or ""))
        apply_text = "yes" if bool(pending.get("can_apply")) else "proposal only"
        apply_reason = html.escape(str(pending.get("apply_reason") or ""))
        action = str(pending.get("action") or "unknown").strip()
        function_address = str(pending.get("function_address") or "").strip()
        function_name = str(pending.get("function_name") or "").strip()
        address = str(pending.get("address") or function_address or "").strip()
        variable_name = str(pending.get("variable_name") or "").strip()
        current_type = str(pending.get("current_type") or "").strip()
        proposed_type = str(pending.get("proposed_type") or "").strip()
        prototype = str(pending.get("prototype") or "").strip()
        comment = str(pending.get("comment") or "").strip()
        evidence_warning = ""
        if evidence_missing:
            warning_text = "No structured evidence was supplied for this proposal."
            if evidence_source == "rationale_fallback":
                warning_text = (
                    "No structured evidence was supplied for this proposal. "
                    "The queue is showing a rationale fallback instead."
                )
            evidence_warning = (
                "<div style='margin-top: 6px; padding: 6px 8px; border: 1px solid #f1d89a; "
                "border-radius: 8px; background: #fff8e1; color: #7a5300;'>"
                f"{html.escape(warning_text)}</div>"
            )
        detail_parts: List[str] = []
        locator_parts: List[str] = []
        if function_address:
            locator_parts.append(f"<strong>function:</strong> {html.escape(function_address)}")
        elif function_name:
            locator_parts.append(f"<strong>function:</strong> {html.escape(function_name)}")
        if address and address != function_address:
            locator_parts.append(f"<strong>address:</strong> {html.escape(address)}")
        if variable_name:
            locator_parts.append(f"<strong>variable:</strong> {html.escape(variable_name)}")
        if locator_parts:
            detail_parts.append(
                "<div style='margin-top: 4px; color: #202124;'>"
                + " | ".join(locator_parts)
                + "</div>"
            )

        if action in {"set_decompiler_comment", "set_disassembly_comment"}:
            if comment:
                detail_parts.append(
                    "<div style='margin-top: 4px; color: #202124;'><strong>comment to add:</strong></div>"
                    "<div style='margin-top: 4px; padding: 8px 10px; border: 1px solid #e0e3e7; border-radius: 8px; "
                    "background: #f8f9fa; color: #202124; white-space: pre-wrap;'>"
                    f"{html.escape(comment)}"
                    "</div>"
                )
        elif action == "set_function_prototype":
            if current_name or function_name:
                detail_parts.append(
                    "<div style='margin-top: 4px; color: #202124;'>"
                    f"<strong>current:</strong> {html.escape(current_name or function_name or 'n/a')}"
                    "</div>"
                )
            if prototype:
                detail_parts.append(
                    "<div style='margin-top: 4px; color: #202124;'><strong>prototype to set:</strong></div>"
                    "<div style='margin-top: 4px; padding: 8px 10px; border: 1px solid #e0e3e7; border-radius: 8px; "
                    "background: #f8f9fa; color: #202124; white-space: pre-wrap;'>"
                    f"{html.escape(prototype)}"
                    "</div>"
                )
        elif action == "set_local_variable_type":
            detail_parts.append(
                "<div style='margin-top: 4px; color: #202124;'>"
                f"<strong>current type:</strong> {html.escape(current_type or 'n/a')}<br>"
                f"<strong>proposed type:</strong> {html.escape(proposed_type or 'n/a')}"
                "</div>"
            )
        elif current_name or proposed_name:
            detail_parts.append(
                "<div style='margin-top: 4px; color: #202124;'>"
                f"<strong>current:</strong> {html.escape(current_name or 'n/a')}<br>"
                f"<strong>proposed:</strong> {html.escape(proposed_name or 'n/a')}"
                "</div>"
            )
        field_line = "".join(detail_parts)
        pending_html = (
            "<div style='margin-top: 10px; padding: 10px 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #ffffff;'>"
            f"<div style='font-size: 14px; color: #202124;'><strong>Next pending:</strong> {summary}</div>"
            f"<div style='margin-top: 4px; color: #5f6368;'>id: {html.escape(str(pending.get('id') or ''))} | "
            f"action: {html.escape(action or 'unknown')} | "
            f"target: {html.escape(str(pending.get('target_kind') or 'unknown'))}</div>"
            f"{field_line}"
            f"<div style='margin-top: 4px; color: #5f6368;'><strong>auto-apply support:</strong> {html.escape(apply_text)}"
            + (f" ({apply_reason})" if apply_reason else "")
            + "</div>"
            + (f"<div style='margin-top: 4px; color: #202124;'><strong>rationale:</strong> {rationale}</div>" if rationale else "")
            + evidence_warning
            + "<div style='margin-top: 6px; color: #202124; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em;'>evidence</div>"
            + evidence_html
            + "</div>"
        )

    history_rows: List[str] = []
    for proposal in proposals[-8:]:
        status = str(proposal.get("status") or "pending")
        if status == "pending":
            continue
        tone = "#5f6368"
        if status == "applied":
            tone = "#1b6e3a"
        elif status in {"failed", "rejected"}:
            tone = "#a61b29"
        elif status == "approved_proposal_only":
            tone = "#8a3b12"
        history_rows.append(
            "<div style='margin-top: 6px; padding-top: 6px; border-top: 1px solid #e0e3e7;'>"
            f"<div style='font-size: 12px; color: {tone};'><strong>{html.escape(str(proposal.get('id') or ''))}</strong> - "
            f"{html.escape(status)}</div>"
            f"<div style='margin-top: 2px; color: #202124; font-size: 12px;'>{html.escape(str(proposal.get('summary') or ''))}</div>"
            + (
                f"<div style='margin-top: 2px; color: #5f6368; font-size: 12px;'>{html.escape(str(proposal.get('result_text') or proposal.get('error') or ''))}</div>"
                if str(proposal.get("result_text") or proposal.get("error") or "").strip()
                else ""
            )
            + "</div>"
        )

    history_html = ""
    if history_rows:
        history_html = (
            "<div style='margin-top: 10px;'>"
            "<div style='font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #5f6368;'>"
            "Recent approvals / rejections</div>"
            + "".join(history_rows)
            + "</div>"
        )

    queue_notice_html = ""
    if pending_count:
        queue_notice_html = (
            "<div style='margin-top: 10px; padding: 8px 10px; border: 1px solid #f4c98b; border-radius: 8px; "
            "background: #fff7e6; color: #8a3b12;'>"
            "Pending changes need attention. Read-only follow-up queries are allowed, but new edit-generating queries are gated until you approve or reject this queue."
            "</div>"
        )

    return (
        f"<div data-ghidra-pending-count='{pending_count}' style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #fbfbfc; margin-bottom: 12px;'>"
        "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
        "<strong>Ghidra Change Queue</strong>"
        f"<span style='color: #5f6368; font-size: 12px;'>pending approvals: {pending_count}</span>"
        "</div>"
        + error_html
        + queue_notice_html
        + pending_html
        + history_html
        + "</div>"
    )


def render_pipeline_todo_board(state: Dict[str, Any]) -> str:
    shared = (state or {}).get("shared_state") or {}
    progress = shared.get("pipeline_stage_progress") or []
    if not progress:
        return (
            "<div style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px;'>"
            "<strong>Pipeline tasks</strong><div style='margin-top: 6px; color: #5f6368;'>"
            "No active pipeline tasks.</div></div>"
        )

    now = time.time()
    rows: List[str] = []
    any_running = False
    for item in progress:
        status = str(item.get("status") or "pending")
        started = item.get("started_at_epoch")
        finished = item.get("finished_at_epoch")
        duration = item.get("duration_sec")
        if status == "running" and started is not None:
            elapsed = now - float(started)
            any_running = True
        elif finished is not None and started is not None:
            elapsed = float(duration) if duration is not None else (float(finished) - float(started))
        else:
            elapsed = None

        if status == "completed":
            box = "☑"
            tone = "#1b6e3a"
            status_label = "done"
        elif status == "failed":
            box = "☒"
            tone = "#a61b29"
            status_label = "failed"
        elif status == "running":
            box = "☐"
            tone = "#0b57d0"
            status_label = "running"
        else:
            box = "☐"
            tone = "#5f6368"
            status_label = "pending"

        stage_name = html.escape(str(item.get("stage_name") or "stage"))
        stage_kind = html.escape(str(item.get("stage_kind") or ""))
        subagents = ", ".join(item.get("subagents") or []) or "none"
        subagents_html = html.escape(subagents)
        error_html = ""
        if item.get("error"):
            error_tone = "#a61b29" if status == "failed" else "#8a3b12"
            error_html = (
                f"<div style='margin-top: 4px; color: {error_tone};'>"
                f"{html.escape(str(item.get('error')))}</div>"
            )

        started_attr = "" if started is None else f'{float(started):.6f}'
        finished_attr = "" if finished is None else f'{float(finished):.6f}'
        duration_attr = "" if duration is None else f'{float(duration):.6f}'
        timer_html = (
            "<span class='wf-stage-timer' "
            f"data-status='{html.escape(status)}' "
            f"data-started='{started_attr}' "
            f"data-finished='{finished_attr}' "
            f"data-duration='{duration_attr}'>"
            f"{_format_elapsed(elapsed)}"
            "</span>"
        )

        rows.append(
            "<div style='border: 1px solid #d5d8dd; border-radius: 10px; padding: 10px 12px; margin-top: 8px;'>"
            f"<div style='display: flex; justify-content: space-between; gap: 12px; align-items: center;'>"
            f"<div style='font-size: 15px;'><span style='font-size: 18px; margin-right: 8px;'>{box}</span>"
            f"<strong>{stage_name}</strong> <span style='color: #5f6368;'>({stage_kind})</span></div>"
            f"<div style='font-family: monospace; color: {tone};'>{timer_html}</div>"
            "</div>"
            f"<div style='margin-top: 4px; color: {tone}; text-transform: uppercase; font-size: 12px; letter-spacing: 0.04em;'>"
            f"{status_label}</div>"
            f"<div style='margin-top: 4px; color: #5f6368;'>subagents: {subagents_html}</div>"
            f"{error_html}"
            "</div>"
        )

    header_note = "live timers update while stages are running" if any_running else "latest stage checklist"
    return (
        "<div style='padding: 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #fbfbfc;'>"
        "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
        "<strong>Pipeline Tasks</strong>"
        f"<span style='color: #5f6368; font-size: 12px;'>{header_note}</span>"
        "</div>"
        + "".join(rows)
        + "</div>"
    )


def _plan_host_worker_assignments(
    planned_work_items: List[Dict[str, Any]],
    architecture: List[Tuple[str, int]],
) -> List[Dict[str, Any]]:
    slots = expand_architecture_slots(architecture)
    if not slots:
        return []

    slot_loads = {slot["slot_name"]: 0 for slot in slots}
    assignments: List[Dict[str, Any]] = []
    for index, work_item in enumerate(planned_work_items, start=1):
        recommended = {
            str(role).strip()
            for role in (work_item.get("recommended_roles") or [])
            if str(role).strip()
        }
        candidate_slots = [
            slot
            for slot in slots
            if slot["archetype_name"] in recommended or slot["slot_name"] in recommended
        ] or list(slots)
        chosen_slot = min(
            candidate_slots,
            key=lambda slot: (
                slot_loads.get(slot["slot_name"], 0),
                0 if (slot["archetype_name"] in recommended or slot["slot_name"] in recommended) else 1,
                slot["slot_name"],
            ),
        )
        slot_loads[chosen_slot["slot_name"]] = slot_loads.get(chosen_slot["slot_name"], 0) + 1
        assignments.append(
            {
                "index": index,
                "work_item": work_item,
                "slot_name": chosen_slot["slot_name"],
                "archetype_name": chosen_slot["archetype_name"],
            }
        )
    return assignments


_HOST_WORKER_SHARED_CONTEXT_KEYS = (
    "selected_pipeline_name",
    "deep_pipeline",
    "deep_architecture_name",
    "validated_sample_path",
    "validated_sample_path_source",
    "validated_sample_md5",
    "validated_sample_sha256",
    "validated_sample_image_base",
    "validated_sample_metadata_source",
    "analysis_target_kind",
    "analysis_target_reason",
    "analysis_target_original_path",
    "analysis_target_original_sha256",
    "analysis_target_packer",
    "analysis_target_packed_detected",
    "available_static_tools",
    "available_dynamic_tools",
    "available_sandbox_tools",
    "supports_dynamic_analysis",
    "supports_sandboxed_execution",
    "allow_parent_input",
    "shell_execution_mode",
    "validator_review_level",
    "auto_triage_status",
    "auto_triage_context_summary",
    "auto_triage_pre_sweep_summary",
    "auto_triage_sample_path",
    "auto_triage_sample_sha256",
    "validation_retry_count",
    "validation_max_retries",
    "validation_last_decision",
    "validation_replan_feedback",
)


def _compact_host_worker_context_text(text: str, *, max_chars: int) -> str:
    raw = str(text or "").strip()
    if not raw or len(raw) <= max_chars:
        return raw
    return raw[: max_chars - 15].rstrip() + "\n...[truncated]..."


def _narrow_host_worker_shared_state(shared_state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    source = dict(shared_state or {})
    narrowed: Dict[str, Any] = {}
    for key in _HOST_WORKER_SHARED_CONTEXT_KEYS:
        if key in source:
            narrowed[key] = source.get(key)
    narrowed["planned_work_items"] = []
    narrowed["auto_triage_context_summary"] = _compact_host_worker_context_text(
        str(narrowed.get("auto_triage_context_summary") or ""),
        max_chars=4000,
    )
    narrowed["auto_triage_pre_sweep_summary"] = _compact_host_worker_context_text(
        str(narrowed.get("auto_triage_pre_sweep_summary") or ""),
        max_chars=2500,
    )
    narrowed["validation_replan_feedback"] = _compact_host_worker_context_text(
        str(narrowed.get("validation_replan_feedback") or ""),
        max_chars=2000,
    )
    return narrowed


def _build_host_worker_prompt(
    *,
    stage_name: str,
    stage_kind: str,
    slot_name: str,
    archetype_name: str,
    work_item: Dict[str, Any],
    user_text: str,
    prior_stage_outputs: Dict[str, str],
    shared_state: Optional[Dict[str, Any]],
) -> str:
    narrowed_shared = _narrow_host_worker_shared_state(shared_state)
    trimmed_prior_outputs: Dict[str, str] = {}
    preflight_output = str(prior_stage_outputs.get("preflight") or "").strip()
    if preflight_output:
        trimmed_prior_outputs["preflight"] = _compact_host_worker_context_text(
            preflight_output,
            max_chars=3500,
        )
    base_prompt = build_stage_prompt(
        stage_name=f"{stage_name}.{slot_name}",
        stage_kind=stage_kind,
        user_text=user_text,
        prior_stage_outputs=trimmed_prior_outputs,
        architecture=[(archetype_name, 1)],
        shared_state=narrowed_shared,
    )

    work_item_id = str(work_item.get("id") or "").strip() or "work_item"
    objective = str(work_item.get("objective") or "").strip() or "No objective provided."
    evidence_targets = work_item.get("evidence_targets") or []
    evidence_lines = "\n".join(f"- {target}" for target in evidence_targets) if evidence_targets else "- none specified"

    return (
        f"{base_prompt}\n\n"
        "Assigned work item to execute now:\n"
        f"- work_item_id: {work_item_id}\n"
        f"- assigned_role: {archetype_name}\n"
        f"- assigned_slot: {slot_name}\n"
        f"- objective: {objective}\n"
        "- Execute this one work item only. Do not broaden into unrelated work items.\n"
        "- If you notice a dependency on another work item, note it briefly but continue focusing on the assigned objective.\n"
        "- Reuse earlier evidence already present in shared context before issuing a new broad catalog query.\n"
        "- Treat strings like `function_name @ 0xADDRESS` as display selectors, not canonical names. Strip the `@ address` suffix for name-based tools, or use the address with an address-based tool.\n"
        "- Avoid rerunning broad `list_functions`, `list_imports`, `list_strings`, or `list_data_items` sweeps unless the current objective truly needs a missing catalog slice.\n"
        "- Once you have mapped a dispatcher and its handler family well enough for this objective, stop re-decompiling the same handlers unless you need a new concrete fact.\n"
        "- Return an evidence-backed result for this work item.\n"
        "Evidence targets for this assignment:\n"
        f"{evidence_lines}"
    ).strip()


async def _run_host_worker_assignment(
    runtime: MultiAgentRuntime,
    stage_name: str,
    stage_kind: str,
    state: Dict[str, Any],
    user_text: str,
    prior_stage_outputs: Dict[str, str],
    assignment: Dict[str, Any],
    *,
    stage_model: str,
) -> Dict[str, Any]:
    slot_name = str(assignment["slot_name"])
    archetype_name = str(assignment["archetype_name"])
    work_item = dict(assignment["work_item"])
    work_item_id = str(work_item.get("id") or f"work_item_{assignment['index']}")
    role_key = f"host_worker::{slot_name}::{work_item_id}"
    prompt = _build_host_worker_prompt(
        stage_name=stage_name,
        stage_kind=stage_kind,
        slot_name=slot_name,
        archetype_name=archetype_name,
        work_item=work_item,
        user_text=user_text,
        prior_stage_outputs=prior_stage_outputs,
        shared_state=state.get("shared_state"),
    )

    append_status(
        state,
        f"Worker assignment started: {work_item_id} -> {slot_name} ({archetype_name})",
    )
    assignment_started_at = datetime.now().isoformat(timespec="seconds")
    _append_tool_log_entries(
        state,
        stage_name,
        [
            {
                "stage": stage_name,
                "kind": "worker_assignment_start",
                "source": slot_name,
                "work_item_id": work_item_id,
                "archetype_name": archetype_name,
                "model": str(stage_model or ""),
                "started_at": assignment_started_at,
            }
        ],
    )
    worker_t0 = time.perf_counter()
    _set_planned_work_item_status(
        state,
        work_item_id,
        "in_execution",
        slot_name=slot_name,
        started_at_epoch=time.time(),
        finished_at_epoch=None,
        duration_sec=None,
        error="",
    )
    max_attempts = 1 + _HOST_WORKER_MAX_TRANSIENT_RETRIES
    for attempt in range(1, max_attempts + 1):
        live_tool_log_token = _LIVE_TOOL_LOG_STATE.set(state)
        active_state_token = _ACTIVE_PIPELINE_STATE.set(state)
        active_stage_token = _ACTIVE_PIPELINE_STAGE.set(stage_name)
        try:
            agent, deps, resolved_model, executor_meta = build_host_worker_assignment_executor(
                runtime,
                stage_name=stage_name,
                slot_name=slot_name,
                archetype_name=archetype_name,
                work_item_id=work_item_id,
                stage_model=stage_model,
            )
            deps.ask_user = _make_parent_input_callback(state, f"{stage_name}/{slot_name}/{work_item_id}")
            model_run_started_at = datetime.now().isoformat(timespec="seconds")
            _append_tool_log_entries(
                state,
                stage_name,
                [
                    {
                        "stage": stage_name,
                        "kind": "model_run_start",
                        "source": slot_name,
                        "work_item_id": work_item_id,
                        "archetype_name": archetype_name,
                        "model": str(resolved_model or ""),
                        "attempt": attempt,
                        "started_at": model_run_started_at,
                        "isolated_backend": bool(executor_meta.get("isolated_backend")),
                        "backend_root": str(executor_meta.get("backend_root") or ""),
                        "context_manager_enabled": bool(executor_meta.get("context_manager_enabled")),
                        "memory_dir": str(executor_meta.get("memory_dir") or ""),
                    }
                ],
            )
            model_t0 = time.perf_counter()
            result = await _stage_agent_run_async(
                agent,
                prompt,
                message_history=None,
                deps=deps,
            )
            new_history = result.all_messages()
            output_text = str(result.output)
            duration_sec = time.perf_counter() - worker_t0
            model_duration_sec = time.perf_counter() - model_t0
            _append_tool_log_entries(
                state,
                stage_name,
                [
                    {
                        "stage": stage_name,
                        "kind": "model_run_finish",
                        "source": slot_name,
                        "work_item_id": work_item_id,
                        "archetype_name": archetype_name,
                        "model": str(resolved_model or ""),
                        "attempt": attempt,
                        "status": "ok",
                        "duration_sec": round(model_duration_sec, 6),
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                    }
                ],
            )
            _append_tool_log_entries(
                state,
                stage_name,
                [
                    {
                        "stage": stage_name,
                        "kind": "worker_assignment_finish",
                        "source": slot_name,
                        "work_item_id": work_item_id,
                        "archetype_name": archetype_name,
                        "model": str(resolved_model or ""),
                        "attempt": attempt,
                        "status": "ok",
                        "duration_sec": round(duration_sec, 6),
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                    }
                ],
            )
            if attempt > 1:
                append_status(
                    state,
                    (
                        f"Worker assignment recovered after retry: {work_item_id} -> {slot_name} "
                        f"on attempt {attempt}/{max_attempts}"
                    ),
                )
            return {
                "index": int(assignment["index"]),
                "work_item_id": work_item_id,
                "slot_name": slot_name,
                "archetype_name": archetype_name,
                "model": str(resolved_model or ""),
                "role_key": role_key,
                "history": new_history,
                "output_text": output_text,
                "usage": _result_usage_snapshot(result),
                "duration_sec": duration_sec,
                "model_duration_sec": model_duration_sec,
                "status": "ok",
                "retryable": False,
                "error_category": "",
                "executor_meta": dict(executor_meta or {}),
            }
        except Exception as error:
            duration_sec = time.perf_counter() - worker_t0
            error_text = _error_text(error)
            retryable = _is_retryable_host_worker_error(error)
            classification = _classify_runtime_error(error)
            _append_tool_log_entries(
                state,
                stage_name,
                [
                    {
                        "stage": stage_name,
                        "kind": "model_run_finish",
                        "source": slot_name,
                        "work_item_id": work_item_id,
                        "archetype_name": archetype_name,
                        "model": str(stage_model or ""),
                        "attempt": attempt,
                        "status": "failed",
                        "duration_sec": round(duration_sec, 6),
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                        "error": error_text,
                        "retryable": retryable,
                    },
                    {
                        "stage": stage_name,
                        "kind": "worker_assignment_finish",
                        "source": slot_name,
                        "work_item_id": work_item_id,
                        "archetype_name": archetype_name,
                        "model": str(stage_model or ""),
                        "attempt": attempt,
                        "status": "failed",
                        "duration_sec": round(duration_sec, 6),
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                        "error": error_text,
                        "retryable": retryable,
                    },
                ],
            )
            if retryable and attempt < max_attempts and not bool(state.get("cancel_requested")):
                backoff_sec = _host_worker_retry_backoff_sec(attempt - 1)
                append_status(
                    state,
                    (
                        f"Worker assignment transient failure: {work_item_id} -> {slot_name} "
                        f"attempt {attempt}/{max_attempts} ({error_text}); retrying in {backoff_sec:.1f}s"
                    ),
                )
                await asyncio.sleep(backoff_sec)
                continue
            return {
                "index": int(assignment["index"]),
                "work_item_id": work_item_id,
                "slot_name": slot_name,
                "archetype_name": archetype_name,
                "model": str(stage_model or ""),
                "role_key": role_key,
                "history": [],
                "output_text": "",
                "usage": _empty_usage_snapshot(),
                "duration_sec": duration_sec,
                "model_duration_sec": duration_sec,
                "status": "failed",
                "error": error_text,
                "retryable": retryable,
                "error_category": str(classification.get("category") or ""),
                "executor_meta": dict(executor_meta or {}) if "executor_meta" in locals() else {},
            }
        finally:
            _ACTIVE_PIPELINE_STAGE.reset(active_stage_token)
            _ACTIVE_PIPELINE_STATE.reset(active_state_token)
            _LIVE_TOOL_LOG_STATE.reset(live_tool_log_token)


def _merge_host_worker_results(results: List[Dict[str, Any]], concurrency_limit: int) -> str:
    ok_count = sum(1 for item in results if item.get("status") == "ok")
    failed_count = sum(1 for item in results if item.get("status") != "ok")
    sections: List[str] = [
        "Host-managed worker execution summary",
        f"- concurrency_limit: {concurrency_limit}",
        f"- completed_assignments: {ok_count}",
        f"- failed_assignments: {failed_count}",
    ]
    for item in results:
        work_item_id = str(item.get("work_item_id") or "work_item")
        slot_name = str(item.get("slot_name") or "worker")
        archetype_name = str(item.get("archetype_name") or "worker")
        status = str(item.get("status") or "unknown")
        duration = float(item.get("duration_sec") or 0.0)
        sections.extend(
            [
                "",
                f"## {work_item_id}",
                f"- assigned_role: {archetype_name}",
                f"- assigned_slot: {slot_name}",
                f"- status: {status}",
                f"- duration_sec: {duration:.1f}",
            ]
        )
        if status == "ok":
            sections.append(str(item.get("output_text") or "").strip())
        else:
            sections.append(f"Worker error: {item.get('error')}")
    return "\n".join(section for section in sections if section is not None).strip()


def _compact_auto_triage_report_text(text: str, *, max_lines: int = 28, max_chars: int = 5000) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
    compact = "\n".join(lines[:max_lines]).strip()
    if len(compact) > max_chars:
        compact = compact[: max_chars - 15].rstrip() + "\n...[truncated]..."
    return compact


def _build_auto_triage_context_summary(state: Dict[str, Any], final_output: str = "") -> str:
    shared = state.setdefault("shared_state", _new_shared_state())
    lines: List[str] = ["Reusable automated triage context"]
    status = str(shared.get("auto_triage_status") or "").strip()
    if status:
        lines.append(f"- status: {status}")
    last_run_at = str(shared.get("auto_triage_last_run_at") or "").strip()
    if last_run_at:
        lines.append(f"- last_run_at: {last_run_at}")
    sample_path = str(shared.get("auto_triage_sample_path") or shared.get("validated_sample_path") or "").strip()
    if sample_path:
        lines.append(f"- sample_path: {sample_path}")
    sample_sha256 = str(shared.get("auto_triage_sample_sha256") or shared.get("validated_sample_sha256") or "").strip()
    if sample_sha256:
        lines.append(f"- sample_sha256: {sample_sha256}")
    pre_sweep_summary = str(shared.get("auto_triage_pre_sweep_summary") or "").strip()
    if pre_sweep_summary:
        lines.extend(["", "Deterministic pre-sweeps:", pre_sweep_summary])
    report_text = _compact_auto_triage_report_text(final_output or str(shared.get("auto_triage_report") or ""))
    if report_text:
        lines.extend(["", "Latest automated triage report:", report_text])
    error = str(shared.get("auto_triage_last_error") or "").strip()
    if error:
        lines.extend(["", "Latest auto-triage error:", error])
    return "\n".join(lines).strip()


def _record_auto_triage_run(
    state: Dict[str, Any],
    *,
    status: str,
    report: str = "",
    error: str = "",
) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    shared["auto_triage_status"] = status
    shared["auto_triage_last_error"] = error
    shared["auto_triage_last_run_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    shared["auto_triage_sample_path"] = str(shared.get("validated_sample_path") or "").strip()
    shared["auto_triage_sample_sha256"] = str(shared.get("validated_sample_sha256") or "").strip()
    if report:
        shared["auto_triage_report"] = report
    shared["auto_triage_context_summary"] = _build_auto_triage_context_summary(state, report)
    runs = shared.setdefault("auto_triage_runs", [])
    runs.append(
        {
            "status": status,
            "at": shared["auto_triage_last_run_at"],
            "sample_path": shared["auto_triage_sample_path"],
            "sample_sha256": shared["auto_triage_sample_sha256"],
            "error": error,
        }
    )


async def _run_host_parallel_assignments_async(
    assignments: List[Dict[str, Any]],
    *,
    concurrency_limit: int,
    assignment_runner: Any,
    serial_archetypes: Tuple[str, ...],
) -> Dict[int, Dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency_limit)
    results_by_index_async: Dict[int, Dict[str, Any]] = {}
    serial_gate_names = {str(name or "").strip().lower() for name in serial_archetypes if str(name or "").strip()}
    archetype_gates = {name: asyncio.Semaphore(1) for name in serial_gate_names}

    async def _run_one(assignment: Dict[str, Any]) -> Dict[str, Any]:
        archetype_key = str(assignment.get("archetype_name") or "").strip().lower()
        gate = archetype_gates.get(archetype_key)
        if gate is not None:
            async with gate:
                async with semaphore:
                    return await assignment_runner(assignment)
        async with semaphore:
            return await assignment_runner(assignment)

    tasks = [asyncio.create_task(_run_one(assignment)) for assignment in assignments]
    for task in asyncio.as_completed(tasks):
        result = await task
        results_by_index_async[int(result["index"])] = result
    return results_by_index_async


def _run_host_parallel_worker_stage(
    runtime: MultiAgentRuntime,
    stage: Any,
    user_text: str,
    prior_stage_outputs: Dict[str, str],
    state: Dict[str, Any],
) -> str:
    """
    Function: _run_host_parallel_worker_stage
    Inputs:
      - runtime: fully built runtime object for the active pipeline.
      - stage: stage runtime object for the worker stage being executed.
      - user_text: original user request driving the run.
      - prior_stage_outputs: text outputs emitted by earlier pipeline stages.
      - state: mutable shared pipeline state for the current run.
    Description:
      Execute one worker stage by turning planner work items into host-managed
      assignments, scheduling those assignments under the concurrency rules, and
      merging the successful worker outputs back into one stage result.
    Outputs:
      Returns the merged worker-stage output text to feed into later stages.
    Side Effects:
      Updates shared pipeline state, appends status/tool history, records model
      usage, and may raise when every assignment fails.
    """
    _check_cancel_requested(state, location="before worker scheduling")
    planned_work_items = list(((state.get("shared_state") or {}).get("planned_work_items") or []))
    assignments = _plan_host_worker_assignments(planned_work_items, stage.architecture)
    if not assignments:
        raise RuntimeError("No host-manageable worker assignments were produced from planned work items.")

    # Cap host-level concurrency so the scheduler respects the configured
    # process-wide limit while still adapting to smaller assignment sets.
    concurrency_limit = max(1, min(MAX_PARALLEL_WORKERS, len(assignments)))
    append_status(
        state,
        (
            f"Stage {stage.name} using host-managed parallel execution "
            f"({len(assignments)} assignments, max_parallel={concurrency_limit})"
        ),
    )
    serial_archetypes_in_stage = sorted(
        {
            str(assignment.get("archetype_name") or "").strip()
            for assignment in assignments
            if str(assignment.get("archetype_name") or "").strip().lower() in SERIAL_HOST_WORKER_ARCHETYPES
        }
    )
    if serial_archetypes_in_stage:
        append_status(
            state,
            (
                "Stage "
                f"{stage.name} serializing host-worker agent runs for archetype(s): "
                f"{', '.join(serial_archetypes_in_stage)}"
            ),
        )
    loop_local_runtime = build_loop_local_host_worker_runtime(runtime)

    async def _run_all_assignments() -> Dict[int, Dict[str, Any]]:
        try:
            preentered_tool_ids = await _enter_mcp_toolsets_async(
                loop_local_runtime.static_tools,
                loop_local_runtime.dynamic_tools,
            )
            if preentered_tool_ids:
                append_status(
                    state,
                    (
                        f"Stage {stage.name} pre-entered loop-local MCP fleet "
                        f"({len(preentered_tool_ids)} server(s)) for host workers"
                    ),
                )
            results_by_index_async = await _run_host_parallel_assignments_async(
                assignments,
                concurrency_limit=concurrency_limit,
                serial_archetypes=SERIAL_HOST_WORKER_ARCHETYPES,
                assignment_runner=lambda assignment: _run_host_worker_assignment(
                    loop_local_runtime,
                    stage.name,
                    stage.stage_kind,
                    state,
                    user_text,
                    prior_stage_outputs,
                    assignment,
                    stage_model=str(stage.model or ""),
                ),
            )
            stage_retry_rounds_used = 0
            stage_retry_recovered_assignments = 0
            for retry_round in range(1, 1 + _HOST_WORKER_STAGE_FAILED_SUBSET_RETRIES):
                retry_assignments = [
                    assignment
                    for assignment in assignments
                    if (retry_result := results_by_index_async.get(int(assignment["index"]))) is not None
                    and retry_result.get("status") != "ok"
                    and _worker_result_retryable(retry_result)
                ]
                if not retry_assignments or bool(state.get("cancel_requested")):
                    break
                stage_retry_rounds_used = retry_round
                backoff_sec = _host_worker_stage_retry_backoff_sec(retry_round - 1)
                append_status(
                    state,
                    (
                        f"Stage retry triggered: {stage.name} rerunning {len(retry_assignments)} "
                        f"transiently failed worker assignment(s) round {retry_round}/"
                        f"{_HOST_WORKER_STAGE_FAILED_SUBSET_RETRIES}"
                        + (f" in {backoff_sec:.1f}s" if backoff_sec > 0 else "")
                    ),
                )
                if backoff_sec > 0:
                    await asyncio.sleep(backoff_sec)
                retried_results = await _run_host_parallel_assignments_async(
                    retry_assignments,
                    concurrency_limit=max(1, min(concurrency_limit, len(retry_assignments))),
                    serial_archetypes=SERIAL_HOST_WORKER_ARCHETYPES,
                    assignment_runner=lambda assignment: _run_host_worker_assignment(
                        loop_local_runtime,
                        stage.name,
                        stage.stage_kind,
                        state,
                        user_text,
                        prior_stage_outputs,
                        assignment,
                        stage_model=str(stage.model or ""),
                    ),
                )
                recovered_this_round = 0
                for index, retried_result in retried_results.items():
                    prior_result = dict(results_by_index_async.get(index) or {})
                    if prior_result.get("status") != "ok" and retried_result.get("status") == "ok":
                        recovered_this_round += 1
                    results_by_index_async[index] = retried_result
                stage_retry_recovered_assignments += recovered_this_round
                append_status(
                    state,
                    (
                        f"Stage retry finished: {stage.name} recovered {recovered_this_round}/"
                        f"{len(retry_assignments)} retried worker assignment(s)"
                    ),
                )
            state.setdefault("shared_state", _new_shared_state())["host_worker_stage_retry_summary"] = {
                "stage_name": stage.name,
                "retry_rounds_used": stage_retry_rounds_used,
                "max_retry_rounds": int(_HOST_WORKER_STAGE_FAILED_SUBSET_RETRIES),
                "recovered_assignments": stage_retry_recovered_assignments,
            }
            for result in [results_by_index_async[idx] for idx in sorted(results_by_index_async)]:
                _check_cancel_requested(state, location="during worker stage")
                _record_model_usage(
                    state,
                    phase="host_worker_assignment",
                    stage_name=stage.name,
                    model=str(result.get("model") or ""),
                    usage=result.get("usage") or {},
                    slot_name=str(result.get("slot_name") or ""),
                    work_item_id=str(result.get("work_item_id") or ""),
                )
                history = list(result.get("history") or [])
                set_role_history(state, str(result.get("role_key") or ""), history)
                append_tool_log_delta(state, stage.name, [], history)
                update_validated_sample_path_from_messages(
                    state,
                    history,
                    f"tool_return:{stage.name}:{result.get('slot_name')}",
                )
                if result.get("status") == "ok":
                    _set_planned_work_item_status(
                        state,
                        str(result.get("work_item_id") or ""),
                        "completed",
                        slot_name=str(result.get("slot_name") or ""),
                        finished_at_epoch=time.time(),
                        duration_sec=float(result.get("duration_sec") or 0.0),
                        error="",
                    )
                    update_validated_sample_path(
                        state,
                        str(result.get("output_text") or ""),
                        f"stage:{stage.name}:{result.get('slot_name')}",
                        explicit_only=True,
                    )
                    append_status(
                        state,
                        (
                            f"Worker assignment finished: {result.get('work_item_id')} -> "
                            f"{result.get('slot_name')} in {float(result.get('duration_sec') or 0.0):.1f}s"
                        ),
                    )
                else:
                    _set_planned_work_item_status(
                        state,
                        str(result.get("work_item_id") or ""),
                        "blocked",
                        slot_name=str(result.get("slot_name") or ""),
                        finished_at_epoch=time.time(),
                        duration_sec=float(result.get("duration_sec") or 0.0),
                        error=str(result.get("error") or ""),
                    )
                    _set_pipeline_stage_status(
                        state,
                        stage.name,
                        stage_kind=stage.stage_kind,
                        subagents=list(stage.subagent_names),
                        status="running",
                        error=(
                            f"Latest assignment failure: {result.get('work_item_id')} -> "
                            f"{result.get('slot_name')} ({result.get('error')})"
                        ),
                    )
                    append_status(
                        state,
                        (
                            f"Worker assignment failed: {result.get('work_item_id')} -> "
                            f"{result.get('slot_name')} after {float(result.get('duration_sec') or 0.0):.1f}s "
                            f"({result.get('error')})"
                        ),
                    )
            return results_by_index_async
        finally:
            await _close_mcp_toolsets_async(loop_local_runtime.static_tools, loop_local_runtime.dynamic_tools)

    results_by_index = asyncio.run(_run_all_assignments())

    ordered_results = [results_by_index[idx] for idx in sorted(results_by_index)]
    failed_results = [item for item in ordered_results if item.get("status") != "ok"]
    # Persist a compact summary even when some assignments fail so the harness
    # can classify the run accurately after the pipeline returns.
    shared = state.setdefault("shared_state", _new_shared_state())
    shared["host_worker_assignment_summary"] = {
        "stage_name": stage.name,
        "concurrency_limit": concurrency_limit,
        "serialized_archetypes": serial_archetypes_in_stage,
        "total_assignments": len(ordered_results),
        "completed_assignments": len(ordered_results) - len(failed_results),
        "failed_assignments": len(failed_results),
        "all_assignments_failed": len(failed_results) == len(ordered_results),
        "stage_retry_rounds_used": int((((shared.get("host_worker_stage_retry_summary") or {}) if isinstance(shared.get("host_worker_stage_retry_summary"), dict) else {}) or {}).get("retry_rounds_used") or 0),
        "stage_retry_recovered_assignments": int((((shared.get("host_worker_stage_retry_summary") or {}) if isinstance(shared.get("host_worker_stage_retry_summary"), dict) else {}) or {}).get("recovered_assignments") or 0),
        "failed_work_items": [
            {
                "work_item_id": str(item.get("work_item_id") or ""),
                "slot_name": str(item.get("slot_name") or ""),
                "archetype_name": str(item.get("archetype_name") or ""),
                "error": str(item.get("error") or ""),
                "error_category": str(item.get("error_category") or ""),
                "retryable": bool(item.get("retryable")),
            }
            for item in failed_results
        ],
    }
    if not any(item.get("status") == "ok" for item in ordered_results):
        append_status(
            state,
            (
                f"Stage contained failure: {stage.name} finished with all "
                f"{len(ordered_results)} host-managed worker assignments failed"
            ),
        )
    return _merge_host_worker_results(ordered_results, concurrency_limit)


def run_deepagent_pipeline(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> str:
    """
    Function: run_deepagent_pipeline
    Inputs:
      - runtime: fully constructed runtime containing the selected pipeline and
        worker architecture.
      - user_text: user request or evaluation prompt for the current run.
      - state: mutable shared state dictionary that accumulates progress,
        histories, validation state, and final outputs across stages.
    Description:
      Execute the configured workflow from the first stage through the reporter,
      including planner parsing, validator retry loops, worker execution, and
      final output normalization.
    Outputs:
      Returns the final report text emitted by the pipeline.
    Side Effects:
      Mutates the shared state extensively, appends UI/status history, performs
      MCP tool calls and model calls, and records final pipeline metadata.
    """
    append_status(
        state,
        (
            f"Deep pipeline started (pipeline={runtime.pipeline_name}, "
            f"worker_breadth={runtime.worker_architecture_name}, "
            f"stages={', '.join(stage.name for stage in runtime.stages)})"
        ),
    )
    t0 = time.perf_counter()

    if "shared_state" not in state:
        state["shared_state"] = _new_shared_state()

    shared = state["shared_state"]
    shared["task_outputs"] = []
    shared["pipeline_stage_outputs"] = []
    shared["turn_task_runs"] = 0
    shared["last_user_request"] = user_text
    shared["execution_mode"] = "deep_pipeline"
    shared["allow_parent_input"] = bool(state.get("allow_parent_input"))
    shared["shell_execution_mode"] = _normalize_shell_execution_mode(
        state.get("shell_execution_mode", DEFAULT_SHELL_EXECUTION_MODE)
    )
    shared["validator_review_level"] = _normalize_validator_review_level(
        state.get("validator_review_level", state.get("validator_strict_mode", "default"))
    )
    shared["deep_architecture_name"] = runtime.worker_architecture_name
    shared["deep_architecture"] = list(runtime.worker_architecture)
    shared["deep_subagents"] = expand_architecture_names(runtime.worker_architecture)
    shared["deep_pipeline_name"] = runtime.pipeline_name
    shared["deep_pipeline"] = list(runtime.pipeline_definition)
    shared["available_static_tools"] = list(runtime.static_tool_ids)
    shared["available_dynamic_tools"] = list(runtime.dynamic_tool_ids)
    shared["available_sandbox_tools"] = list(runtime.sandbox_tool_ids)
    shared["supports_dynamic_analysis"] = bool(runtime.dynamic_tool_ids)
    shared["supports_sandboxed_execution"] = bool(runtime.sandbox_tool_ids)
    shared["planned_work_items"] = []
    shared["planned_work_item_status"] = {}
    shared["planned_work_items_parse_error"] = ""
    shared["ghidra_change_proposals"] = []
    shared["ghidra_change_draft_proposals"] = []
    shared["ghidra_change_queue_finalized"] = False
    shared["ghidra_change_parse_error"] = ""
    shared["generated_yara_rules"] = []
    shared["generated_yara_rule_parse_error"] = ""
    shared["validation_retry_count"] = 0
    shared["validation_max_retries"] = MAX_VALIDATION_REPLAN_RETRIES
    shared["validation_last_decision"] = ""
    shared["validation_replan_feedback"] = ""
    shared["validation_history"] = []
    shared["pipeline_duration_sec"] = 0.0
    shared["last_pipeline_error"] = {}
    shared["last_stage_request_fingerprint"] = {}
    shared["model_usage_totals"] = _empty_usage_snapshot()
    shared["model_usage_by_stage"] = {}
    shared["model_usage_events"] = []
    shared["host_worker_assignment_summary"] = {}
    shared["host_parallel_worker_execution"] = HOST_PARALLEL_WORKER_EXECUTION
    shared["max_parallel_workers"] = MAX_PARALLEL_WORKERS
    state["pending_parent_input"] = _empty_parent_input()
    if runtime.pipeline_name == "auto_triage":
        shared["auto_triage_status"] = "running"
        shared["auto_triage_last_error"] = ""
        shared["auto_triage_pre_sweeps"] = {}
        shared["auto_triage_pre_sweep_summary"] = ""
        shared["auto_triage_report"] = ""
    _seed_pipeline_stage_progress(
        state,
        [(stage.name, stage.stage_kind, list(stage.subagent_names)) for stage in runtime.stages],
    )
    update_validated_sample_path(state, user_text, "user_request", explicit_only=False)

    prior_stage_outputs: Dict[str, str] = {}
    final_output = ""
    stage_name_to_index = {stage.name: idx for idx, stage in enumerate(runtime.stages)}
    planner_restart_index = next(
        (idx for idx, stage in enumerate(runtime.stages) if stage_kind_flag(stage.stage_kind, "parses_planner_work_items")),
        next((idx for idx, stage in enumerate(runtime.stages) if stage_kind_flag(stage.stage_kind, "supports_parallel_assignments")), 0),
    )
    restart_stage_names = [stage.name for stage in runtime.stages[planner_restart_index:]]
    stage_index = 0

    while stage_index < len(runtime.stages):
        _check_cancel_requested(state, location="before stage start")
        stage = runtime.stages[stage_index]
        stage_meta = get_stage_kind_metadata(stage.stage_kind)
        stage.deps.ask_user = _make_parent_input_callback(state, stage.name)
        role_key = f"pipeline_{stage.name}"
        old_history = get_role_history(state, role_key)
        stage_prompt = build_stage_prompt(
            stage_name=stage.name,
            stage_kind=stage.stage_kind,
            user_text=user_text,
            prior_stage_outputs=prior_stage_outputs,
            architecture=stage.architecture,
            shared_state=state.get("shared_state"),
        )

        append_status(
            state,
            (
                f"Stage started: {stage.name} "
                f"(kind={stage.stage_kind}, subagents={', '.join(stage.subagent_names) or 'none'})"
            ),
        )
        _set_pipeline_stage_status(
            state,
            stage.name,
            stage_kind=stage.stage_kind,
            subagents=list(stage.subagent_names),
            status="running",
        )
        if stage_meta["supports_parallel_assignments"] and not (
            HOST_PARALLEL_WORKER_EXECUTION and (state.get("shared_state") or {}).get("planned_work_items")
        ):
            for work_item in list((state.get("shared_state") or {}).get("planned_work_items") or []):
                _set_planned_work_item_status(
                    state,
                    str(work_item.get("id") or ""),
                    "in_execution",
                    started_at_epoch=time.time(),
                    error="",
                )
        stage_t0 = time.perf_counter()
        live_tool_log_token = _LIVE_TOOL_LOG_STATE.set(state)
        active_state_token = _ACTIVE_PIPELINE_STATE.set(state)
        active_stage_token = _ACTIVE_PIPELINE_STAGE.set(stage.name)
        try:
            _check_cancel_requested(state, location=f"before executing {stage.name}")
            # Tutorial 2.5 in extension_tutorial.md: add the execution branch
            # for each new `stage_kind` here and keep its shared-state/status
            # behavior aligned with the existing stage implementations.
            if stage.stage_kind == "deterministic_presweeps":
                stage_output, presweep_bundle = run_deterministic_presweeps_sync(runtime, state)
                shared["auto_triage_pre_sweeps"] = presweep_bundle
                shared["auto_triage_pre_sweep_summary"] = stage_output
                result = None
            elif (
                stage_meta["supports_parallel_assignments"]
                and HOST_PARALLEL_WORKER_EXECUTION
                and (state.get("shared_state") or {}).get("planned_work_items")
            ):
                stage_output = _run_host_parallel_worker_stage(
                    runtime,
                    stage,
                    user_text,
                    prior_stage_outputs,
                    state,
                )
                result = None
            else:
                result = _run_stage_agent_sync_with_guardrails(
                    stage=stage,
                    stage_prompt=stage_prompt,
                    old_history=old_history,
                    state=state,
                )
        except Exception as e:
            error_info = _classify_runtime_error(e)
            shared["last_pipeline_error"] = {
                "stage_name": stage.name,
                "stage_kind": stage.stage_kind,
                "error_text": str(error_info.get("error_text") or ""),
                "category": str(error_info.get("category") or "unknown"),
                "retryable": bool(error_info.get("retryable")),
                "request_fingerprint": dict(shared.get("last_stage_request_fingerprint") or {}),
                "occurred_at": datetime.now().isoformat(timespec="seconds"),
            }
            if stage_meta["supports_parallel_assignments"]:
                status_map = ((state.get("shared_state") or {}).get("planned_work_item_status") or {})
                for work_item in list((state.get("shared_state") or {}).get("planned_work_items") or []):
                    work_item_id = str(work_item.get("id") or "")
                    current = str((status_map.get(work_item_id) or {}).get("status") or "").strip().lower()
                    if current == "completed":
                        continue
                    _set_planned_work_item_status(
                        state,
                        work_item_id,
                        "blocked",
                        finished_at_epoch=time.time(),
                        error=f"{type(e).__name__}: {e}",
                    )
            _set_pipeline_stage_status(
                state,
                stage.name,
                stage_kind=stage.stage_kind,
                subagents=list(stage.subagent_names),
                status="failed",
                error=f"{type(e).__name__}: {e}",
            )
            append_status(
                state,
                (
                    f"Stage failed: {stage.name} after {time.perf_counter() - stage_t0:.1f}s "
                    f"({type(e).__name__}, category={error_info.get('category')}, retryable={bool(error_info.get('retryable'))})"
                ),
            )
            if runtime.pipeline_name == "auto_triage":
                _record_auto_triage_run(
                    state,
                    status="failed",
                    error=str(error_info.get("error_text") or f"{type(e).__name__}: {e}"),
                )
            raise
        finally:
            _ACTIVE_PIPELINE_STAGE.reset(active_stage_token)
            _ACTIVE_PIPELINE_STATE.reset(active_state_token)
            _LIVE_TOOL_LOG_STATE.reset(live_tool_log_token)

        if result is not None:
            new_history = result.all_messages()
            set_role_history(state, role_key, new_history)
            append_tool_log_delta(state, stage.name, old_history, new_history)
            update_validated_sample_path_from_messages(
                state,
                new_history[len(old_history) if old_history else 0:],
                f"tool_return:{stage.name}",
            )
            stage_output = str(result.output)
            _record_model_usage(
                state,
                phase="pipeline_stage",
                stage_name=stage.name,
                model=str(stage.model or ""),
                usage=_result_usage_snapshot(result),
            )
        if stage_meta["parses_planner_work_items"]:
            update_planned_work_items_from_planner_output(state, stage_output)
        if stage_meta["supports_parallel_assignments"] or stage_meta["finalizes_report"]:
            update_ghidra_change_proposals_from_stage_output(
                state,
                stage_output,
                stage_name=stage.name,
                stage_kind=stage.stage_kind,
            )
        if stage_meta["finalizes_report"]:
            update_generated_yara_rules_from_stage_output(
                state,
                runtime,
                stage_output,
                stage_name=stage.name,
                stage_kind=stage.stage_kind,
            )
        if not stage_meta["finalizes_report"]:
            update_validated_sample_path(
                state,
                stage_output,
                f"stage:{stage.name}",
                explicit_only=True,
            )
        prior_stage_outputs[stage.name] = stage_output
        if stage_meta["finalizes_report"]:
            final_output = _annotate_unapproved_ghidra_aliases(
                _sanitize_user_facing_output(stage_output),
                state.get("shared_state"),
            )
        else:
            final_output = stage_output
        if stage_meta["supports_parallel_assignments"] and not (
            HOST_PARALLEL_WORKER_EXECUTION and (state.get("shared_state") or {}).get("planned_work_items")
        ):
            for work_item in list((state.get("shared_state") or {}).get("planned_work_items") or []):
                _set_planned_work_item_status(
                    state,
                    str(work_item.get("id") or ""),
                    "completed",
                    finished_at_epoch=time.time(),
                    error="",
                )

        stage_entry = {
            "task_id": f"stage:{stage.name}",
            "worker": stage.stage_kind,
            "objective": f"Pipeline stage `{stage.name}`",
            "status": "ok",
            "output_text": stage_output,
            "subagents": list(stage.subagent_names),
        }
        worker_failure_count = 0
        worker_stage_summary = {}
        if stage_meta["supports_parallel_assignments"] and HOST_PARALLEL_WORKER_EXECUTION:
            worker_stage_summary = dict(((state.get("shared_state") or {}).get("host_worker_assignment_summary") or {}))
            if str(worker_stage_summary.get("stage_name") or "") == stage.name:
                worker_failure_count = int(worker_stage_summary.get("failed_assignments") or 0)
        if worker_failure_count > 0:
            stage_entry["status"] = "failed"
            stage_entry["worker_assignment_summary"] = worker_stage_summary
        state["shared_state"]["pipeline_stage_outputs"].append(
            {
                "stage_name": stage.name,
                "stage_kind": stage.stage_kind,
                "subagents": list(stage.subagent_names),
                "output_text": stage_output,
            }
        )
        if stage_meta["finalizes_report"]:
            stage_entry["output_text"] = final_output
        state["shared_state"]["task_outputs"].append(stage_entry)
        state["shared_state"]["turn_task_runs"] = int(state["shared_state"].get("turn_task_runs", 0)) + 1
        state["shared_state"]["total_task_runs"] = int(state["shared_state"].get("total_task_runs", 0)) + 1
        if worker_failure_count > 0:
            _set_pipeline_stage_status(
                state,
                stage.name,
                stage_kind=stage.stage_kind,
                subagents=list(stage.subagent_names),
                status="failed",
                error=f"{worker_failure_count} host worker assignment(s) failed",
            )
        else:
            _set_pipeline_stage_status(
                state,
                stage.name,
                stage_kind=stage.stage_kind,
                subagents=list(stage.subagent_names),
                status="completed",
            )
        compact_shared_state(state)
        if worker_failure_count > 0:
            append_status(
                state,
                (
                    f"Stage finished with assignment failures: {stage.name} "
                    f"in {time.perf_counter() - stage_t0:.1f}s ({worker_failure_count} failed assignment(s))"
                ),
            )
        else:
            append_status(state, f"Stage finished: {stage.name} in {time.perf_counter() - stage_t0:.1f}s")
        _check_cancel_requested(state, location=f"after stage {stage.name}")

        if stage_meta["runs_validation_gate"]:
            required_signoffs = max(1, len(stage.subagent_names) or len(stage.architecture) or 1)
            gate, gate_error = extract_validation_gate(stage_output, required_signoffs=required_signoffs)
            shared["validation_history"].append(
                {
                    "attempt": int(shared.get("validation_retry_count") or 0),
                    "stage_name": stage.name,
                    "decision": str(gate.get("decision") or "reject"),
                    "signoff_count": gate.get("signoff_count"),
                    "required_signoffs": gate.get("required_signoffs", required_signoffs),
                    "parse_error": gate_error,
                    "out_of_scope_work_items": list(gate.get("out_of_scope_work_items") or []),
                    "rejection_reasons": list(gate.get("rejection_reasons") or []),
                    "planner_fixes": list(gate.get("planner_fixes") or []),
                }
            )
            if gate_error:
                append_status(state, f"Validation gate parse warning: {gate_error}")

            accepted = bool(gate.get("accepted")) and not gate_error
            shared["validation_last_decision"] = "accept" if accepted else "reject"

            if accepted:
                shared["validation_replan_feedback"] = ""
                append_status(
                    state,
                    (
                        "Validation gate accepted "
                        f"({gate.get('signoff_count', required_signoffs)}/{gate.get('required_signoffs', required_signoffs)} signoffs)"
                    ),
                )
            else:
                feedback = _format_validation_feedback(gate, stage_output, gate_error)
                shared["validation_replan_feedback"] = feedback
                retries_used = int(shared.get("validation_retry_count") or 0)
                if retries_used < MAX_VALIDATION_REPLAN_RETRIES:
                    retries_used += 1
                    shared["validation_retry_count"] = retries_used
                    append_status(
                        state,
                        (
                            "Validation gate rejected; returning to planner "
                            f"(replan {retries_used}/{MAX_VALIDATION_REPLAN_RETRIES})"
                        ),
                    )
                    _reset_pipeline_stages_to_pending(state, restart_stage_names)
                    _clear_stage_role_histories(state, restart_stage_names)
                    shared["planned_work_items"] = []
                    shared["planned_work_item_status"] = {}
                    shared["planned_work_items_parse_error"] = ""
                    shared["ghidra_change_proposals"] = []
                    shared["ghidra_change_draft_proposals"] = []
                    shared["ghidra_change_queue_finalized"] = False
                    shared["ghidra_change_parse_error"] = ""
                    prior_stage_outputs = {
                        name: output
                        for name, output in prior_stage_outputs.items()
                        if stage_name_to_index.get(name, -1) < planner_restart_index
                    }
                    final_output = ""
                    compact_shared_state(state)
                    stage_index = planner_restart_index
                    continue

                _set_pipeline_stage_status(
                    state,
                    stage.name,
                    stage_kind=stage.stage_kind,
                    subagents=list(stage.subagent_names),
                    status="failed",
                    error="Validation gate rejected after max replans",
                )
                append_status(
                    state,
                    (
                        "Validation gate rejected after max replans; "
                        "returning provisional output before reporter stage"
                    ),
                )
                final_output = _build_validation_failure_fallback_output(
                    state,
                    gate,
                    stage_output,
                    gate_error,
                )
                if runtime.pipeline_name == "auto_triage":
                    _record_auto_triage_run(
                        state,
                        status="failed",
                        report=final_output,
                        error="Validation gate rejected after max replans",
                    )
                shared["run_count"] = int(shared.get("run_count", 0)) + 1
                shared["pipeline_duration_sec"] = round(time.perf_counter() - t0, 6)
                shared["final_output"] = final_output
                append_status(state, f"Deep pipeline stopped in {time.perf_counter() - t0:.1f}s")
                return final_output

        stage_index += 1

    shared["run_count"] = int(shared.get("run_count", 0)) + 1
    shared["pipeline_duration_sec"] = round(time.perf_counter() - t0, 6)
    shared["final_output"] = final_output
    if runtime.pipeline_name == "auto_triage":
        _record_auto_triage_run(
            state,
            status="succeeded",
            report=final_output,
        )
    append_status(state, f"Deep pipeline finished in {time.perf_counter() - t0:.1f}s")
    return final_output
