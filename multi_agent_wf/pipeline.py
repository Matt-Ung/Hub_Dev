from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from pydantic_ai import ModelMessage

from .config import (
    DEEP_AGENT_ARCHITECTURE,
    DEEP_AGENT_ARCHITECTURE_NAME,
    DEFAULT_SHELL_EXECUTION_MODE,
    HOST_PARALLEL_WORKER_EXECUTION,
    MAX_PARALLEL_WORKERS,
    MAX_VALIDATION_REPLAN_RETRIES,
    PLANNER_WORK_ITEMS_END,
    PLANNER_WORK_ITEMS_START,
    VALIDATION_DECISION_END,
    VALIDATION_DECISION_START,
    _normalize_shell_execution_mode,
    _normalize_validator_review_level,
)
from .runtime import (
    MultiAgentRuntime,
    _ACTIVE_PIPELINE_STAGE,
    _ACTIVE_PIPELINE_STATE,
    _LIVE_TOOL_LOG_STATE,
    build_host_worker_assignment_executor,
    build_stage_prompt,
    expand_architecture_slots,
    expand_architecture_names,
)
from .shared_state import (
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
        if raw_stage.get("use_worker_architecture"):
            architecture = list(DEEP_AGENT_ARCHITECTURE)
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
    shared["planned_work_items_parse_error"] = error
    if items:
        append_status(state, f"Planner work items parsed: {len(items)}")
    elif error:
        append_status(state, f"Planner work-item parse warning: {error}")
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


def _planner_work_item_rollup(progress: List[Dict[str, Any]]) -> Tuple[str, str, str]:
    statuses = {str(item.get("stage_name") or ""): str(item.get("status") or "pending") for item in progress}
    if any(status == "failed" for status in statuses.values()):
        return "☒", "#a61b29", "blocked"
    if statuses.get("reporter") == "completed":
        return "☑", "#1b6e3a", "completed"
    if statuses.get("reporter") == "running":
        return "☑", "#0b57d0", "reporting"
    if statuses.get("validators") == "completed":
        return "☑", "#1b6e3a", "validated"
    if statuses.get("validators") == "running":
        return "☑", "#0b57d0", "under review"
    if statuses.get("workers") == "completed":
        return "☑", "#1b6e3a", "executed"
    if statuses.get("workers") == "running":
        return "☐", "#0b57d0", "in execution"
    if statuses.get("planner") == "completed":
        return "☐", "#5f6368", "planned"
    if statuses.get("planner") == "running":
        return "☐", "#0b57d0", "drafting"
    if statuses.get("preflight") == "completed":
        return "☐", "#5f6368", "context ready"
    if statuses.get("preflight") == "running":
        return "☐", "#0b57d0", "preflight"
    return "☐", "#5f6368", "pending"


def render_planned_work_items_panel(state: Dict[str, Any]) -> str:
    shared = (state or {}).get("shared_state") or {}
    items = shared.get("planned_work_items") or []
    parse_error = str(shared.get("planned_work_items_parse_error") or "").strip()
    progress = shared.get("pipeline_stage_progress") or []
    planner_status = ""
    preflight_status = ""
    for item in progress:
        if str(item.get("stage_name") or "") == "planner":
            planner_status = str(item.get("status") or "")
        elif str(item.get("stage_name") or "") == "preflight":
            preflight_status = str(item.get("status") or "")
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

    _, tone, status_label = _planner_work_item_rollup(progress)
    rows: List[str] = []
    for item in items:
        item_id = html.escape(str(item.get("id") or ""))
        objective = html.escape(str(item.get("objective") or ""))
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
    validator_entry = next((item for item in progress if str(item.get("stage_kind") or "") == "validators"), None) or {}
    planner_entry = next((item for item in progress if str(item.get("stage_kind") or "") == "planner"), None) or {}
    worker_entry = next((item for item in progress if str(item.get("stage_kind") or "") == "workers"), None) or {}

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

    if validator_status == "running":
        tone = "#0b57d0"
        badge_bg = "#e8f0fe"
        headline = "Validation in progress"
        detail = "Validators are reviewing worker evidence."
    elif last_decision == "accept":
        tone = "#1b6e3a"
        badge_bg = "#e6f4ea"
        headline = "Validation accepted"
        if signoff_count is not None and required_signoffs is not None:
            detail = f"Validator signoff: {signoff_count}/{required_signoffs}"
        else:
            detail = "Validated findings are cleared for reporting."
    elif last_decision == "reject":
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


def _build_host_worker_prompt(
    *,
    slot_name: str,
    archetype_name: str,
    work_item: Dict[str, Any],
    user_text: str,
    prior_stage_outputs: Dict[str, str],
    shared_state: Optional[Dict[str, Any]],
) -> str:
    narrowed_shared = dict(shared_state or {})
    narrowed_shared["planned_work_items"] = []
    trimmed_prior_outputs: Dict[str, str] = {}
    preflight_output = str(prior_stage_outputs.get("preflight") or "").strip()
    if preflight_output:
        trimmed_prior_outputs["preflight"] = preflight_output
    base_prompt = build_stage_prompt(
        stage_name=f"workers.{slot_name}",
        stage_kind="workers",
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
        "- Return an evidence-backed result for this work item.\n"
        "Evidence targets for this assignment:\n"
        f"{evidence_lines}"
    ).strip()


def _run_host_worker_assignment(
    runtime: MultiAgentRuntime,
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
    worker_t0 = time.perf_counter()
    old_history = get_role_history(state, role_key)

    live_tool_log_token = _LIVE_TOOL_LOG_STATE.set(state)
    active_state_token = _ACTIVE_PIPELINE_STATE.set(state)
    active_stage_token = _ACTIVE_PIPELINE_STAGE.set("workers")
    try:
        agent, deps = build_host_worker_assignment_executor(
            runtime,
            stage_name="workers",
            slot_name=slot_name,
            archetype_name=archetype_name,
            stage_model=stage_model,
        )
        deps.ask_user = _make_parent_input_callback(state, f"workers/{slot_name}/{work_item_id}")
        result = agent.run_sync(
            prompt,
            message_history=old_history if old_history else None,
            deps=deps,
        )
        new_history = result.all_messages()
        output_text = str(result.output)
        duration_sec = time.perf_counter() - worker_t0
        return {
            "index": int(assignment["index"]),
            "work_item_id": work_item_id,
            "slot_name": slot_name,
            "archetype_name": archetype_name,
            "role_key": role_key,
            "history": new_history,
            "output_text": output_text,
            "duration_sec": duration_sec,
            "status": "ok",
        }
    except Exception as e:
        duration_sec = time.perf_counter() - worker_t0
        return {
            "index": int(assignment["index"]),
            "work_item_id": work_item_id,
            "slot_name": slot_name,
            "archetype_name": archetype_name,
            "role_key": role_key,
            "history": [],
            "output_text": "",
            "duration_sec": duration_sec,
            "status": "failed",
            "error": f"{type(e).__name__}: {e}",
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


def _run_host_parallel_worker_stage(
    runtime: MultiAgentRuntime,
    stage: Any,
    user_text: str,
    prior_stage_outputs: Dict[str, str],
    state: Dict[str, Any],
) -> str:
    _check_cancel_requested(state, location="before worker scheduling")
    planned_work_items = list(((state.get("shared_state") or {}).get("planned_work_items") or []))
    assignments = _plan_host_worker_assignments(planned_work_items, stage.architecture)
    if not assignments:
        raise RuntimeError("No host-manageable worker assignments were produced from planned work items.")

    concurrency_limit = max(1, min(MAX_PARALLEL_WORKERS, len(assignments)))
    append_status(
        state,
        (
            f"Worker stage using host-managed parallel execution "
            f"({len(assignments)} assignments, max_parallel={concurrency_limit})"
        ),
    )

    results_by_index: Dict[int, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=concurrency_limit, thread_name_prefix="host-worker") as executor:
        future_map = {
            executor.submit(
                _run_host_worker_assignment,
                runtime,
                state,
                user_text,
                prior_stage_outputs,
                assignment,
                stage_model=str(stage.model or ""),
            ): assignment
            for assignment in assignments
        }
        for future in as_completed(future_map):
            _check_cancel_requested(state, location="during worker stage")
            assignment = future_map[future]
            result = future.result()
            results_by_index[int(result["index"])] = result
            history = list(result.get("history") or [])
            set_role_history(state, str(result.get("role_key") or ""), history)
            append_tool_log_delta(state, "workers", [], history)
            update_validated_sample_path_from_messages(
                state,
                history,
                f"tool_return:workers:{result.get('slot_name')}",
            )
            if result.get("status") == "ok":
                update_validated_sample_path(
                    state,
                    str(result.get("output_text") or ""),
                    f"stage:workers:{result.get('slot_name')}",
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

    ordered_results = [results_by_index[idx] for idx in sorted(results_by_index)]
    if not any(item.get("status") == "ok" for item in ordered_results):
        raise RuntimeError("All host-managed worker assignments failed.")
    return _merge_host_worker_results(ordered_results, concurrency_limit)


def run_deepagent_pipeline(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> str:
    append_status(
        state,
        (
            f"Deep pipeline started (pipeline={runtime.pipeline_name}, "
            f"worker_breadth={DEEP_AGENT_ARCHITECTURE_NAME}, "
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
    shared["deep_architecture_name"] = DEEP_AGENT_ARCHITECTURE_NAME
    shared["deep_architecture"] = list(DEEP_AGENT_ARCHITECTURE)
    shared["deep_subagents"] = expand_architecture_names(DEEP_AGENT_ARCHITECTURE)
    shared["deep_pipeline_name"] = runtime.pipeline_name
    shared["deep_pipeline"] = list(runtime.pipeline_definition)
    shared["available_static_tools"] = list(runtime.static_tool_ids)
    shared["available_dynamic_tools"] = list(runtime.dynamic_tool_ids)
    shared["available_sandbox_tools"] = list(runtime.sandbox_tool_ids)
    shared["supports_dynamic_analysis"] = bool(runtime.dynamic_tool_ids)
    shared["supports_sandboxed_execution"] = bool(runtime.sandbox_tool_ids)
    shared["planned_work_items"] = []
    shared["planned_work_items_parse_error"] = ""
    shared["validation_retry_count"] = 0
    shared["validation_max_retries"] = MAX_VALIDATION_REPLAN_RETRIES
    shared["validation_last_decision"] = ""
    shared["validation_replan_feedback"] = ""
    shared["validation_history"] = []
    shared["host_parallel_worker_execution"] = HOST_PARALLEL_WORKER_EXECUTION
    shared["max_parallel_workers"] = MAX_PARALLEL_WORKERS
    state["pending_parent_input"] = _empty_parent_input()
    _seed_pipeline_stage_progress(
        state,
        [(stage.name, stage.stage_kind, list(stage.subagent_names)) for stage in runtime.stages],
    )
    update_validated_sample_path(state, user_text, "user_request", explicit_only=False)

    prior_stage_outputs: Dict[str, str] = {}
    final_output = ""
    stage_name_to_index = {stage.name: idx for idx, stage in enumerate(runtime.stages)}
    planner_restart_index = next(
        (idx for idx, stage in enumerate(runtime.stages) if stage.stage_kind == "planner"),
        next((idx for idx, stage in enumerate(runtime.stages) if stage.stage_kind == "workers"), 0),
    )
    restart_stage_names = [stage.name for stage in runtime.stages[planner_restart_index:]]
    stage_index = 0

    while stage_index < len(runtime.stages):
        _check_cancel_requested(state, location="before stage start")
        stage = runtime.stages[stage_index]
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
        stage_t0 = time.perf_counter()
        live_tool_log_token = _LIVE_TOOL_LOG_STATE.set(state)
        active_state_token = _ACTIVE_PIPELINE_STATE.set(state)
        active_stage_token = _ACTIVE_PIPELINE_STAGE.set(stage.name)
        try:
            _check_cancel_requested(state, location=f"before executing {stage.name}")
            if (
                stage.stage_kind == "workers"
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
                result = stage.agent.run_sync(
                    stage_prompt,
                    message_history=old_history if old_history else None,
                    deps=stage.deps,
                )
        except Exception as e:
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
                f"Stage failed: {stage.name} after {time.perf_counter() - stage_t0:.1f}s ({type(e).__name__})",
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
        if stage.stage_kind == "planner":
            update_planned_work_items_from_planner_output(state, stage_output)
        if stage.stage_kind != "reporter":
            update_validated_sample_path(
                state,
                stage_output,
                f"stage:{stage.name}",
                explicit_only=True,
            )
        prior_stage_outputs[stage.name] = stage_output
        final_output = _sanitize_user_facing_output(stage_output) if stage.stage_kind == "reporter" else stage_output

        stage_entry = {
            "task_id": f"stage:{stage.name}",
            "worker": stage.stage_kind,
            "objective": f"Pipeline stage `{stage.name}`",
            "status": "ok",
            "output_text": stage_output,
            "subagents": list(stage.subagent_names),
        }
        state["shared_state"]["pipeline_stage_outputs"].append(
            {
                "stage_name": stage.name,
                "stage_kind": stage.stage_kind,
                "subagents": list(stage.subagent_names),
                "output_text": stage_output,
            }
        )
        if stage.stage_kind == "reporter":
            stage_entry["output_text"] = final_output
        state["shared_state"]["task_outputs"].append(stage_entry)
        state["shared_state"]["turn_task_runs"] = int(state["shared_state"].get("turn_task_runs", 0)) + 1
        state["shared_state"]["total_task_runs"] = int(state["shared_state"].get("total_task_runs", 0)) + 1
        _set_pipeline_stage_status(
            state,
            stage.name,
            stage_kind=stage.stage_kind,
            subagents=list(stage.subagent_names),
            status="completed",
        )
        compact_shared_state(state)
        append_status(state, f"Stage finished: {stage.name} in {time.perf_counter() - stage_t0:.1f}s")
        _check_cancel_requested(state, location=f"after stage {stage.name}")

        if stage.stage_kind == "validators":
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
                    shared["planned_work_items_parse_error"] = ""
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
                shared["run_count"] = int(shared.get("run_count", 0)) + 1
                shared["final_output"] = final_output
                append_status(state, f"Deep pipeline stopped in {time.perf_counter() - t0:.1f}s")
                return final_output

        stage_index += 1

    shared["run_count"] = int(shared.get("run_count", 0)) + 1
    shared["final_output"] = final_output
    append_status(state, f"Deep pipeline finished in {time.perf_counter() - t0:.1f}s")
    return final_output
