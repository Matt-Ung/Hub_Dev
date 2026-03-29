from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from pydantic_ai import ModelMessage

from .config import (
    DEFAULT_SHELL_EXECUTION_MODE,
    HOST_PARALLEL_WORKER_EXECUTION,
    GHIDRA_CHANGE_PROPOSALS_END,
    GHIDRA_CHANGE_PROPOSALS_START,
    MAX_PARALLEL_WORKERS,
    MAX_VALIDATION_REPLAN_RETRIES,
    PLANNER_WORK_ITEMS_END,
    PLANNER_WORK_ITEMS_START,
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
    _LIVE_TOOL_LOG_STATE,
    _direct_mcp_tool_call_sync,
    _find_mcp_server_by_marker,
    _parse_jsonish_tool_result,
    build_host_worker_assignment_executor,
    build_stage_prompt,
    expand_architecture_slots,
    expand_architecture_names,
    normalize_ghidra_change_proposal,
    prepare_ghidra_change_operation,
    run_deterministic_presweeps_sync,
)
from .shared_state import (
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
            evidence = _normalize_string_list(raw_item.get("evidence") or raw_item.get("evidence_targets"))
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
        field_line = ""
        if current_name or proposed_name:
            field_line = (
                "<div style='margin-top: 4px; color: #202124;'>"
                f"<strong>current:</strong> {html.escape(current_name or 'n/a')}<br>"
                f"<strong>proposed:</strong> {html.escape(proposed_name or 'n/a')}"
                "</div>"
            )
        pending_html = (
            "<div style='margin-top: 10px; padding: 10px 12px; border: 1px solid #d5d8dd; border-radius: 10px; background: #ffffff;'>"
            f"<div style='font-size: 14px; color: #202124;'><strong>Next pending:</strong> {summary}</div>"
            f"<div style='margin-top: 4px; color: #5f6368;'>id: {html.escape(str(pending.get('id') or ''))} | "
            f"action: {html.escape(str(pending.get('action') or 'unknown'))} | "
            f"target: {html.escape(str(pending.get('target_kind') or 'unknown'))}</div>"
            f"{field_line}"
            f"<div style='margin-top: 4px; color: #5f6368;'><strong>auto-apply support:</strong> {html.escape(apply_text)}"
            + (f" ({apply_reason})" if apply_reason else "")
            + "</div>"
            + (f"<div style='margin-top: 4px; color: #202124;'><strong>rationale:</strong> {rationale}</div>" if rationale else "")
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
    narrowed_shared = dict(shared_state or {})
    narrowed_shared["planned_work_items"] = []
    trimmed_prior_outputs: Dict[str, str] = {}
    preflight_output = str(prior_stage_outputs.get("preflight") or "").strip()
    if preflight_output:
        trimmed_prior_outputs["preflight"] = preflight_output
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
        "- Return an evidence-backed result for this work item.\n"
        "Evidence targets for this assignment:\n"
        f"{evidence_lines}"
    ).strip()


def _run_host_worker_assignment(
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
    old_history = get_role_history(state, role_key)

    live_tool_log_token = _LIVE_TOOL_LOG_STATE.set(state)
    active_state_token = _ACTIVE_PIPELINE_STATE.set(state)
    active_stage_token = _ACTIVE_PIPELINE_STAGE.set(stage_name)
    try:
        agent, deps = build_host_worker_assignment_executor(
            runtime,
            stage_name=stage_name,
            slot_name=slot_name,
            archetype_name=archetype_name,
            stage_model=stage_model,
        )
        deps.ask_user = _make_parent_input_callback(state, f"{stage_name}/{slot_name}/{work_item_id}")
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
            f"Stage {stage.name} using host-managed parallel execution "
            f"({len(assignments)} assignments, max_parallel={concurrency_limit})"
        ),
    )

    results_by_index: Dict[int, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=concurrency_limit, thread_name_prefix="host-worker") as executor:
        future_map = {
            executor.submit(
                _run_host_worker_assignment,
                runtime,
                stage.name,
                stage.stage_kind,
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

    ordered_results = [results_by_index[idx] for idx in sorted(results_by_index)]
    if not any(item.get("status") == "ok" for item in ordered_results):
        raise RuntimeError("All host-managed worker assignments failed.")
    return _merge_host_worker_results(ordered_results, concurrency_limit)


def run_deepagent_pipeline(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> str:
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
                result = stage.agent.run_sync(
                    stage_prompt,
                    message_history=old_history if old_history else None,
                    deps=stage.deps,
                )
        except Exception as e:
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
                f"Stage failed: {stage.name} after {time.perf_counter() - stage_t0:.1f}s ({type(e).__name__})",
            )
            if runtime.pipeline_name == "auto_triage":
                _record_auto_triage_run(
                    state,
                    status="failed",
                    error=f"{type(e).__name__}: {e}",
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
                shared["final_output"] = final_output
                append_status(state, f"Deep pipeline stopped in {time.perf_counter() - t0:.1f}s")
                return final_output

        stage_index += 1

    shared["run_count"] = int(shared.get("run_count", 0)) + 1
    shared["final_output"] = final_output
    if runtime.pipeline_name == "auto_triage":
        _record_auto_triage_run(
            state,
            status="succeeded",
            report=final_output,
        )
    append_status(state, f"Deep pipeline finished in {time.perf_counter() - t0:.1f}s")
    return final_output
