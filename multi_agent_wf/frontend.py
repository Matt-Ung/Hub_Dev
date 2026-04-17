from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from threading import Event, Thread
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import gradio as gr

from .config import (
    AUTOMATION_DEFAULT_ARCHITECTURE_NAME,
    AUTOMATION_DEFAULT_REQUEST_PROFILE,
    AUTOMATION_DEFAULT_PROMPT_TEMPLATE,
    AUTOMATION_TRIGGER_ENABLED,
    AUTOMATION_TRIGGER_HEALTH_PATH,
    AUTOMATION_TRIGGER_HOST,
    AUTOMATION_TRIGGER_PATH,
    AUTOMATION_TRIGGER_PORT,
    DEEP_AGENT_ARCHITECTURE_PRESETS,
    DEEP_AGENT_ARCHITECTURE_NAME,
    DEEP_AGENT_AUTO_SELECT_PIPELINE,
    DEEP_AGENT_PIPELINE_DESCRIPTIONS,
    DEEP_AGENT_PIPELINE_NAME,
    DEEP_AGENT_PIPELINE_PRESETS,
    DEFAULT_VALIDATOR_REVIEW_LEVEL,
    PIPELINE_LOG_SLOTS,
    PATH_HANDOFF_LINE_PREFIX,
    VALIDATOR_REVIEW_LEVEL_CHOICES,
    _normalize_automation_request_profile,
    _normalize_validator_review_level,
    stage_kind_flag,
)
from .pipeline import (
    PipelineCancelled,
    _stage_progress_from_pipeline_definition,
    get_pending_change_count,
    get_pending_change_proposal,
    get_pending_ghidra_change_count,
    get_pending_ghidra_change_proposal,
    render_change_queue_panel,
    render_automation_status_panel,
    render_pipeline_todo_board,
    render_ghidra_change_queue_panel,
    render_planned_work_items_panel,
    render_validation_gate_panel,
    run_deepagent_pipeline,
)
from .runtime import (
    apply_change_proposal_sync,
    apply_ghidra_change_proposal_sync,
    build_run_local_pipeline_runtime,
    get_pipeline_definition_sync,
    get_runtime_sync,
    is_edit_intent_query,
    select_architecture_name_for_query_sync,
    select_pipeline_name_for_query_sync,
    shutdown_runtime_sync,
)
from .shared_state import (
    _get_ui_snapshot,
    _new_shared_state,
    _sanitize_user_facing_output,
    _shorten,
    _snapshot_state_default,
    _store_ui_snapshot,
    apply_automation_payload_to_state,
    append_status,
    preserved_automation_shared_state,
    record_automation_event,
)

_AUTOMATION_TRIGGER_SERVER: ThreadingHTTPServer | None = None
_AUTOMATION_TRIGGER_LOCK = Lock()
_AUTOMATION_TRIGGER_PENDING = False
_AUTOMATION_RUN_HISTORY: Dict[str, Dict[str, Any]] = {}
_FRONTEND_HEAD_PATH = Path(__file__).resolve().parent / "assets" / "frontend_head.html"
_AUTOMATION_STATUS_PATH = "/automation/status"

# Tutorial 1.5 in extension_tutorial.md: preset names auto-populate here from
# workflow config. Tutorial 4.2: add a new helper/control only when you are
# introducing a brand new workflow knob, not just another preset name.
_PIPELINE_PRESET_CHOICES = [("DYNAMIC (agent chooses)", "dynamic")] + [
    (name, name) for name in DEEP_AGENT_PIPELINE_PRESETS.keys()
]
_ARCHITECTURE_PRESET_CHOICES = [("DYNAMIC (agent chooses)", "dynamic")] + [
    (name, name) for name in DEEP_AGENT_ARCHITECTURE_PRESETS.keys()
]


def _resolve_automation_architecture_name(payload: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    requested = str(
        (payload or {}).get("automation_architecture_name")
        or (payload or {}).get("architecture_name")
        or (payload or {}).get("worker_architecture_name")
        or ""
    ).strip()
    default_name = str(AUTOMATION_DEFAULT_ARCHITECTURE_NAME or "automation_triage").strip() or "automation_triage"
    if not requested:
        return default_name, "automation default"
    if requested.lower() in {"auto", "dynamic"}:
        return "dynamic", "payload override"
    if requested in DEEP_AGENT_ARCHITECTURE_PRESETS:
        return requested, "payload override"
    return default_name, f"invalid payload override {requested!r}; using automation default"


def _load_frontend_head() -> str:
    try:
        content = _FRONTEND_HEAD_PATH.read_text(encoding="utf-8")
        status_host = AUTOMATION_TRIGGER_HOST if AUTOMATION_TRIGGER_ENABLED else ""
        status_port = str(AUTOMATION_TRIGGER_PORT) if AUTOMATION_TRIGGER_ENABLED else ""
        status_path = _AUTOMATION_STATUS_PATH if AUTOMATION_TRIGGER_ENABLED else ""
        return (
            content.replace("__AUTOMATION_STATUS_HOST__", status_host)
            .replace("__AUTOMATION_STATUS_PORT__", status_port)
            .replace("__AUTOMATION_STATUS_PATH__", status_path)
        )
    except FileNotFoundError:
        return ""


# ----------------------------
# Gradio handlers
# ----------------------------

def _message_input(value: str = "", interactive: bool = True, visible: bool = True):
    return gr.update(value=value, interactive=interactive, visible=visible)


def _send_button(interactive: bool = True, visible: bool = True):
    return gr.update(interactive=interactive, visible=visible)


def _cancel_button(interactive: bool = True, visible: bool = True):
    return gr.update(interactive=interactive, visible=visible)


def _validator_review_level_dropdown(state: Dict[str, Any], interactive: bool = True, visible: bool = True):
    value = _normalize_validator_review_level(
        (state or {}).get("validator_review_level", (state or {}).get("validator_strict_mode", "default"))
    )
    return gr.update(
        choices=VALIDATOR_REVIEW_LEVEL_CHOICES,
        value=value,
        interactive=interactive,
        visible=visible,
    )


def _pipeline_auto_select_checkbox(state: Dict[str, Any], interactive: bool = True, visible: bool = True):
    return gr.update(
        value=bool((state or {}).get("deep_agent_auto_select_pipeline", DEEP_AGENT_AUTO_SELECT_PIPELINE)),
        interactive=interactive,
        visible=False,
    )


def _architecture_preset_dropdown(state: Dict[str, Any], interactive: bool = True, visible: bool = True):
    value = str((state or {}).get("deep_agent_architecture_name", DEEP_AGENT_ARCHITECTURE_NAME)).strip()
    if value.lower() in {"dynamic", "auto"}:
        value = "dynamic"
    elif value not in DEEP_AGENT_ARCHITECTURE_PRESETS:
        value = DEEP_AGENT_ARCHITECTURE_NAME
    return gr.update(
        choices=_ARCHITECTURE_PRESET_CHOICES,
        value=value,
        interactive=interactive,
        visible=visible,
    )


def _pipeline_preset_dropdown(state: Dict[str, Any], interactive: bool = True, visible: bool = True):
    value = str((state or {}).get("deep_agent_pipeline_name", DEEP_AGENT_PIPELINE_NAME)).strip()
    if bool((state or {}).get("deep_agent_auto_select_pipeline", DEEP_AGENT_AUTO_SELECT_PIPELINE)):
        value = "dynamic"
    elif value not in DEEP_AGENT_PIPELINE_PRESETS:
        value = DEEP_AGENT_PIPELINE_NAME
    return gr.update(
        choices=_PIPELINE_PRESET_CHOICES,
        value=value,
        interactive=interactive,
        visible=visible,
    )


def _todo_board(state: Dict[str, Any], visible: bool):
    return gr.update(value=render_pipeline_todo_board(state), visible=visible)


def _planned_work_items_board(state: Dict[str, Any]):
    return gr.update(value=render_planned_work_items_panel(state), visible=True)


def _validation_gate_board(state: Dict[str, Any]):
    return gr.update(value=render_validation_gate_panel(state), visible=True)


def _has_validation_gate(state: Dict[str, Any]) -> bool:
    state = state or {}
    shared = (state.get("shared_state") or {})

    progress = shared.get("pipeline_stage_progress") or []
    if any(
        (
            bool(item.get("runs_validation_gate"))
            or stage_kind_flag(str(item.get("stage_kind") or "").strip(), "runs_validation_gate")
        )
        for item in progress
        if isinstance(item, dict)
    ):
        return True

    if (
        shared.get("validation_history")
        or str(shared.get("validation_last_decision") or "").strip()
        or str(shared.get("validation_replan_feedback") or "").strip()
    ):
        return True

    deep_pipeline = shared.get("deep_pipeline") or []
    if any(
        stage_kind_flag(str((stage or {}).get("stage_kind") or "").strip(), "runs_validation_gate")
        for stage in deep_pipeline
        if isinstance(stage, dict)
    ):
        return True

    pipeline_name = str(
        shared.get("selected_pipeline_name")
        or state.get("deep_agent_pipeline_name")
        or ""
    ).strip()
    if not pipeline_name or pipeline_name == "dynamic":
        return False

    pipeline_definition = DEEP_AGENT_PIPELINE_PRESETS.get(pipeline_name) or []
    return any(
        stage_kind_flag(str((stage or {}).get("stage_kind") or "").strip(), "runs_validation_gate")
        for stage in pipeline_definition
        if isinstance(stage, dict)
    )


def _validation_gate_container(state: Dict[str, Any]):
    return gr.update(visible=_has_validation_gate(state))


def _automation_status_board(state: Dict[str, Any]):
    return gr.update(
        value=render_automation_status_panel(state),
        visible=bool(AUTOMATION_TRIGGER_ENABLED),
    )


def _ghidra_change_queue_board(state: Dict[str, Any]):
    return gr.update(value=render_change_queue_panel(state), visible=True)


def _pending_change_proposals(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    shared = (state or {}).get("shared_state") or {}
    queue_finalized = bool(shared.get("change_queue_finalized") or shared.get("ghidra_change_queue_finalized"))
    if not queue_finalized:
        return []
    proposals = list(shared.get("change_queue_proposals") or shared.get("ghidra_change_proposals") or [])
    return [
        proposal
        for proposal in proposals
        if str(proposal.get("status") or "pending").strip().lower() == "pending"
    ]


def _change_queue_choice_label(proposal: Dict[str, Any]) -> str:
    proposal_id = str(proposal.get("id") or "").strip()
    summary = str(proposal.get("summary") or proposal_id or "proposal").strip()
    category = str(proposal.get("change_category") or "").strip().lower().replace("_", " ") or "change"
    target = str(proposal.get("target_kind") or proposal.get("target_system") or "").strip() or "target"
    return f"{summary} [{category}] ({target}) :: {proposal_id}"


def _normalize_selected_change_proposal_id(state: Dict[str, Any]) -> str:
    pending = _pending_change_proposals(state)
    valid_ids = [str(proposal.get("id") or "").strip() for proposal in pending if str(proposal.get("id") or "").strip()]
    current = str((state or {}).get("selected_change_proposal_id") or "").strip()
    normalized = current if current in valid_ids else (valid_ids[0] if valid_ids else "")
    if isinstance(state, dict):
        state["selected_change_proposal_id"] = normalized
    return normalized


def _resolve_selected_change_proposal(state: Dict[str, Any], selected_proposal_id: str = "") -> Optional[Dict[str, Any]]:
    pending = _pending_change_proposals(state)
    if not pending:
        if isinstance(state, dict):
            state["selected_change_proposal_id"] = ""
        return None
    requested = str(selected_proposal_id or "").strip()
    if requested:
        for proposal in pending:
            if str(proposal.get("id") or "").strip() == requested:
                if isinstance(state, dict):
                    state["selected_change_proposal_id"] = requested
                return proposal
    normalized = _normalize_selected_change_proposal_id(state)
    for proposal in pending:
        if str(proposal.get("id") or "").strip() == normalized:
            return proposal
    return pending[0]


def _change_queue_selector(state: Dict[str, Any], active: bool):
    pending = _pending_change_proposals(state)
    choices = [(_change_queue_choice_label(proposal), str(proposal.get("id") or "").strip()) for proposal in pending]
    value = _normalize_selected_change_proposal_id(state)
    return gr.update(
        choices=choices,
        value=(value or None),
        interactive=(not active) and bool(choices),
        visible=bool(choices),
    )


def _approve_change_button(state: Dict[str, Any], active: bool):
    has_pending = _resolve_selected_change_proposal(state) is not None
    return gr.update(interactive=(not active) and has_pending, visible=True)


def _reject_change_button(state: Dict[str, Any], active: bool):
    has_pending = _resolve_selected_change_proposal(state) is not None
    return gr.update(interactive=(not active) and has_pending, visible=True)


def _tool_log_text_for_stage(state: Dict[str, Any], stage_name: str, stage_kind: str) -> str:
    state = state or {}
    sections = state.get("tool_log_sections") or {}
    progress = ((state.get("shared_state") or {}).get("pipeline_stage_progress") or [])
    progress_map = {
        str(item.get("stage_name") or ""): item
        for item in progress
    }
    stage_entry = progress_map.get(stage_name) or {}
    status = str(stage_entry.get("status") or "pending")
    log_text = str(sections.get(stage_name) or "").strip()
    header = f"phase: {stage_name} ({stage_kind})\nstatus: {status}"
    if not log_text:
        return f"{header}\n\nNo tool calls recorded for this phase yet."
    return f"{header}\n\n{log_text}"


def _tool_log_updates(state: Dict[str, Any]) -> Tuple[Any, ...]:
    return tuple(
        gr.update(value=_tool_log_text_for_stage(state, stage_name, stage_kind))
        for stage_name, stage_kind in PIPELINE_LOG_SLOTS
    )


def _tool_log_skip_updates() -> Tuple[Any, ...]:
    return tuple(gr.skip() for _ in PIPELINE_LOG_SLOTS)


def _ui_updates(
    message_update: Any,
    chat_history: Any,
    state: Dict[str, Any],
    validator_review_level_update: Any,
    pipeline_auto_select_update: Any,
    architecture_preset_update: Any,
    pipeline_preset_update: Any,
    automation_status_update: Any,
    validation_gate_container_update: Any,
    validation_gate_update: Any,
    planned_work_items_update: Any,
    ghidra_change_queue_update: Any,
    change_selector_update: Any,
    approve_change_update: Any,
    reject_change_update: Any,
    send_update: Any,
    cancel_update: Any,
    clear_update: Any,
    todo_update: Any,
) -> Tuple[Any, ...]:
    return (
        message_update,
        chat_history,
        state,
        validator_review_level_update,
        pipeline_auto_select_update,
        architecture_preset_update,
        pipeline_preset_update,
        automation_status_update,
        validation_gate_container_update,
        validation_gate_update,
        planned_work_items_update,
        ghidra_change_queue_update,
        change_selector_update,
        approve_change_update,
        reject_change_update,
        *_tool_log_updates(state),
        send_update,
        cancel_update,
        clear_update,
        todo_update,
    )


def _restore_snapshot_outputs(snapshot: Dict[str, Any]):
    state = snapshot.get("state") or _snapshot_state_default()
    chat_history = snapshot.get("chat_history") or []
    active = bool(snapshot.get("run_active"))
    composer_visible = bool(snapshot.get("composer_visible", True)) and not active
    send_visible = bool(snapshot.get("send_visible", True)) and not active
    cancel_visible = active
    clear_visible = bool(snapshot.get("clear_visible", True)) and not active
    todo_visible = bool(snapshot.get("todo_visible", False)) or active
    return _ui_updates(
        _message_input(
            value="",
            interactive=composer_visible,
            visible=composer_visible,
        ),
        chat_history,
        state,
        _validator_review_level_dropdown(
            state,
            interactive=not active,
            visible=True,
        ),
        _pipeline_auto_select_checkbox(
            state,
            interactive=not active,
            visible=True,
        ),
        _architecture_preset_dropdown(
            state,
            interactive=not active,
            visible=True,
        ),
        _pipeline_preset_dropdown(
            state,
            interactive=not active,
            visible=True,
        ),
        _automation_status_board(state),
        _validation_gate_container(state),
        _validation_gate_board(state),
        _planned_work_items_board(state),
        _ghidra_change_queue_board(state),
        _change_queue_selector(state, active),
        _approve_change_button(state, active),
        _reject_change_button(state, active),
        _send_button(
            interactive=send_visible,
            visible=send_visible,
        ),
        _cancel_button(
            interactive=cancel_visible,
            visible=cancel_visible,
        ),
        _send_button(
            interactive=clear_visible,
            visible=clear_visible,
        ),
        _todo_board(state, visible=todo_visible),
    )


def restore_last_ui():
    return _restore_snapshot_outputs(_get_ui_snapshot())


def poll_active_ui_snapshot():
    snapshot = _get_ui_snapshot()
    if not snapshot.get("run_active"):
        return (
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            *_tool_log_skip_updates(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
        )
    return _restore_snapshot_outputs(snapshot)


def chat_turn(
    user_text: str,
    chat_history: List[Dict[str, str]],
    state: Dict[str, Any],
    validator_review_level_value: str,
    pipeline_auto_select_value: bool,
    architecture_preset_value: str,
    pipeline_preset_value: str,
):
    user_text = (user_text or "").strip()
    if not user_text:
        yield _ui_updates(
            _message_input(value="", interactive=True, visible=True),
            chat_history,
            state,
            _validator_review_level_dropdown(state, interactive=True, visible=True),
            _pipeline_auto_select_checkbox(state, interactive=True, visible=True),
            _architecture_preset_dropdown(state, interactive=True, visible=True),
            _pipeline_preset_dropdown(state, interactive=True, visible=True),
            _automation_status_board(state),
            _validation_gate_container(state),
            _validation_gate_board(state),
            _planned_work_items_board(state),
            _ghidra_change_queue_board(state),
            _change_queue_selector(state, False),
            _approve_change_button(state, False),
            _reject_change_button(state, False),
            _send_button(interactive=True, visible=True),
            _cancel_button(interactive=False, visible=False),
            _send_button(interactive=True, visible=True),
            _todo_board(state, visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress"))),
        )
        return

    chat_history = chat_history or []
    state = state or {}
    turn_t0 = time.perf_counter()
    chat_box: Dict[str, List[Dict[str, str]]] = {"history": chat_history}

    # Make sure state keys exist
    state.setdefault("role_histories", {})
    state.setdefault("tool_log", "")
    state.setdefault("tool_log_sections", {})
    state.setdefault("_tool_log_seen_keys", {})
    state.setdefault("tool_result_cache", {})
    state.setdefault("status_log", "")
    state.setdefault("active_run_id", "")
    state.setdefault("cancel_requested", False)
    state.setdefault("selected_change_proposal_id", "")
    state.setdefault("shared_state", _new_shared_state())
    pending_change_count = get_pending_change_count(state)
    edit_intent_query = is_edit_intent_query(user_text)
    preserve_change_queue = pending_change_count > 0

    state["validator_review_level"] = _normalize_validator_review_level(validator_review_level_value)

    if pending_change_count and edit_intent_query:
        append_status(
            state,
            (
                "Blocked edit-generating query while pending Ghidra changes exist "
                f"({pending_change_count} pending)"
            ),
        )
        gate_note = (
            f"There {'is' if pending_change_count == 1 else 'are'} {pending_change_count} pending Ghidra change "
            f"proposal{'s' if pending_change_count != 1 else ''} in the queue.\n"
            "New edit-generating requests remain gated until you review the current queue."
        )
        blocked_history = list(chat_history) + [
            {"role": "user", "content": user_text},
            {"role": "assistant", "content": gate_note},
        ]
        _store_ui_snapshot(
            chat_history=blocked_history,
            state=state,
            run_active=False,
            composer_visible=True,
            send_visible=True,
            clear_visible=True,
            todo_visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress")),
            force=True,
        )
        yield _ui_updates(
            _message_input(value="", interactive=True, visible=True),
            blocked_history,
            state,
            _validator_review_level_dropdown(state, interactive=True, visible=True),
            _pipeline_auto_select_checkbox(state, interactive=True, visible=True),
            _architecture_preset_dropdown(state, interactive=True, visible=True),
            _pipeline_preset_dropdown(state, interactive=True, visible=True),
            _automation_status_board(state),
            _validation_gate_container(state),
            _validation_gate_board(state),
            _planned_work_items_board(state),
            _ghidra_change_queue_board(state),
            _change_queue_selector(state, False),
            _approve_change_button(state, False),
            _reject_change_button(state, False),
            _send_button(interactive=True, visible=True),
            _cancel_button(interactive=False, visible=False),
            _send_button(interactive=True, visible=True),
            _todo_board(state, visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress"))),
        )
        return

    run_id = uuid4().hex
    state["active_run_id"] = run_id
    state["cancel_requested"] = False
    selected_pipeline_default = str(pipeline_preset_value or "").strip() or DEEP_AGENT_PIPELINE_NAME
    state["deep_agent_auto_select_pipeline"] = selected_pipeline_default.lower() in {"dynamic", "auto"} or bool(
        pipeline_auto_select_value
    )
    selected_architecture_default = str(architecture_preset_value or "").strip() or DEEP_AGENT_ARCHITECTURE_NAME
    architecture_auto_select = selected_architecture_default.lower() in {"dynamic", "auto"}
    if architecture_auto_select:
        selected_architecture_default = "dynamic"
    elif selected_architecture_default not in DEEP_AGENT_ARCHITECTURE_PRESETS:
        selected_architecture_default = DEEP_AGENT_ARCHITECTURE_NAME
    state["deep_agent_architecture_name"] = selected_architecture_default
    if selected_pipeline_default.lower() in {"dynamic", "auto"}:
        state["deep_agent_pipeline_name"] = "dynamic"
    elif selected_pipeline_default not in DEEP_AGENT_PIPELINE_PRESETS:
        selected_pipeline_default = DEEP_AGENT_PIPELINE_NAME
        state["deep_agent_pipeline_name"] = selected_pipeline_default
    else:
        state["deep_agent_pipeline_name"] = selected_pipeline_default
    state["tool_log"] = ""
    state["tool_log_sections"] = {}
    state["_tool_log_seen_keys"] = {}
    selected_pipeline_name = select_pipeline_name_for_query_sync(user_text, state)
    state["shared_state"]["selected_pipeline_name"] = selected_pipeline_name
    selected_architecture_name = select_architecture_name_for_query_sync(user_text, state)
    selected_pipeline_definition = get_pipeline_definition_sync(
        selected_pipeline_name,
        architecture_name=selected_architecture_name,
    )
    state["shared_state"]["selected_architecture_name"] = selected_architecture_name
    state["shared_state"]["pipeline_stage_progress"] = _stage_progress_from_pipeline_definition(
        selected_pipeline_definition
    )
    state["shared_state"]["planned_work_items"] = []
    state["shared_state"]["planned_work_items_parse_error"] = ""
    if preserve_change_queue:
        state["shared_state"]["change_queue_draft_proposals"] = []
        state["shared_state"]["ghidra_change_draft_proposals"] = []
    else:
        state["selected_change_proposal_id"] = ""
        state["shared_state"]["change_queue_proposals"] = []
        state["shared_state"]["change_queue_draft_proposals"] = []
        state["shared_state"]["change_queue_finalized"] = False
        state["shared_state"]["change_queue_parse_error"] = ""
        state["shared_state"]["ghidra_change_proposals"] = []
        state["shared_state"]["ghidra_change_draft_proposals"] = []
        state["shared_state"]["ghidra_change_queue_finalized"] = False
        state["shared_state"]["ghidra_change_parse_error"] = ""
    state["shared_state"]["validation_retry_count"] = 0
    state["shared_state"]["validation_last_decision"] = ""
    state["shared_state"]["validation_replan_feedback"] = ""
    state["shared_state"]["validation_history"] = []

    append_status(state, f"New query: {_shorten(user_text, max_chars=220)}")
    append_status(state, f"Pipeline selected for query: {selected_pipeline_name}")
    append_status(state, f"Architecture selected for query: {selected_architecture_name}")
    running_note = "[deep pipeline running... task board is live]"
    routing_note = ""
    queue_notice = ""
    if pending_change_count:
        queue_notice = (
            f"Pending Ghidra changes: {pending_change_count} proposal{'s' if pending_change_count != 1 else ''} still need approval or rejection.\n"
            "New edit-generating requests remain gated until the queue is addressed."
        )
        append_status(state, f"Continuing with pending Ghidra queue in view ({pending_change_count} pending)")
    if bool(state.get("deep_agent_auto_select_pipeline", DEEP_AGENT_AUTO_SELECT_PIPELINE)):
        routing_note = (
            "Pipeline auto-selection is enabled.\n"
            f'The determined best pipeline for the query "{user_text}" is `{selected_pipeline_name}`.'
        )
        if architecture_auto_select and selected_architecture_name:
            routing_note += (
                "\n"
                f'The determined best worker architecture for the query is `{selected_architecture_name}`.'
            )

    # Show user input immediately and begin streaming status/tool log updates.
    chat_box["history"] = chat_history + [{"role": "user", "content": user_text}]
    if queue_notice:
        chat_box["history"].append({"role": "assistant", "content": queue_notice})
    if routing_note:
        chat_box["history"].append({"role": "assistant", "content": routing_note})
    chat_box["history"].append({"role": "assistant", "content": running_note})
    _store_ui_snapshot(
        chat_history=chat_box["history"],
        state=state,
        run_active=True,
        composer_visible=False,
        send_visible=False,
        clear_visible=False,
        todo_visible=True,
        force=True,
    )
    yield _ui_updates(
        _message_input(value="", interactive=False, visible=False),
        chat_box["history"],
        state,
        _validator_review_level_dropdown(state, interactive=False, visible=True),
        _pipeline_auto_select_checkbox(state, interactive=False, visible=True),
        _architecture_preset_dropdown(state, interactive=False, visible=True),
        _pipeline_preset_dropdown(state, interactive=False, visible=True),
        _automation_status_board(state),
        _validation_gate_container(state),
        _validation_gate_board(state),
        _planned_work_items_board(state),
        _ghidra_change_queue_board(state),
        _change_queue_selector(state, True),
        _approve_change_button(state, True),
        _reject_change_button(state, True),
        _send_button(interactive=False, visible=False),
        _cancel_button(interactive=True, visible=True),
        _send_button(interactive=False, visible=False),
        _todo_board(state, visible=True),
    )

    def _run_deep_pipeline() -> Tuple[str, str]:
        runtime = build_run_local_pipeline_runtime(
            get_runtime_sync(
                pipeline_name=selected_pipeline_name,
                architecture_name=selected_architecture_name,
            )
        )
        return run_deepagent_pipeline(runtime, user_text, state), "deep_pipeline"

    result_box: Dict[str, str] = {"assistant_text": running_note}
    done = Event()

    def _runner() -> None:
        try:
            assistant_text, mode = _run_deep_pipeline()
            append_status(state, f"Chat turn finished in {time.perf_counter() - turn_t0:.1f}s (mode={mode})")
            result_box["assistant_text"] = _sanitize_user_facing_output(assistant_text)
            return
        except PipelineCancelled:
            append_status(state, f"Chat turn canceled after {time.perf_counter() - turn_t0:.1f}s")
            result_box["assistant_text"] = "[pipeline canceled by user]"
            if selected_pipeline_name == "auto_triage":
                shared = state.setdefault("shared_state", _new_shared_state())
                shared["auto_triage_status"] = "canceled"
                shared["auto_triage_last_error"] = "Pipeline canceled by user"
                shared["auto_triage_last_run_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            return
        except Exception as e:
            err = str(e)
            if "messages with role 'tool' must be a response to a preceeding message with 'tool_calls'" in err:
                append_status(state, "Detected invalid tool history; clearing role histories and retrying once")
                state["role_histories"] = {}
                try:
                    assistant_text, mode = _run_deep_pipeline()
                    append_status(
                        state,
                        f"Chat turn recovered after history reset in {time.perf_counter() - turn_t0:.1f}s (mode={mode})",
                    )
                    result_box["assistant_text"] = _sanitize_user_facing_output(assistant_text)
                    return
                except Exception as e2:
                    append_status(
                        state,
                        f"Chat turn failed after history-reset retry ({type(e2).__name__}) in {time.perf_counter() - turn_t0:.1f}s",
                    )
                    result_box["assistant_text"] = f"[multi-agent pipeline error] {type(e2).__name__}: {e2}"
                    if selected_pipeline_name == "auto_triage":
                        shared = state.setdefault("shared_state", _new_shared_state())
                        shared["auto_triage_status"] = "failed"
                        shared["auto_triage_last_error"] = f"{type(e2).__name__}: {e2}"
                        shared["auto_triage_last_run_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    return
            append_status(state, f"Chat turn failed ({type(e).__name__}) in {time.perf_counter() - turn_t0:.1f}s")
            result_box["assistant_text"] = f"[multi-agent pipeline error] {type(e).__name__}: {e}"
            if selected_pipeline_name == "auto_triage":
                shared = state.setdefault("shared_state", _new_shared_state())
                shared["auto_triage_status"] = "failed"
                shared["auto_triage_last_error"] = f"{type(e).__name__}: {e}"
                shared["auto_triage_last_run_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        finally:
            if str(state.get("active_run_id") or "") == run_id:
                if chat_box["history"]:
                    chat_box["history"][-1] = {"role": "assistant", "content": result_box["assistant_text"]}
                _store_ui_snapshot(
                    chat_history=chat_box["history"],
                    state=state,
                    run_active=False,
                    composer_visible=True,
                    send_visible=True,
                    clear_visible=True,
                    todo_visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress")),
                )
            done.set()

    worker = Thread(target=_runner, daemon=True)
    worker.start()

    last_tool_log = state.get("tool_log", "")
    last_todo_html = render_pipeline_todo_board(state)
    last_planned_html = render_planned_work_items_panel(state)
    last_validation_html = render_validation_gate_panel(state)
    while not done.wait(0.35):
        if str(state.get("active_run_id") or "") != run_id:
            return
        tool_now = state.get("tool_log", "")
        todo_now = render_pipeline_todo_board(state)
        planned_now = render_planned_work_items_panel(state)
        validation_now = render_validation_gate_panel(state)
        if (
            tool_now != last_tool_log
            or todo_now != last_todo_html
            or planned_now != last_planned_html
            or validation_now != last_validation_html
        ):
            last_tool_log = tool_now
            last_todo_html = todo_now
            last_planned_html = planned_now
            last_validation_html = validation_now
            _store_ui_snapshot(
                chat_history=chat_box["history"],
                state=state,
                run_active=True,
                composer_visible=False,
                send_visible=False,
                clear_visible=False,
                todo_visible=True,
            )
            yield _ui_updates(
                _message_input(value="", interactive=False, visible=False),
                chat_box["history"],
                state,
                _validator_review_level_dropdown(state, interactive=False, visible=True),
                _pipeline_auto_select_checkbox(state, interactive=False, visible=True),
                _architecture_preset_dropdown(state, interactive=False, visible=True),
                _pipeline_preset_dropdown(state, interactive=False, visible=True),
                _automation_status_board(state),
                _validation_gate_container(state),
                gr.update(value=validation_now, visible=True),
                gr.update(value=planned_now, visible=True),
                _ghidra_change_queue_board(state),
                _change_queue_selector(state, True),
                _approve_change_button(state, True),
                _reject_change_button(state, True),
                _send_button(interactive=False, visible=False),
                _cancel_button(interactive=True, visible=True),
                _send_button(interactive=False, visible=False),
                gr.update(value=todo_now, visible=True),
            )

    worker.join(timeout=0.1)
    if str(state.get("active_run_id") or "") != run_id:
        return

    # Update UI chat
    chat_history = chat_box["history"]

    yield _ui_updates(
        _message_input(value="", interactive=True, visible=True),
        chat_history,
        state,
        _validator_review_level_dropdown(state, interactive=True, visible=True),
        _pipeline_auto_select_checkbox(state, interactive=True, visible=True),
        _architecture_preset_dropdown(state, interactive=True, visible=True),
        _pipeline_preset_dropdown(state, interactive=True, visible=True),
        _automation_status_board(state),
        _validation_gate_container(state),
        _validation_gate_board(state),
        _planned_work_items_board(state),
        _ghidra_change_queue_board(state),
        _change_queue_selector(state, False),
        _approve_change_button(state, False),
        _reject_change_button(state, False),
        _send_button(interactive=True, visible=True),
        _cancel_button(interactive=False, visible=False),
        _send_button(interactive=True, visible=True),
        _todo_board(state, visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress"))),
    )


def set_validator_review_level(validator_review_level_value: str, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    state["validator_review_level"] = _normalize_validator_review_level(validator_review_level_value)
    _store_ui_snapshot(state=state)
    return (
        state,
        _validator_review_level_dropdown(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
    )


def set_pipeline_auto_select(pipeline_auto_select_value: bool, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    state["deep_agent_auto_select_pipeline"] = bool(pipeline_auto_select_value)
    _store_ui_snapshot(state=state)
    return (
        state,
        _pipeline_auto_select_checkbox(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
    )


def set_architecture_preset(architecture_preset_value: str, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    value = str(architecture_preset_value or "").strip() or DEEP_AGENT_ARCHITECTURE_NAME
    if value.lower() in {"dynamic", "auto"}:
        value = "dynamic"
    elif value not in DEEP_AGENT_ARCHITECTURE_PRESETS:
        value = DEEP_AGENT_ARCHITECTURE_NAME
    state["deep_agent_architecture_name"] = value
    _store_ui_snapshot(state=state)
    return (
        state,
        _architecture_preset_dropdown(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
    )


def set_pipeline_preset(pipeline_preset_value: str, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    value = str(pipeline_preset_value or "").strip() or DEEP_AGENT_PIPELINE_NAME
    if value.lower() in {"dynamic", "auto"}:
        state["deep_agent_pipeline_name"] = "dynamic"
        state["deep_agent_auto_select_pipeline"] = True
    elif value not in DEEP_AGENT_PIPELINE_PRESETS:
        value = DEEP_AGENT_PIPELINE_NAME
        state["deep_agent_pipeline_name"] = value
        state["deep_agent_auto_select_pipeline"] = False
    else:
        state["deep_agent_pipeline_name"] = value
        state["deep_agent_auto_select_pipeline"] = False
    _store_ui_snapshot(state=state)
    return (
        state,
        _pipeline_auto_select_checkbox(
            state,
            interactive=False,
            visible=False,
        ),
        _pipeline_preset_dropdown(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
    )


def _apply_ghidra_change_status(
    state: Dict[str, Any],
    proposal_id: str,
    *,
    status: str,
    result_text: str = "",
    error: str = "",
) -> Optional[Dict[str, Any]]:
    shared = state.setdefault("shared_state", _new_shared_state())
    proposals = list(shared.get("change_queue_proposals") or [])
    for proposal in proposals:
        if str(proposal.get("id") or "") != proposal_id:
            continue
        proposal["status"] = status
        proposal["result_text"] = result_text
        proposal["error"] = error
        if status == "applied":
            proposal["proposal_stage"] = "executed"
        elif status == "approved_proposal_only":
            proposal["proposal_stage"] = "approved"
        elif status in {"rejected", "failed", "stale", "invalid", "not_compilable"}:
            proposal["proposal_stage"] = "failed"
        return proposal
    return None


def _supersede_conflicting_ghidra_changes(
    state: Dict[str, Any],
    chosen_proposal_id: str,
    *,
    reason: str,
) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    proposals = list(shared.get("change_queue_proposals") or [])
    chosen = next((item for item in proposals if str(item.get("id") or "") == chosen_proposal_id), None)
    if not chosen:
        return
    chosen_conflict_signature = str(chosen.get("conflict_signature") or "").strip()
    if not chosen_conflict_signature:
        return
    for proposal in proposals:
        proposal_id = str(proposal.get("id") or "")
        if not proposal_id or proposal_id == chosen_proposal_id:
            continue
        if str(proposal.get("status") or "pending") != "pending":
            continue
        if str(proposal.get("conflict_signature") or "").strip() != chosen_conflict_signature:
            continue
        proposal["status"] = "superseded"
        proposal["result_text"] = ""
        proposal["error"] = reason


def _promote_conflicting_ghidra_changes(
    state: Dict[str, Any],
    retired_proposal_id: str,
    *,
    reason: str,
) -> Optional[Dict[str, Any]]:
    shared = state.setdefault("shared_state", _new_shared_state())
    proposals = list(shared.get("change_queue_proposals") or [])
    retired = next((item for item in proposals if str(item.get("id") or "") == retired_proposal_id), None)
    if not retired:
        return None
    conflict_group_id = str(retired.get("conflict_group_id") or "").strip()
    if not conflict_group_id:
        return None
    candidates = [
        proposal
        for proposal in proposals
        if str(proposal.get("conflict_group_id") or "").strip() == conflict_group_id
        and str(proposal.get("id") or "") != retired_proposal_id
        and str(proposal.get("status") or "") in {"conflicting", "superseded"}
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda proposal: (-float(proposal.get("quality_score") or 0.0), str(proposal.get("id") or "")))
    promoted = candidates[0]
    promoted_id = str(promoted.get("id") or "")
    promoted["status"] = "pending"
    promoted["proposal_stage"] = str(promoted.get("proposal_stage") or "compilable")
    promoted["group_role"] = "primary"
    promoted["primary_proposal_id"] = promoted_id
    promoted["result_text"] = ""
    promoted["error"] = ""
    promoted["queue_status_reason"] = reason

    alternates = []
    for proposal in proposals:
        proposal_id = str(proposal.get("id") or "")
        if str(proposal.get("conflict_group_id") or "").strip() != conflict_group_id or proposal_id == retired_proposal_id:
            continue
        if proposal_id == promoted_id:
            continue
        if str(proposal.get("status") or "") in {"conflicting", "superseded"}:
            proposal["status"] = "conflicting"
            proposal["group_role"] = "alternative"
            proposal["primary_proposal_id"] = promoted_id
            proposal["queue_status_reason"] = f"Competing alternative after promotion of {promoted_id}."
            alternates.append(proposal_id)
    promoted["competing_proposal_ids"] = alternates
    return promoted


def set_selected_change_proposal(selected_proposal_id: str, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    state["selected_change_proposal_id"] = str(selected_proposal_id or "").strip()
    _normalize_selected_change_proposal_id(state)
    _store_ui_snapshot(state=state, force=True)
    return (
        state,
        _ghidra_change_queue_board(state),
        _change_queue_selector(state, False),
        _approve_change_button(state, False),
        _reject_change_button(state, False),
    )


def approve_selected_ghidra_change(
    chat_history: List[Dict[str, str]],
    state: Dict[str, Any],
    selected_proposal_id: str,
):
    state = state or _snapshot_state_default()
    chat_history = chat_history or []
    if bool(_get_ui_snapshot().get("run_active")):
        return _restore_snapshot_outputs(_get_ui_snapshot())

    proposal = _resolve_selected_change_proposal(state, selected_proposal_id)
    if not proposal:
        return _restore_snapshot_outputs(_get_ui_snapshot())

    pipeline_name = str(((state.get("shared_state") or {}).get("selected_pipeline_name") or "")).strip() or None
    result = apply_change_proposal_sync(proposal, pipeline_name=pipeline_name, state=state)
    proposal_id = str(proposal.get("id") or "")
    summary = str(result.get("summary") or proposal.get("summary") or proposal_id).strip()
    result_text = str(result.get("result_text") or "").strip()
    error = str(result.get("error") or "").strip()
    target_system = str(result.get("target_system") or proposal.get("target_system") or "").strip().lower()
    change_label = "ghidra change" if target_system == "ghidra" else "change"

    if result.get("ok"):
        final_status = "applied"
        assistant_note = f"[{change_label} applied] {summary}"
        if result_text:
            assistant_note += f"\n\n{result_text}"
    elif str(result.get("status") or "") == "needs_active_program_switch":
        assistant_note = f"[ghidra change waiting for active program switch] {summary}"
        if error:
            assistant_note += f"\n\n{error}"
        new_history = list(chat_history) + [{"role": "assistant", "content": assistant_note}]
        append_status(state, f"Ghidra change pending active-program switch: {summary}")
        _store_ui_snapshot(
            chat_history=new_history,
            state=state,
            run_active=False,
            composer_visible=True,
            send_visible=True,
            clear_visible=True,
            todo_visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress")),
            force=True,
        )
        return _restore_snapshot_outputs(_get_ui_snapshot())
    elif str(result.get("status") or "") == "proposal_only":
        final_status = "approved_proposal_only"
        assistant_note = f"[{change_label} approved as proposal only] {summary}"
        if error:
            assistant_note += f"\n\n{error}"
    elif str(result.get("status") or "") in {"stale", "invalid", "not_compilable"}:
        final_status = str(result.get("status") or "failed")
        assistant_note = f"[{change_label} blocked] {summary}"
        if error:
            assistant_note += f"\n\n{error}"
    else:
        final_status = "failed"
        assistant_note = f"[{change_label} apply failed] {summary}"
        if error:
            assistant_note += f"\n\n{error}"

    _apply_ghidra_change_status(
        state,
        proposal_id,
        status=final_status,
        result_text=result_text,
        error=error,
    )
    if final_status in {"applied", "approved_proposal_only"}:
        _supersede_conflicting_ghidra_changes(
            state,
            proposal_id,
            reason=f"Superseded after {final_status} of {summary}.",
        )
    elif final_status in {"stale", "invalid", "not_compilable", "rejected"}:
        promoted = _promote_conflicting_ghidra_changes(
            state,
            proposal_id,
            reason=f"Promoted after {final_status} of {summary}.",
        )
        if promoted:
            append_status(state, f"Promoted alternative change proposal: {promoted.get('summary') or promoted.get('id')}")
    new_history = list(chat_history) + [{"role": "assistant", "content": assistant_note}]
    _store_ui_snapshot(
        chat_history=new_history,
        state=state,
        run_active=False,
        composer_visible=True,
        send_visible=True,
        clear_visible=True,
        todo_visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress")),
        force=True,
    )
    return _restore_snapshot_outputs(_get_ui_snapshot())


def approve_next_ghidra_change(chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    return approve_selected_ghidra_change(chat_history, state, "")


def reject_selected_ghidra_change(
    chat_history: List[Dict[str, str]],
    state: Dict[str, Any],
    selected_proposal_id: str,
):
    state = state or _snapshot_state_default()
    chat_history = chat_history or []
    if bool(_get_ui_snapshot().get("run_active")):
        return _restore_snapshot_outputs(_get_ui_snapshot())

    proposal = _resolve_selected_change_proposal(state, selected_proposal_id)
    if not proposal:
        return _restore_snapshot_outputs(_get_ui_snapshot())

    proposal_id = str(proposal.get("id") or "")
    summary = str(proposal.get("summary") or proposal_id).strip()
    target_system = str(proposal.get("target_system") or "").strip().lower()
    change_label = "ghidra change" if target_system == "ghidra" else "change"
    _apply_ghidra_change_status(
        state,
        proposal_id,
        status="rejected",
        result_text="",
        error="Rejected by user.",
    )
    promoted = _promote_conflicting_ghidra_changes(
        state,
        proposal_id,
        reason=f"Promoted after rejection of {summary}.",
    )
    if promoted:
        append_status(state, f"Promoted alternative change proposal: {promoted.get('summary') or promoted.get('id')}")
    append_status(state, f"{change_label.title()} rejected by user: {summary}")
    new_history = list(chat_history) + [{"role": "assistant", "content": f"[{change_label} rejected] {summary}"}]
    _store_ui_snapshot(
        chat_history=new_history,
        state=state,
        run_active=False,
        composer_visible=True,
        send_visible=True,
        clear_visible=True,
        todo_visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress")),
        force=True,
    )
    return _restore_snapshot_outputs(_get_ui_snapshot())


def reject_next_ghidra_change(chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    return reject_selected_ghidra_change(chat_history, state, "")


def cancel_run(chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    chat_history = chat_history or []
    state = state or _snapshot_state_default()
    active_run_id = str(state.get("active_run_id") or "").strip()
    if not active_run_id:
        return _restore_snapshot_outputs(_get_ui_snapshot())

    state["cancel_requested"] = True
    state["active_run_id"] = f"canceled:{active_run_id}"
    append_status(state, "Cancellation requested by user")

    fresh_shared_state = _new_shared_state()
    fresh_shared_state.update(preserved_automation_shared_state((state.get("shared_state") or {})))
    fresh_state = {
        "role_histories": {},
        "tool_log": "",
        "tool_log_sections": {},
        "_tool_log_seen_keys": {},
        "tool_result_cache": dict(state.get("tool_result_cache") or {}),
        "status_log": "",
        "active_run_id": f"idle:{uuid4().hex}",
        "cancel_requested": False,
        "selected_change_proposal_id": "",
        "validator_review_level": _normalize_validator_review_level(
            state.get("validator_review_level", DEFAULT_VALIDATOR_REVIEW_LEVEL)
        ),
        "deep_agent_auto_select_pipeline": bool(
            state.get("deep_agent_auto_select_pipeline", DEEP_AGENT_AUTO_SELECT_PIPELINE)
        ),
        "deep_agent_architecture_name": str(
            state.get("deep_agent_architecture_name", DEEP_AGENT_ARCHITECTURE_NAME)
        ).strip()
        or DEEP_AGENT_ARCHITECTURE_NAME,
        "deep_agent_pipeline_name": str(
            state.get(
                "deep_agent_pipeline_name",
                ("dynamic" if DEEP_AGENT_AUTO_SELECT_PIPELINE else DEEP_AGENT_PIPELINE_NAME),
            )
        ).strip()
        or ("dynamic" if DEEP_AGENT_AUTO_SELECT_PIPELINE else DEEP_AGENT_PIPELINE_NAME),
        "shared_state": fresh_shared_state,
    }
    detached_note = "[pipeline cancel requested] The current run was detached. You can submit a new query."
    fresh_history = list(chat_history) + [{"role": "assistant", "content": detached_note}]
    _store_ui_snapshot(
        chat_history=fresh_history,
        state=fresh_state,
        run_active=False,
        composer_visible=True,
        send_visible=True,
        clear_visible=True,
        todo_visible=False,
        force=True,
    )
    return _ui_updates(
        _message_input(value="", interactive=True, visible=True),
        fresh_history,
        fresh_state,
        _validator_review_level_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_auto_select_checkbox(fresh_state, interactive=True, visible=True),
        _architecture_preset_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_preset_dropdown(fresh_state, interactive=True, visible=True),
        _automation_status_board(fresh_state),
        _validation_gate_container(fresh_state),
        _validation_gate_board(fresh_state),
        _planned_work_items_board(fresh_state),
        _ghidra_change_queue_board(fresh_state),
        _change_queue_selector(fresh_state, False),
        _approve_change_button(fresh_state, False),
        _reject_change_button(fresh_state, False),
        _send_button(interactive=True, visible=True),
        _cancel_button(interactive=False, visible=False),
        _send_button(interactive=True, visible=True),
        _todo_board({"shared_state": fresh_shared_state}, visible=False),
    )


def reset():
    prior_snapshot = _get_ui_snapshot()
    prior_state = prior_snapshot.get("state") if isinstance(prior_snapshot.get("state"), dict) else {}
    fresh_shared_state = _new_shared_state()
    fresh_shared_state.update(preserved_automation_shared_state((prior_state or {}).get("shared_state") or {}))
    fresh_state = {
        "role_histories": {},
        "tool_log": "",
        "tool_log_sections": {},
        "_tool_log_seen_keys": {},
        "tool_result_cache": {},
        "status_log": "",
        "active_run_id": "",
        "cancel_requested": False,
        "selected_change_proposal_id": "",
        "validator_review_level": DEFAULT_VALIDATOR_REVIEW_LEVEL,
        "deep_agent_auto_select_pipeline": DEEP_AGENT_AUTO_SELECT_PIPELINE,
        "deep_agent_architecture_name": DEEP_AGENT_ARCHITECTURE_NAME,
        "deep_agent_pipeline_name": "dynamic" if DEEP_AGENT_AUTO_SELECT_PIPELINE else DEEP_AGENT_PIPELINE_NAME,
        "shared_state": fresh_shared_state,
    }
    _store_ui_snapshot(
        chat_history=[],
        state=fresh_state,
        run_active=False,
        composer_visible=True,
        send_visible=True,
        clear_visible=True,
        todo_visible=False,
    )
    return _ui_updates(
        _message_input(value="", interactive=True, visible=True),
        [],
        fresh_state,
        _validator_review_level_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_auto_select_checkbox(fresh_state, interactive=True, visible=True),
        _architecture_preset_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_preset_dropdown(fresh_state, interactive=True, visible=True),
        _automation_status_board(fresh_state),
        _validation_gate_container(fresh_state),
        _validation_gate_board(fresh_state),
        _planned_work_items_board(fresh_state),
        _ghidra_change_queue_board(fresh_state),
        _change_queue_selector(fresh_state, False),
        _approve_change_button(fresh_state, False),
        _reject_change_button(fresh_state, False),
        _send_button(interactive=True, visible=True),
        _cancel_button(interactive=False, visible=False),
        _send_button(interactive=True, visible=True),
        _todo_board({"shared_state": fresh_shared_state}, visible=False),
    )


def _automation_run_busy() -> bool:
    snapshot = _get_ui_snapshot()
    return bool(snapshot.get("run_active"))


def _mark_automation_snapshot_event(
    payload: Optional[Dict[str, Any]],
    *,
    status: str,
    source: str = "",
    program_key: str = "",
    reason: str = "",
    detail: str = "",
) -> None:
    snapshot = _get_ui_snapshot()
    state = snapshot.get("state")
    if not isinstance(state, dict):
        state = _snapshot_state_default()
    if isinstance(payload, dict):
        apply_automation_payload_to_state(state, payload)
    record_automation_event(
        state,
        status=status,
        source=source,
        program_key=program_key,
        reason=reason,
        detail=detail,
    )
    _store_ui_snapshot(
        chat_history=snapshot.get("chat_history") if isinstance(snapshot.get("chat_history"), list) else [],
        state=state,
        run_active=bool(snapshot.get("run_active")),
        composer_visible=bool(snapshot.get("composer_visible", True)),
        send_visible=bool(snapshot.get("send_visible", True)),
        clear_visible=bool(snapshot.get("clear_visible", True)),
        todo_visible=bool(snapshot.get("todo_visible", False)),
        force=True,
    )


def _automation_program_key_from_payload(payload: Dict[str, Any]) -> str:
    return str(
        payload.get("automation_program_key")
        or payload.get("program_key")
        or payload.get("ghidra_project_path")
        or payload.get("executable_path")
        or payload.get("program_name")
        or "global"
    ).strip() or "global"


def _automation_analysis_token_from_payload(payload: Dict[str, Any]) -> str:
    return str(
        payload.get("analysis_token")
        or payload.get("automation_signature")
        or payload.get("analysis_completed_at_epoch_ms")
        or ""
    ).strip()


def _automation_sha256_from_payload(payload: Dict[str, Any]) -> str:
    return str(
        payload.get("executable_sha256")
        or payload.get("sha256")
        or (((payload.get("program_info") or {}).get("program") or {}).get("executableSHA256") if isinstance(payload.get("program_info"), dict) else "")
        or ""
    ).strip()


def _should_accept_automation_trigger(payload: Dict[str, Any]) -> Tuple[bool, str, str]:
    program_key = _automation_program_key_from_payload(payload)
    force_rerun = bool(payload.get("force_rerun"))
    if force_rerun:
        return True, "manual_force_rerun", program_key

    prior = _AUTOMATION_RUN_HISTORY.get(program_key)
    if prior is None:
        return True, "first_trigger_for_program", program_key

    prior_status = str(prior.get("status") or "").strip().lower()
    if prior_status and prior_status != "succeeded":
        return True, "previous_auto_triage_not_successful", program_key

    prior_sha256 = str(prior.get("sha256") or "").strip()
    incoming_sha256 = _automation_sha256_from_payload(payload)
    if incoming_sha256 and prior_sha256 and incoming_sha256 != prior_sha256:
        return True, "sample_hash_changed", program_key

    prior_analysis_token = str(prior.get("analysis_token") or "").strip()
    incoming_analysis_token = _automation_analysis_token_from_payload(payload)
    if incoming_analysis_token and prior_analysis_token and incoming_analysis_token != prior_analysis_token:
        return True, "analysis_token_changed", program_key

    return False, "duplicate_completed_auto_triage", program_key


def _register_automation_run_start(payload: Dict[str, Any], rerun_reason: str) -> str:
    program_key = _automation_program_key_from_payload(payload)
    _AUTOMATION_RUN_HISTORY[program_key] = {
        "status": "running",
        "sha256": _automation_sha256_from_payload(payload),
        "analysis_token": _automation_analysis_token_from_payload(payload),
        "rerun_reason": rerun_reason,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": str(payload.get("source") or "").strip(),
    }
    _mark_automation_snapshot_event(
        payload,
        status="accepted",
        source=str(payload.get("source") or "").strip(),
        program_key=program_key,
        reason=rerun_reason,
        detail="Trigger accepted and auto-triage queued.",
    )
    return program_key


def _register_automation_run_finish(
    program_key: str,
    payload: Dict[str, Any],
    *,
    status: str,
    error: str = "",
) -> None:
    _AUTOMATION_RUN_HISTORY[program_key] = {
        "status": status,
        "sha256": _automation_sha256_from_payload(payload),
        "analysis_token": _automation_analysis_token_from_payload(payload),
        "rerun_reason": str(payload.get("rerun_reason") or payload.get("trigger_reason") or "").strip(),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": str(payload.get("source") or "").strip(),
        "error": error,
    }
    detail = error.strip()
    if not detail:
        if status == "succeeded":
            detail = "Automated triage completed successfully."
        elif status == "failed":
            detail = "Automated triage failed."
        elif status == "canceled":
            detail = "Automated triage was canceled or detached."
        else:
            detail = f"Automated triage finished with status {status}."
    _mark_automation_snapshot_event(
        payload,
        status=status,
        source=str(payload.get("source") or "").strip(),
        program_key=program_key,
        reason=str(payload.get("rerun_reason") or payload.get("trigger_reason") or "").strip(),
        detail=detail,
    )


def _automation_prompt_from_payload(payload: Dict[str, Any]) -> str:
    user_text = str(payload.get("user_text") or payload.get("prompt") or "").strip()
    if user_text:
        return user_text

    program_name = str(payload.get("program_name") or payload.get("name") or "").strip() or "unknown"
    executable_path = str(payload.get("executable_path") or payload.get("path") or "").strip()
    executable_sha256 = str(payload.get("executable_sha256") or payload.get("sha256") or "").strip() or "unknown"
    executable_md5 = str(payload.get("executable_md5") or payload.get("md5") or "").strip() or "unknown"
    ghidra_project_path = str(payload.get("ghidra_project_path") or payload.get("project_path") or "").strip() or "unknown"
    path_handoff_line = f"{PATH_HANDOFF_LINE_PREFIX} {executable_path}" if executable_path else ""
    base_prompt = AUTOMATION_DEFAULT_PROMPT_TEMPLATE.format(
        program_name=program_name,
        executable_path=executable_path or "unknown",
        executable_sha256=executable_sha256,
        executable_md5=executable_md5,
        ghidra_project_path=ghidra_project_path,
        path_handoff_line=path_handoff_line,
    ).strip()
    request_profile = _normalize_automation_request_profile(
        payload.get("automation_request_profile")
        or payload.get("automation_query_mode")
        or AUTOMATION_DEFAULT_REQUEST_PROFILE
    )

    extra_lines: List[str] = [
        "",
        "This request should use the dedicated automated bootstrap triage pipeline.",
        "Treat any automation bootstrap metadata and deterministic pre-sweeps as primary starting context.",
        "Do not auto-apply edits or launch dynamic analysis automatically.",
        "This is an unattended automation run. Do the bounded static-analysis work available in the pipeline now rather than asking the user for permission to continue.",
    ]
    if request_profile == "technical_report":
        extra_lines.extend(
            [
                "Automation request profile: technical_report.",
                "Return the analyst-facing technical triage report itself, not a plan, menu, or optional deliverable list.",
                "Do not write phrases such as `Would you like me to`, `How would you like to proceed`, `I can create a todo list`, or similar interactive follow-up language.",
                "If FLOSS, capa, HashDB, strings, YARA, or packer checks are already present in deterministic pre-sweeps, use those results directly and perform only targeted follow-up static analysis when needed to explain the sample.",
                "Do not merely recommend running available static tools as future work unless a sweep failed, was unavailable, or a narrower follow-up is still needed.",
                "Preferred sections: `Technical Summary`, `Confirmed Findings`, `Evidence Highlights`, `Unknowns / Limitations`, and `Recommended Next Steps`.",
            ]
        )
    elif request_profile == "detailed_report":
        extra_lines.extend(
            [
                "Automation request profile: detailed_report.",
                "Return a detailed analyst-facing technical report, not a plan, menu, or optional deliverable list.",
                "Do not ask the user what to do next and do not offer to create task lists instead of presenting findings.",
                "Use deterministic pre-sweeps as completed evidence when available, then perform targeted follow-up static analysis to deepen the explanation of code paths, capabilities, anti-analysis behavior, and evidence-backed rename/type/patch opportunities.",
                "Preferred sections: `Technical Summary`, `Program Behavior`, `Key Functions / Control-Flow Pivots`, `Capabilities and Anti-Analysis`, `Evidence Highlights`, `Unknowns / Limitations`, and `Recommended Next Steps`.",
            ]
        )
    else:
        extra_lines.extend(
            [
                "Automation request profile: workplan.",
                "Return a concrete prioritized work plan rather than a final report.",
                "Use deterministic pre-sweeps as already-completed bootstrap work and plan only the targeted follow-up analysis still worth doing.",
                "Do not ask the user to choose among options; return the recommended plan directly.",
            ]
        )
    for label, key in (
        ("Language", "language"),
        ("Compiler", "compiler"),
        ("Image Base", "image_base"),
        ("Entry Point", "entry_point"),
    ):
        value = str(payload.get(key) or "").strip()
        if value:
            extra_lines.append(f"{label}: {value}")

    section_summary = list(payload.get("section_summary") or [])
    if section_summary:
        extra_lines.append("Section summary:")
        extra_lines.extend(f"- {line}" for line in section_summary[:6])

    import_summary = list(payload.get("import_summary") or [])
    if import_summary:
        extra_lines.append("Import summary:")
        extra_lines.extend(f"- {line}" for line in import_summary[:8])

    root_functions = list(payload.get("root_functions") or [])
    if root_functions:
        extra_lines.append("Discovered root functions:")
        extra_lines.extend(f"- {line}" for line in root_functions[:6])

    warnings = list(payload.get("auto_analysis_warnings") or [])
    failures = list(payload.get("auto_analysis_failures") or [])
    if warnings:
        extra_lines.append("Auto-analysis warnings:")
        extra_lines.extend(f"- {line}" for line in warnings[:6])
    if failures:
        extra_lines.append("Auto-analysis failures:")
        extra_lines.extend(f"- {line}" for line in failures[:6])

    return "\n".join([base_prompt, *extra_lines]).strip()


def _run_automation_trigger(user_text: str, source: str, payload: Dict[str, Any], program_key: str) -> None:
    global _AUTOMATION_TRIGGER_PENDING
    try:
        snapshot = _get_ui_snapshot()
        state = snapshot.get("state")
        if not isinstance(state, dict):
            state = _snapshot_state_default()
        chat_history = snapshot.get("chat_history") or []
        if not isinstance(chat_history, list):
            chat_history = []

        apply_automation_payload_to_state(state, payload)
        _mark_automation_snapshot_event(
            payload,
            status="running",
            source=source,
            program_key=program_key,
            reason=str(payload.get("rerun_reason") or "").strip(),
            detail="Automated triage is running.",
        )
        validator_review_level = _normalize_validator_review_level(
            state.get("validator_review_level", DEFAULT_VALIDATOR_REVIEW_LEVEL)
        )
        automation_architecture_name, automation_architecture_reason = _resolve_automation_architecture_name(payload)
        append_status(state, f"Automation trigger accepted from {source}")
        append_status(
            state,
            f"Automation architecture selected: {automation_architecture_name} ({automation_architecture_reason})",
        )

        for _ in chat_turn(
            user_text,
            list(chat_history),
            state,
            validator_review_level,
            False,
            automation_architecture_name,
            "auto_triage",
        ):
            pass
        shared = state.get("shared_state") if isinstance(state.get("shared_state"), dict) else {}
        final_status = str((shared or {}).get("auto_triage_status") or "").strip().lower() or "succeeded"
        final_error = str((shared or {}).get("auto_triage_last_error") or "").strip()
        _register_automation_run_finish(
            program_key,
            payload,
            status=final_status,
            error=final_error,
        )
    except Exception as e:
        print(f"[automation trigger error] {type(e).__name__}: {e}", flush=True)
        _register_automation_run_finish(
            program_key,
            payload,
            status="failed",
            error=f"{type(e).__name__}: {e}",
        )
    finally:
        with _AUTOMATION_TRIGGER_LOCK:
            _AUTOMATION_TRIGGER_PENDING = False


class _AutomationTriggerHandler(BaseHTTPRequestHandler):
    server_version = "MultiAgentWFAutomation/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        path = getattr(self, "path", "") or ""
        command = getattr(self, "command", "") or ""
        if command == "GET" and path.rstrip("/") == _AUTOMATION_STATUS_PATH.rstrip("/"):
            return
        print(f"[automation http] {self.address_string()} - {format % args}", flush=True)

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == _AUTOMATION_STATUS_PATH.rstrip("/"):
            snapshot = _get_ui_snapshot()
            state = snapshot.get("state") if isinstance(snapshot.get("state"), dict) else _snapshot_state_default()
            self._send_json(
                200,
                {
                    "ok": True,
                    "html": render_automation_status_panel(state),
                    "snapshot_version": int(snapshot.get("snapshot_version") or 0),
                    "run_active": bool(snapshot.get("run_active")),
                },
            )
            return

        if self.path.rstrip("/") != AUTOMATION_TRIGGER_HEALTH_PATH.rstrip("/"):
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        self._send_json(
            200,
            {
                "ok": True,
                "busy": _automation_run_busy() or _AUTOMATION_TRIGGER_PENDING,
                "trigger_path": AUTOMATION_TRIGGER_PATH,
            },
        )

    def do_POST(self) -> None:
        if self.path.rstrip("/") != AUTOMATION_TRIGGER_PATH.rstrip("/"):
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            content_length = 0
        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"ok": False, "error": f"invalid JSON body: {type(e).__name__}: {e}"})
            return

        if not isinstance(payload, dict):
            self._send_json(400, {"ok": False, "error": "JSON body must decode to an object"})
            return

        source = str(payload.get("source") or "external").strip() or "external"
        user_text = _automation_prompt_from_payload(payload)
        if not user_text:
            self._send_json(400, {"ok": False, "error": "trigger prompt resolved to an empty request"})
            return

        accept_trigger, rerun_reason, program_key = _should_accept_automation_trigger(payload)
        if not accept_trigger:
            _mark_automation_snapshot_event(
                payload,
                status="skipped",
                source=source,
                program_key=program_key,
                reason=rerun_reason,
                detail="Trigger skipped because no rerun condition was met.",
            )
            self._send_json(
                200,
                {
                    "ok": True,
                    "accepted": False,
                    "source": source,
                    "reason": rerun_reason,
                    "program_key": program_key,
                },
            )
            return
        payload["rerun_reason"] = rerun_reason

        global _AUTOMATION_TRIGGER_PENDING
        with _AUTOMATION_TRIGGER_LOCK:
            if _AUTOMATION_TRIGGER_PENDING or _automation_run_busy():
                _mark_automation_snapshot_event(
                    payload,
                    status="busy",
                    source=source,
                    program_key=program_key,
                    reason="workflow_already_running",
                    detail="Trigger received while another workflow was active.",
                )
                self._send_json(
                    409,
                    {
                        "ok": False,
                        "accepted": False,
                        "error": "workflow is already running",
                    },
                )
                return
            _AUTOMATION_TRIGGER_PENDING = True
            program_key = _register_automation_run_start(payload, rerun_reason)

        worker = Thread(
            target=_run_automation_trigger,
            args=(user_text, source, payload, program_key),
            daemon=True,
            name="automation-trigger",
        )
        worker.start()
        self._send_json(
            202,
            {
                "ok": True,
                "accepted": True,
                "source": source,
                "reason": rerun_reason,
                "program_key": program_key,
            },
        )


def _start_automation_trigger_server() -> None:
    global _AUTOMATION_TRIGGER_SERVER
    if not AUTOMATION_TRIGGER_ENABLED:
        print("[automation] trigger server disabled", flush=True)
        return
    if _AUTOMATION_TRIGGER_SERVER is not None:
        return

    try:
        server = ThreadingHTTPServer((AUTOMATION_TRIGGER_HOST, AUTOMATION_TRIGGER_PORT), _AutomationTriggerHandler)
    except OSError as e:
        print(
            f"[automation] failed to bind trigger server on {AUTOMATION_TRIGGER_HOST}:{AUTOMATION_TRIGGER_PORT}: {e}",
            flush=True,
        )
        return

    server.daemon_threads = True
    _AUTOMATION_TRIGGER_SERVER = server
    Thread(
        target=server.serve_forever,
        daemon=True,
        name="multi-agent-automation-trigger",
    ).start()
    print(
        f"[automation] trigger server listening on http://{AUTOMATION_TRIGGER_HOST}:{AUTOMATION_TRIGGER_PORT}{AUTOMATION_TRIGGER_PATH}",
        flush=True,
    )


def _stop_automation_trigger_server() -> None:
    global _AUTOMATION_TRIGGER_SERVER
    server = _AUTOMATION_TRIGGER_SERVER
    if server is None:
        return
    _AUTOMATION_TRIGGER_SERVER = None
    try:
        server.shutdown()
    except Exception as e:
        print(f"[automation] warning: failed to shutdown trigger server cleanly: {e}", flush=True)
    try:
        server.server_close()
    except Exception as e:
        print(f"[automation] warning: failed to close trigger server socket cleanly: {e}", flush=True)


def shutdown_workflow_services() -> None:
    _stop_automation_trigger_server()
    shutdown_runtime_sync()


class WorkflowUI:
    def __init__(self, app_settings: Optional[Dict[str, Any]] = None) -> None:
        self.app_settings = dict(app_settings or {})
        self._demo: Optional[gr.Blocks] = None

    def build_demo(self) -> gr.Blocks:
        if self._demo is not None:
            return self._demo

        with gr.Blocks(title="MCP Deep-Agent Tool Bench (PydanticAI)") as demo:
            gr.Markdown("# MCP Deep-Agent Tool Bench (PydanticAI + MCPServerStdio)")
            gr.Markdown("Deep pipeline -> staged delegated subagents")

            initial_state = _snapshot_state_default()
            _store_ui_snapshot(
                chat_history=[],
                state=initial_state,
                run_active=False,
                composer_visible=True,
                send_visible=True,
                clear_visible=True,
                todo_visible=False,
            )
            state = gr.State(initial_state)

            with gr.Sidebar(label="Advanced Settings", open=False, position="right"):
                with gr.Column(elem_id="advanced-settings-panel"):
                    gr.Markdown("### Advanced Settings")
                    validator_review_level = gr.Dropdown(
                        label="Validator review profile",
                        choices=VALIDATOR_REVIEW_LEVEL_CHOICES,
                        value=_normalize_validator_review_level(initial_state.get("validator_review_level", "default")),
                        info="Controls how strict validator feedback should be.",
                    )
                    pipeline_auto_select = gr.Checkbox(
                        label="Dynamic pipeline auto-selection",
                        value=bool(initial_state.get("deep_agent_auto_select_pipeline", DEEP_AGENT_AUTO_SELECT_PIPELINE)),
                        visible=False,
                    )
                    architecture_preset = gr.Dropdown(
                        label="Worker architecture preset",
                        choices=_ARCHITECTURE_PRESET_CHOICES,
                        value=(
                            "dynamic"
                            if str(initial_state.get("deep_agent_architecture_name", DEEP_AGENT_ARCHITECTURE_NAME)).strip().lower() in {"dynamic", "auto"}
                            else str(initial_state.get("deep_agent_architecture_name", DEEP_AGENT_ARCHITECTURE_NAME)).strip()
                            or DEEP_AGENT_ARCHITECTURE_NAME
                        ),
                        info="Select which specialist worker mix is available for the run.",
                    )
                    pipeline_preset = gr.Dropdown(
                        label="Pipeline preset",
                        choices=_PIPELINE_PRESET_CHOICES,
                        value=(
                            "dynamic"
                            if bool(initial_state.get("deep_agent_auto_select_pipeline", DEEP_AGENT_AUTO_SELECT_PIPELINE))
                            else str(initial_state.get("deep_agent_pipeline_name", DEEP_AGENT_PIPELINE_NAME)).strip()
                            or DEEP_AGENT_PIPELINE_NAME
                        ),
                        info="Pick a fixed pipeline, or choose DYNAMIC to let the router select one per query.",
                    )

            with gr.Row():
                with gr.Column(scale=3):
                    chat = gr.Chatbot(
                        label="Chat",
                        height=330,
                        group_consecutive_messages=False,
                    )
                    todo_board = gr.HTML(visible=False)
                    user = gr.Textbox(
                        label="Message",
                        lines=2,
                        placeholder="Ask something. Example: analyze this sample for hashing, anti-debugging, and network behavior...",
                    )
                    snapshot_refresh = gr.Button(
                        "Refresh UI Snapshot",
                        visible=True,
                        elem_id="wf-hidden-snapshot-refresh",
                        elem_classes=["wf-hidden-refresh-trigger"],
                    )
                    with gr.Row():
                        send = gr.Button("Send", variant="primary")
                        cancel = gr.Button("Cancel", visible=False)
                        clear = gr.Button("Reset")

                with gr.Column(scale=2):
                    automation_status_panel = gr.HTML(
                        value=render_automation_status_panel(initial_state),
                        elem_id="automation-status-panel",
                        visible=bool(AUTOMATION_TRIGGER_ENABLED),
                    )
                    with gr.Accordion("Planned Work Items", open=False):
                        planned_work_items_panel = gr.HTML(value=render_planned_work_items_panel(initial_state))
                    with gr.Accordion("Validation Gate", open=False, visible=_has_validation_gate(initial_state)) as validation_gate_group:
                        validation_gate_panel = gr.HTML(value=render_validation_gate_panel(initial_state))
                    with gr.Accordion("Change Queue", open=False, elem_id="ghidra-change-queue-accordion"):
                        ghidra_change_queue_panel = gr.HTML(
                            value=render_change_queue_panel(initial_state),
                            elem_id="ghidra-change-queue-panel",
                        )
                        change_selector = gr.Dropdown(
                            label="Selected Change Proposal",
                            choices=[],
                            value=None,
                            interactive=False,
                            visible=False,
                        )
                        with gr.Row():
                            approve_change = gr.Button("Apply Selected Change", interactive=False)
                            reject_change = gr.Button("Reject Selected Change", interactive=False)
                    gr.Markdown("### Tool Log")
                    tool_log_boxes: List[Any] = []
                    for stage_name, stage_kind in PIPELINE_LOG_SLOTS:
                        with gr.Accordion(f"{stage_name} ({stage_kind})", open=False):
                            tool_log_boxes.append(
                                gr.Code(
                                    value=_tool_log_text_for_stage(initial_state, stage_name, stage_kind),
                                    language=None,
                                    lines=12,
                                    max_lines=28,
                                    wrap_lines=True,
                                    show_line_numbers=False,
                                    buttons=["copy", "download"],
                                    interactive=False,
                                    label="Phase Log",
                                )
                            )

            ui_outputs = [
                user,
                chat,
                state,
                validator_review_level,
                pipeline_auto_select,
                architecture_preset,
                pipeline_preset,
                automation_status_panel,
                validation_gate_group,
                validation_gate_panel,
                planned_work_items_panel,
                ghidra_change_queue_panel,
                change_selector,
                approve_change,
                reject_change,
                *tool_log_boxes,
                send,
                cancel,
                clear,
                todo_board,
            ]
            snapshot_refresh.click(
                restore_last_ui,
                inputs=None,
                outputs=ui_outputs,
                show_progress="hidden",
                queue=False,
            )
            send_event = send.click(
                chat_turn,
                inputs=[
                    user,
                    chat,
                    state,
                    validator_review_level,
                    pipeline_auto_select,
                    architecture_preset,
                    pipeline_preset,
                ],
                outputs=ui_outputs,
            )
            submit_event = user.submit(
                chat_turn,
                inputs=[
                    user,
                    chat,
                    state,
                    validator_review_level,
                    pipeline_auto_select,
                    architecture_preset,
                    pipeline_preset,
                ],
                outputs=ui_outputs,
            )
            validator_review_level.change(
                set_validator_review_level,
                inputs=[validator_review_level, state],
                outputs=[state, validator_review_level],
                show_progress="hidden",
            )
            architecture_preset.change(
                set_architecture_preset,
                inputs=[architecture_preset, state],
                outputs=[state, architecture_preset],
                show_progress="hidden",
            )
            pipeline_preset.change(
                set_pipeline_preset,
                inputs=[pipeline_preset, state],
                outputs=[state, pipeline_auto_select, pipeline_preset],
                show_progress="hidden",
            )
            change_selector.change(
                set_selected_change_proposal,
                inputs=[change_selector, state],
                outputs=[state, ghidra_change_queue_panel, change_selector, approve_change, reject_change],
                show_progress="hidden",
                queue=False,
            )
            approve_change.click(
                approve_selected_ghidra_change,
                inputs=[chat, state, change_selector],
                outputs=ui_outputs,
                show_progress="hidden",
                queue=False,
            )
            reject_change.click(
                reject_selected_ghidra_change,
                inputs=[chat, state, change_selector],
                outputs=ui_outputs,
                show_progress="hidden",
                queue=False,
            )
            cancel.click(
                cancel_run,
                inputs=[chat, state],
                outputs=ui_outputs,
                show_progress="hidden",
                queue=False,
                cancels=[send_event, submit_event],
            )
            clear.click(reset, inputs=None, outputs=ui_outputs)
            demo.load(
                restore_last_ui,
                inputs=None,
                outputs=ui_outputs,
                show_progress="hidden",
                queue=False,
            )

        self._demo = demo
        return demo

    def launch(self, **launch_kwargs):
        demo = self.build_demo()
        demo.queue()
        _start_automation_trigger_server()
        effective_launch_kwargs = dict(self.app_settings.get("launch_kwargs") or {})
        effective_launch_kwargs.update(launch_kwargs)
        effective_launch_kwargs.setdefault("head", _load_frontend_head())
        demo.launch(**effective_launch_kwargs)
        return demo


def launch_workflow_app(*, app_settings: Optional[Dict[str, Any]] = None, **launch_kwargs):
    return WorkflowUI(app_settings=app_settings).launch(**launch_kwargs)
