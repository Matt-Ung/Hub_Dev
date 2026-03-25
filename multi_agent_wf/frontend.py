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
    DEFAULT_ALLOW_PARENT_INPUT,
    DEFAULT_SHELL_EXECUTION_MODE,
    DEFAULT_VALIDATOR_REVIEW_LEVEL,
    PIPELINE_LOG_SLOTS,
    PATH_HANDOFF_LINE_PREFIX,
    SHELL_EXECUTION_MODE_CHOICES,
    VALIDATOR_REVIEW_LEVEL_CHOICES,
    _normalize_shell_execution_mode,
    _normalize_validator_review_level,
)
from .pipeline import (
    PipelineCancelled,
    _stage_progress_from_pipeline_definition,
    get_pending_ghidra_change_count,
    get_pending_ghidra_change_proposal,
    render_pipeline_todo_board,
    render_ghidra_change_queue_panel,
    render_planned_work_items_panel,
    render_validation_gate_panel,
    run_deepagent_pipeline,
)
from .runtime import (
    apply_ghidra_change_proposal_sync,
    get_pipeline_definition_sync,
    get_runtime_sync,
    is_edit_intent_query,
    select_architecture_name_for_query_sync,
    select_pipeline_name_for_query_sync,
    shutdown_runtime_sync,
)
from .shared_state import (
    _empty_parent_input,
    _get_ui_snapshot,
    _new_shared_state,
    _pending_parent_input,
    _resolve_parent_input_request,
    _sanitize_user_facing_output,
    _shorten,
    _snapshot_state_default,
    _store_ui_snapshot,
    apply_automation_payload_to_state,
    append_status,
    render_parent_input_panel,
)

_AUTOMATION_TRIGGER_SERVER: ThreadingHTTPServer | None = None
_AUTOMATION_TRIGGER_LOCK = Lock()
_AUTOMATION_TRIGGER_PENDING = False
_AUTOMATION_RUN_HISTORY: Dict[str, Dict[str, Any]] = {}
_FRONTEND_HEAD_PATH = Path(__file__).resolve().parent / "assets" / "frontend_head.html"

_PIPELINE_PRESET_CHOICES = [("DYNAMIC (agent chooses)", "dynamic")] + [
    (name, name) for name in DEEP_AGENT_PIPELINE_PRESETS.keys()
]
_ARCHITECTURE_PRESET_CHOICES = [("DYNAMIC (agent chooses)", "dynamic")] + [
    (name, name) for name in DEEP_AGENT_ARCHITECTURE_PRESETS.keys()
]


def _load_frontend_head() -> str:
    try:
        return _FRONTEND_HEAD_PATH.read_text(encoding="utf-8")
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


def _allow_parent_input_checkbox(state: Dict[str, Any], interactive: bool = True, visible: bool = True):
    return gr.update(value=bool((state or {}).get("allow_parent_input")), interactive=interactive, visible=visible)


def _shell_execution_mode_dropdown(state: Dict[str, Any], interactive: bool = True, visible: bool = True):
    value = _normalize_shell_execution_mode((state or {}).get("shell_execution_mode", DEFAULT_SHELL_EXECUTION_MODE))
    return gr.update(
        choices=SHELL_EXECUTION_MODE_CHOICES,
        value=value,
        interactive=interactive,
        visible=visible,
    )


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


def _ghidra_change_queue_board(state: Dict[str, Any]):
    return gr.update(value=render_ghidra_change_queue_panel(state), visible=True)


def _approve_change_button(state: Dict[str, Any], active: bool):
    has_pending = get_pending_ghidra_change_proposal(state) is not None
    return gr.update(interactive=(not active) and has_pending, visible=True)


def _reject_change_button(state: Dict[str, Any], active: bool):
    has_pending = get_pending_ghidra_change_proposal(state) is not None
    return gr.update(interactive=(not active) and has_pending, visible=True)


def _parent_input_signature(state: Dict[str, Any]) -> str:
    pending = _pending_parent_input(state or {})
    return "|".join(
        [
            str(pending.get("request_id") or ""),
            str(pending.get("status") or ""),
            str(pending.get("question") or ""),
        ]
    )


def _parent_input_component_updates(
    state: Dict[str, Any],
    *,
    interactive: bool,
    reset_response: bool,
) -> Tuple[Any, Any, Any, Any]:
    pending = _pending_parent_input(state or {})
    visible = str(pending.get("status") or "") == "waiting"
    response_update = gr.update(
        interactive=interactive,
        visible=visible,
        placeholder="Type a concise answer for the agent...",
    )
    if reset_response:
        response_update = gr.update(
            value="",
            interactive=interactive,
            visible=visible,
            placeholder="Type a concise answer for the agent...",
        )
    return (
        gr.update(value=render_parent_input_panel(state), visible=visible),
        response_update,
        gr.update(interactive=interactive, visible=visible),
        gr.update(interactive=interactive, visible=visible),
    )


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
    allow_parent_input_update: Any,
    shell_execution_mode_update: Any,
    validator_review_level_update: Any,
    pipeline_auto_select_update: Any,
    architecture_preset_update: Any,
    pipeline_preset_update: Any,
    parent_prompt_update: Any,
    parent_response_update: Any,
    parent_submit_update: Any,
    parent_decline_update: Any,
    validation_gate_update: Any,
    planned_work_items_update: Any,
    ghidra_change_queue_update: Any,
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
        allow_parent_input_update,
        shell_execution_mode_update,
        validator_review_level_update,
        pipeline_auto_select_update,
        architecture_preset_update,
        pipeline_preset_update,
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
        validation_gate_update,
        planned_work_items_update,
        ghidra_change_queue_update,
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
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            state,
            interactive=True,
            reset_response=False,
        )
    )
    return _ui_updates(
        _message_input(
            value="",
            interactive=composer_visible,
            visible=composer_visible,
        ),
        chat_history,
        state,
        _allow_parent_input_checkbox(
            state,
            interactive=not active,
            visible=True,
        ),
        _shell_execution_mode_dropdown(
            state,
            interactive=not active,
            visible=True,
        ),
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
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
        _validation_gate_board(state),
        _planned_work_items_board(state),
        _ghidra_change_queue_board(state),
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
    allow_parent_input_value: bool,
    shell_execution_mode_value: str,
    validator_review_level_value: str,
    pipeline_auto_select_value: bool,
    architecture_preset_value: str,
    pipeline_preset_value: str,
):
    user_text = (user_text or "").strip()
    if not user_text:
        state = state or {}
        parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
            _parent_input_component_updates(
                state,
                interactive=True,
                reset_response=False,
            )
        )
        yield _ui_updates(
            _message_input(value="", interactive=True, visible=True),
            chat_history,
            state,
            _allow_parent_input_checkbox(state, interactive=True, visible=True),
            _shell_execution_mode_dropdown(state, interactive=True, visible=True),
            _validator_review_level_dropdown(state, interactive=True, visible=True),
            _pipeline_auto_select_checkbox(state, interactive=True, visible=True),
            _architecture_preset_dropdown(state, interactive=True, visible=True),
            _pipeline_preset_dropdown(state, interactive=True, visible=True),
            parent_prompt_update,
            parent_response_update,
            parent_submit_update,
            parent_decline_update,
            _validation_gate_board(state),
            _planned_work_items_board(state),
            _ghidra_change_queue_board(state),
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
    state.setdefault("shared_state", _new_shared_state())
    pending_change_count = get_pending_ghidra_change_count(state)
    edit_intent_query = is_edit_intent_query(user_text)
    preserve_change_queue = pending_change_count > 0

    state["allow_parent_input"] = bool(allow_parent_input_value)
    state["shell_execution_mode"] = _normalize_shell_execution_mode(shell_execution_mode_value)
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
            "Read-only follow-up questions are allowed, but new edit-generating queries are gated until you approve or reject the current queue."
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
        parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
            _parent_input_component_updates(
                state,
                interactive=True,
                reset_response=False,
            )
        )
        yield _ui_updates(
            _message_input(value="", interactive=True, visible=True),
            blocked_history,
            state,
            _allow_parent_input_checkbox(state, interactive=True, visible=True),
            _shell_execution_mode_dropdown(state, interactive=True, visible=True),
            _validator_review_level_dropdown(state, interactive=True, visible=True),
            _pipeline_auto_select_checkbox(state, interactive=True, visible=True),
            _architecture_preset_dropdown(state, interactive=True, visible=True),
            _pipeline_preset_dropdown(state, interactive=True, visible=True),
            parent_prompt_update,
            parent_response_update,
            parent_submit_update,
            parent_decline_update,
            _validation_gate_board(state),
            _planned_work_items_board(state),
            _ghidra_change_queue_board(state),
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
    state["pending_parent_input"] = _empty_parent_input()
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
        state["shared_state"]["ghidra_change_draft_proposals"] = []
    else:
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
            "Continuing with a read-only follow-up query. New edit-generating requests remain gated until the queue is addressed."
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
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            state,
            interactive=True,
            reset_response=True,
        )
    )
    yield _ui_updates(
        _message_input(value="", interactive=False, visible=False),
        chat_box["history"],
        state,
        _allow_parent_input_checkbox(state, interactive=False, visible=True),
        _shell_execution_mode_dropdown(state, interactive=False, visible=True),
        _validator_review_level_dropdown(state, interactive=False, visible=True),
        _pipeline_auto_select_checkbox(state, interactive=False, visible=True),
        _architecture_preset_dropdown(state, interactive=False, visible=True),
        _pipeline_preset_dropdown(state, interactive=False, visible=True),
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
        _validation_gate_board(state),
        _planned_work_items_board(state),
        _ghidra_change_queue_board(state),
        _approve_change_button(state, True),
        _reject_change_button(state, True),
        _send_button(interactive=False, visible=False),
        _cancel_button(interactive=True, visible=True),
        _send_button(interactive=False, visible=False),
        _todo_board(state, visible=True),
    )

    def _run_deep_pipeline() -> Tuple[str, str]:
        runtime = get_runtime_sync(
            pipeline_name=selected_pipeline_name,
            architecture_name=selected_architecture_name,
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
    last_parent_input_sig = _parent_input_signature(state)
    while not done.wait(0.35):
        if str(state.get("active_run_id") or "") != run_id:
            return
        tool_now = state.get("tool_log", "")
        todo_now = render_pipeline_todo_board(state)
        planned_now = render_planned_work_items_panel(state)
        validation_now = render_validation_gate_panel(state)
        parent_input_sig = _parent_input_signature(state)
        if (
            tool_now != last_tool_log
            or todo_now != last_todo_html
            or planned_now != last_planned_html
            or validation_now != last_validation_html
            or parent_input_sig != last_parent_input_sig
        ):
            parent_input_changed = parent_input_sig != last_parent_input_sig
            last_tool_log = tool_now
            last_todo_html = todo_now
            last_planned_html = planned_now
            last_validation_html = validation_now
            last_parent_input_sig = parent_input_sig
            _store_ui_snapshot(
                chat_history=chat_box["history"],
                state=state,
                run_active=True,
                composer_visible=False,
                send_visible=False,
                clear_visible=False,
                todo_visible=True,
            )
            parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
                _parent_input_component_updates(
                    state,
                    interactive=True,
                    reset_response=parent_input_changed,
                )
            )
            yield _ui_updates(
                _message_input(value="", interactive=False, visible=False),
                chat_box["history"],
                state,
                _allow_parent_input_checkbox(state, interactive=False, visible=True),
                _shell_execution_mode_dropdown(state, interactive=False, visible=True),
                _validator_review_level_dropdown(state, interactive=False, visible=True),
                _pipeline_auto_select_checkbox(state, interactive=False, visible=True),
                _architecture_preset_dropdown(state, interactive=False, visible=True),
                _pipeline_preset_dropdown(state, interactive=False, visible=True),
                parent_prompt_update,
                parent_response_update,
                parent_submit_update,
                parent_decline_update,
                gr.update(value=validation_now, visible=True),
                gr.update(value=planned_now, visible=True),
                _ghidra_change_queue_board(state),
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
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            state,
            interactive=True,
            reset_response=True,
        )
    )

    yield _ui_updates(
        _message_input(value="", interactive=True, visible=True),
        chat_history,
        state,
        _allow_parent_input_checkbox(state, interactive=True, visible=True),
        _shell_execution_mode_dropdown(state, interactive=True, visible=True),
        _validator_review_level_dropdown(state, interactive=True, visible=True),
        _pipeline_auto_select_checkbox(state, interactive=True, visible=True),
        _architecture_preset_dropdown(state, interactive=True, visible=True),
        _pipeline_preset_dropdown(state, interactive=True, visible=True),
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
        _validation_gate_board(state),
        _planned_work_items_board(state),
        _ghidra_change_queue_board(state),
        _approve_change_button(state, False),
        _reject_change_button(state, False),
        _send_button(interactive=True, visible=True),
        _cancel_button(interactive=False, visible=False),
        _send_button(interactive=True, visible=True),
        _todo_board(state, visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress"))),
    )


def set_allow_parent_input(allow_parent_input_value: bool, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    state["allow_parent_input"] = bool(allow_parent_input_value)
    _store_ui_snapshot(state=state)
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            reset_response=False,
        )
    )
    return (
        state,
        _allow_parent_input_checkbox(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
    )


def set_shell_execution_mode(shell_execution_mode_value: str, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    state["shell_execution_mode"] = _normalize_shell_execution_mode(shell_execution_mode_value)
    _store_ui_snapshot(state=state)
    return (
        state,
        _shell_execution_mode_dropdown(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
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


def submit_parent_input(response_text: str, state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    _resolve_parent_input_request(state, response=response_text, declined=False)
    _store_ui_snapshot(state=state)
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            state,
            interactive=bool(_get_ui_snapshot().get("run_active")),
            reset_response=True,
        )
    )
    return (
        state,
        _allow_parent_input_checkbox(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
    )


def decline_parent_input(state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    _resolve_parent_input_request(state, response="", declined=True)
    _store_ui_snapshot(state=state)
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            state,
            interactive=bool(_get_ui_snapshot().get("run_active")),
            reset_response=True,
        )
    )
    return (
        state,
        _allow_parent_input_checkbox(
            state,
            interactive=not bool(_get_ui_snapshot().get("run_active")),
            visible=True,
        ),
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
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
    proposals = list(shared.get("ghidra_change_proposals") or [])
    for proposal in proposals:
        if str(proposal.get("id") or "") != proposal_id:
            continue
        proposal["status"] = status
        proposal["result_text"] = result_text
        proposal["error"] = error
        return proposal
    return None


def _supersede_conflicting_ghidra_changes(
    state: Dict[str, Any],
    chosen_proposal_id: str,
    *,
    reason: str,
) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    proposals = list(shared.get("ghidra_change_proposals") or [])
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


def approve_next_ghidra_change(chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    chat_history = chat_history or []
    if bool(_get_ui_snapshot().get("run_active")):
        return _restore_snapshot_outputs(_get_ui_snapshot())

    proposal = get_pending_ghidra_change_proposal(state)
    if not proposal:
        return _restore_snapshot_outputs(_get_ui_snapshot())

    pipeline_name = str(((state.get("shared_state") or {}).get("selected_pipeline_name") or "")).strip() or None
    result = apply_ghidra_change_proposal_sync(proposal, pipeline_name=pipeline_name, state=state)
    proposal_id = str(proposal.get("id") or "")
    summary = str(result.get("summary") or proposal.get("summary") or proposal_id).strip()
    result_text = str(result.get("result_text") or "").strip()
    error = str(result.get("error") or "").strip()

    if result.get("ok"):
        final_status = "applied"
        assistant_note = f"[ghidra change applied] {summary}"
        if result_text:
            assistant_note += f"\n\n{result_text}"
    elif str(result.get("status") or "") == "proposal_only":
        final_status = "approved_proposal_only"
        assistant_note = f"[ghidra change approved as proposal only] {summary}"
        if error:
            assistant_note += f"\n\n{error}"
    else:
        final_status = "failed"
        assistant_note = f"[ghidra change apply failed] {summary}"
        if error:
            assistant_note += f"\n\n{error}"

    _apply_ghidra_change_status(
        state,
        proposal_id,
        status=final_status,
        result_text=result_text,
        error=error,
    )
    _supersede_conflicting_ghidra_changes(
        state,
        proposal_id,
        reason=f"Superseded after {final_status} of {summary}.",
    )
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


def reject_next_ghidra_change(chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    state = state or _snapshot_state_default()
    chat_history = chat_history or []
    if bool(_get_ui_snapshot().get("run_active")):
        return _restore_snapshot_outputs(_get_ui_snapshot())

    proposal = get_pending_ghidra_change_proposal(state)
    if not proposal:
        return _restore_snapshot_outputs(_get_ui_snapshot())

    proposal_id = str(proposal.get("id") or "")
    summary = str(proposal.get("summary") or proposal_id).strip()
    _apply_ghidra_change_status(
        state,
        proposal_id,
        status="rejected",
        result_text="",
        error="Rejected by user.",
    )
    _supersede_conflicting_ghidra_changes(
        state,
        proposal_id,
        reason=f"Superseded after rejection of {summary}.",
    )
    append_status(state, f"Ghidra change rejected by user: {summary}")
    new_history = list(chat_history) + [{"role": "assistant", "content": f"[ghidra change rejected] {summary}"}]
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


def cancel_run(chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    chat_history = chat_history or []
    state = state or _snapshot_state_default()
    active_run_id = str(state.get("active_run_id") or "").strip()
    if not active_run_id:
        return _restore_snapshot_outputs(_get_ui_snapshot())

    state["cancel_requested"] = True
    state["active_run_id"] = f"canceled:{active_run_id}"
    _resolve_parent_input_request(state, response="Pipeline canceled by user", declined=False)
    append_status(state, "Cancellation requested by user")

    fresh_shared_state = _new_shared_state()
    fresh_state = {
        "role_histories": {},
        "tool_log": "",
        "tool_log_sections": {},
        "_tool_log_seen_keys": {},
        "tool_result_cache": dict(state.get("tool_result_cache") or {}),
        "status_log": "",
        "active_run_id": f"idle:{uuid4().hex}",
        "cancel_requested": False,
        "allow_parent_input": bool(state.get("allow_parent_input", DEFAULT_ALLOW_PARENT_INPUT)),
        "shell_execution_mode": _normalize_shell_execution_mode(
            state.get("shell_execution_mode", DEFAULT_SHELL_EXECUTION_MODE)
        ),
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
        "pending_parent_input": _empty_parent_input(),
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
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            fresh_state,
            interactive=True,
            reset_response=True,
        )
    )
    return _ui_updates(
        _message_input(value="", interactive=True, visible=True),
        fresh_history,
        fresh_state,
        _allow_parent_input_checkbox(fresh_state, interactive=True, visible=True),
        _shell_execution_mode_dropdown(fresh_state, interactive=True, visible=True),
        _validator_review_level_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_auto_select_checkbox(fresh_state, interactive=True, visible=True),
        _architecture_preset_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_preset_dropdown(fresh_state, interactive=True, visible=True),
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
        _validation_gate_board(fresh_state),
        _planned_work_items_board(fresh_state),
        _ghidra_change_queue_board(fresh_state),
        _approve_change_button(fresh_state, False),
        _reject_change_button(fresh_state, False),
        _send_button(interactive=True, visible=True),
        _cancel_button(interactive=False, visible=False),
        _send_button(interactive=True, visible=True),
        _todo_board({"shared_state": fresh_shared_state}, visible=False),
    )


def reset():
    fresh_shared_state = _new_shared_state()
    fresh_state = {
        "role_histories": {},
        "tool_log": "",
        "tool_log_sections": {},
        "_tool_log_seen_keys": {},
        "tool_result_cache": {},
        "status_log": "",
        "active_run_id": "",
        "cancel_requested": False,
        "allow_parent_input": DEFAULT_ALLOW_PARENT_INPUT,
        "shell_execution_mode": DEFAULT_SHELL_EXECUTION_MODE,
        "validator_review_level": DEFAULT_VALIDATOR_REVIEW_LEVEL,
        "deep_agent_auto_select_pipeline": DEEP_AGENT_AUTO_SELECT_PIPELINE,
        "deep_agent_architecture_name": DEEP_AGENT_ARCHITECTURE_NAME,
        "deep_agent_pipeline_name": "dynamic" if DEEP_AGENT_AUTO_SELECT_PIPELINE else DEEP_AGENT_PIPELINE_NAME,
        "pending_parent_input": _empty_parent_input(),
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
    parent_prompt_update, parent_response_update, parent_submit_update, parent_decline_update = (
        _parent_input_component_updates(
            fresh_state,
            interactive=True,
            reset_response=True,
        )
    )
    return _ui_updates(
        _message_input(value="", interactive=True, visible=True),
        [],
        fresh_state,
        _allow_parent_input_checkbox(fresh_state, interactive=True, visible=True),
        _shell_execution_mode_dropdown(fresh_state, interactive=True, visible=True),
        _validator_review_level_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_auto_select_checkbox(fresh_state, interactive=True, visible=True),
        _architecture_preset_dropdown(fresh_state, interactive=True, visible=True),
        _pipeline_preset_dropdown(fresh_state, interactive=True, visible=True),
        parent_prompt_update,
        parent_response_update,
        parent_submit_update,
        parent_decline_update,
        _validation_gate_board(fresh_state),
        _planned_work_items_board(fresh_state),
        _ghidra_change_queue_board(fresh_state),
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

    extra_lines: List[str] = [
        "",
        "This request should use the dedicated automated bootstrap triage pipeline.",
        "Treat any automation bootstrap metadata and deterministic pre-sweeps as primary starting context.",
        "Do not auto-apply edits or launch dynamic analysis automatically.",
    ]
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
        shell_execution_mode = "none"
        validator_review_level = _normalize_validator_review_level(
            state.get("validator_review_level", DEFAULT_VALIDATOR_REVIEW_LEVEL)
        )
        append_status(state, f"Automation trigger accepted from {source}")

        for _ in chat_turn(
            user_text,
            list(chat_history),
            state,
            False,
            shell_execution_mode,
            validator_review_level,
            False,
            "balanced",
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
        print(f"[automation http] {self.address_string()} - {format % args}", flush=True)

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
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
                    allow_parent_input = gr.Checkbox(
                        label="Allow agent follow-up questions",
                        value=bool(initial_state.get("allow_parent_input")),
                        info="Lets the agent pause and ask for one clarification during a run.",
                    )
                    shell_execution_mode = gr.Dropdown(
                        label="Shell command execution",
                        choices=SHELL_EXECUTION_MODE_CHOICES,
                        value=_normalize_shell_execution_mode(initial_state.get("shell_execution_mode", DEFAULT_SHELL_EXECUTION_MODE)),
                        info="Choose whether local shell commands are blocked, approval-gated, or fully enabled.",
                    )
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
                    parent_prompt_panel = gr.HTML(value=render_parent_input_panel(initial_state), visible=False)
                    parent_response = gr.Textbox(
                        label="Follow-up Response",
                        lines=2,
                        placeholder="Type a concise answer for the agent...",
                        visible=False,
                    )
                    with gr.Row():
                        parent_submit = gr.Button("Submit Answer", visible=False)
                        parent_decline = gr.Button("Decline", visible=False)
                    user = gr.Textbox(
                        label="Message",
                        lines=2,
                        placeholder="Ask something. Example: analyze this sample for hashing, anti-debugging, and network behavior...",
                    )
                    with gr.Row():
                        send = gr.Button("Send", variant="primary")
                        cancel = gr.Button("Cancel", visible=False)
                        clear = gr.Button("Reset")

                with gr.Column(scale=2):
                    with gr.Accordion("Planned Work Items", open=False):
                        planned_work_items_panel = gr.HTML(value=render_planned_work_items_panel(initial_state))
                    with gr.Accordion("Validation Gate", open=False):
                        validation_gate_panel = gr.HTML(value=render_validation_gate_panel(initial_state))
                    with gr.Accordion("Ghidra Change Queue", open=False, elem_id="ghidra-change-queue-accordion"):
                        ghidra_change_queue_panel = gr.HTML(
                            value=render_ghidra_change_queue_panel(initial_state),
                            elem_id="ghidra-change-queue-panel",
                        )
                        with gr.Row():
                            approve_change = gr.Button("Approve Next Change", interactive=False)
                            reject_change = gr.Button("Reject Next Change", interactive=False)
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
                allow_parent_input,
                shell_execution_mode,
                validator_review_level,
                pipeline_auto_select,
                architecture_preset,
                pipeline_preset,
                parent_prompt_panel,
                parent_response,
                parent_submit,
                parent_decline,
                validation_gate_panel,
                planned_work_items_panel,
                ghidra_change_queue_panel,
                approve_change,
                reject_change,
                *tool_log_boxes,
                send,
                cancel,
                clear,
                todo_board,
            ]
            send_event = send.click(
                chat_turn,
                inputs=[
                    user,
                    chat,
                    state,
                    allow_parent_input,
                    shell_execution_mode,
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
                    allow_parent_input,
                    shell_execution_mode,
                    validator_review_level,
                    pipeline_auto_select,
                    architecture_preset,
                    pipeline_preset,
                ],
                outputs=ui_outputs,
            )
            allow_parent_input.change(
                set_allow_parent_input,
                inputs=[allow_parent_input, state],
                outputs=[state, allow_parent_input, parent_prompt_panel, parent_response, parent_submit, parent_decline],
                show_progress="hidden",
            )
            shell_execution_mode.change(
                set_shell_execution_mode,
                inputs=[shell_execution_mode, state],
                outputs=[state, shell_execution_mode],
                show_progress="hidden",
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
            parent_submit.click(
                submit_parent_input,
                inputs=[parent_response, state],
                outputs=[state, allow_parent_input, parent_prompt_panel, parent_response, parent_submit, parent_decline],
                show_progress="hidden",
            )
            parent_response.submit(
                submit_parent_input,
                inputs=[parent_response, state],
                outputs=[state, allow_parent_input, parent_prompt_panel, parent_response, parent_submit, parent_decline],
                show_progress="hidden",
            )
            parent_decline.click(
                decline_parent_input,
                inputs=[state],
                outputs=[state, allow_parent_input, parent_prompt_panel, parent_response, parent_submit, parent_decline],
                show_progress="hidden",
            )
            approve_change.click(
                approve_next_ghidra_change,
                inputs=[chat, state],
                outputs=ui_outputs,
                show_progress="hidden",
                queue=False,
            )
            reject_change.click(
                reject_next_ghidra_change,
                inputs=[chat, state],
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
