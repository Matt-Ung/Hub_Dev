import html
import json
import os
import re
import time
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from threading import Event, Lock
from uuid import uuid4
from typing import Any, Dict, List, Optional, Tuple

from pydantic_ai import ModelMessage
from pydantic_ai.messages import (
    FunctionToolCallEvent,
    FunctionToolResultEvent,
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

from .config import (
    DEEP_AGENT_ARCHITECTURE_NAME,
    DEEP_AGENT_AUTO_SELECT_PIPELINE,
    DEEP_AGENT_PIPELINE_NAME,
    DEFAULT_ALLOW_PARENT_INPUT,
    DEFAULT_SHELL_EXECUTION_MODE,
    DEFAULT_VALIDATOR_REVIEW_LEVEL,
    GHIDRA_CHANGE_PROPOSALS_END,
    GHIDRA_CHANGE_PROPOSALS_START,
    GHIDRA_EXECUTABLE_MD5_RE,
    GHIDRA_EXECUTABLE_PATH_RE,
    GHIDRA_EXECUTABLE_SHA256_RE,
    GHIDRA_IMAGE_BASE_RE,
    MAX_ROLE_HISTORY_MESSAGES,
    MAX_STATUS_LOG_LINES,
    MAX_TASK_OUTPUTS,
    MAX_TOOL_LOG_CHARS,
    MAX_VALIDATION_REPLAN_RETRIES,
    PATH_HANDOFF_LINE_PREFIX,
    REPO_ROOT,
    SAMPLE_PATH_POSIX_RE,
    SAMPLE_PATH_QUOTED_RE,
    SAMPLE_PATH_WINDOWS_RE,
    STATUS_LOG_STDOUT,
)

_LIVE_TOOL_LOG_STATE: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "live_tool_log_state",
    default=None,
)
_STATE_MUTATION_LOCK = Lock()
_PARENT_INPUT_LOCK = Lock()
_PARENT_INPUT_REQUESTS: Dict[str, Dict[str, Any]] = {}
_SERVER_RUN_TOOL_LOG_LOCK = Lock()
_SERVER_RUN_TOOL_LOG_DIR: Optional[Path] = None
_SERVER_RUN_TOOL_LOG_STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
_SERVER_RUN_TOOL_LOG_ANNOUNCED = False

# ----------------------------
# Tool log extraction (best-effort)
# ----------------------------
def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def _normalize_tool_args(args: Any) -> Any:
    if args is None:
        return {}
    if isinstance(args, dict):
        return _json_safe(args)
    if isinstance(args, str):
        stripped = args.strip()
        if not stripped:
            return {}
        try:
            return _json_safe(json.loads(stripped))
        except Exception:
            return stripped
    return str(args)


def _tool_call_entry(
    stage_name: str,
    tool_name: str,
    tool_call_id: str,
    args: Any,
    *,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "stage": stage_name,
        "kind": "tool_call",
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "args": _normalize_tool_args(args),
    }
    if source:
        entry["source"] = source
    return entry


def _tool_result_entry(
    stage_name: str,
    tool_name: str,
    tool_call_id: str,
    content: Any,
    *,
    source: Optional[str] = None,
    kind: str = "tool_return",
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "stage": stage_name,
        "kind": kind,
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "content": _coerce_tool_return_text(content),
    }
    if source:
        entry["source"] = source
    return entry


def extract_tool_log_entries_from_messages(
    messages: List[ModelMessage],
    stage_name: str,
) -> List[Dict[str, Any]]:
    """
    Walk the message stream and pull out tool calls + tool returns.
    This is for debugging/UI visibility, not a stable format.
    """
    out: List[Dict[str, Any]] = []

    for m in messages:
        if isinstance(m, ModelRequest):
            for part in getattr(m, "parts", []) or []:
                if isinstance(part, ToolReturnPart):
                    out.append(
                        _tool_result_entry(
                            stage_name,
                            part.tool_name,
                            part.tool_call_id,
                            part.content,
                        )
                    )

        elif isinstance(m, ModelResponse):
            for part in getattr(m, "parts", []) or []:
                if isinstance(part, ToolCallPart):
                    out.append(
                        _tool_call_entry(
                            stage_name,
                            part.tool_name,
                            part.tool_call_id,
                            part.args,
                        )
                    )
                elif isinstance(part, ToolReturnPart):
                    out.append(
                        _tool_result_entry(
                            stage_name,
                            part.tool_name,
                            part.tool_call_id,
                            part.content,
                        )
                    )

    return out


def _tool_log_dedupe_key(entry: Dict[str, Any]) -> str:
    stable = {k: v for k, v in entry.items() if k != "source"}
    return json.dumps(stable, sort_keys=True, ensure_ascii=False, default=str)


def _stage_log_filename(stage_name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(stage_name or "").strip()).strip("._")
    return f"{safe or 'unknown'}.log"


def _server_run_tool_log_dir() -> Path:
    global _SERVER_RUN_TOOL_LOG_DIR, _SERVER_RUN_TOOL_LOG_ANNOUNCED
    with _SERVER_RUN_TOOL_LOG_LOCK:
        if _SERVER_RUN_TOOL_LOG_DIR is None:
            run_dir = (REPO_ROOT / "logs" / f"agentToolBench_{_SERVER_RUN_TOOL_LOG_STAMP}").resolve()
            run_dir.mkdir(parents=True, exist_ok=True)
            _SERVER_RUN_TOOL_LOG_DIR = run_dir
        if not _SERVER_RUN_TOOL_LOG_ANNOUNCED:
            print(f"[tool log files] writing stage logs to {_SERVER_RUN_TOOL_LOG_DIR}", flush=True)
            _SERVER_RUN_TOOL_LOG_ANNOUNCED = True
        return _SERVER_RUN_TOOL_LOG_DIR


def _append_tool_log_file_entries(
    state: Dict[str, Any],
    stage_name: str,
    rendered_entries: List[str],
) -> None:
    if not rendered_entries:
        return

    timestamp = datetime.now().isoformat(timespec="seconds")
    run_id = str(state.get("active_run_id") or "").strip() or "server"
    log_path = _server_run_tool_log_dir() / _stage_log_filename(stage_name)
    chunks: List[str] = []
    for rendered in rendered_entries:
        chunks.append(f"[{timestamp}] run_id={run_id} stage={stage_name}")
        chunks.append(rendered)
        chunks.append("")
    payload = "\n".join(chunks)

    try:
        with _SERVER_RUN_TOOL_LOG_LOCK:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(payload)
    except Exception as exc:
        print(f"[tool log files] warning: failed to append {log_path}: {exc}", flush=True)


def _append_tool_log_entries(
    state: Dict[str, Any],
    stage_name: str,
    entries: List[Dict[str, Any]],
) -> None:
    if not entries:
        return

    with _STATE_MUTATION_LOCK:
        seen = state.setdefault("_tool_log_seen_keys", {})
        sections = state.setdefault("tool_log_sections", {})
        rendered_entries: List[str] = []

        for entry in entries:
            dedupe_key = _tool_log_dedupe_key(entry)
            if seen.get(dedupe_key):
                continue
            seen[dedupe_key] = True
            rendered_entries.append(json.dumps(_json_safe(entry), indent=2, ensure_ascii=False))

        if not rendered_entries:
            return

        addition = "\n\n".join(rendered_entries)

        prev = str(state.get("tool_log") or "").strip()
        merged = f"{prev}\n\n{addition}".strip() if prev else addition
        if len(merged) > MAX_TOOL_LOG_CHARS:
            merged = merged[-MAX_TOOL_LOG_CHARS:]
        state["tool_log"] = merged

        prev_section = str(sections.get(stage_name) or "").strip()
        merged_section = f"{prev_section}\n\n{addition}".strip() if prev_section else addition
        if len(merged_section) > MAX_TOOL_LOG_CHARS:
            merged_section = merged_section[-MAX_TOOL_LOG_CHARS:]
        sections[stage_name] = merged_section
    _append_tool_log_file_entries(state, stage_name, rendered_entries)
    _store_ui_snapshot(state=state)


def _build_live_tool_log_entries(
    stage_name: str,
    source_label: str,
    event: Any,
) -> List[Dict[str, Any]]:
    if isinstance(event, FunctionToolCallEvent):
        return [
            _tool_call_entry(
                stage_name,
                event.part.tool_name,
                event.tool_call_id,
                event.part.args,
                source=source_label,
            )
        ]

    if isinstance(event, FunctionToolResultEvent):
        if isinstance(event.result, ToolReturnPart):
            return [
                _tool_result_entry(
                    stage_name,
                    event.result.tool_name,
                    event.tool_call_id,
                    event.result.content,
                    source=source_label,
                )
            ]
        if isinstance(event.result, RetryPromptPart):
            return [
                _tool_result_entry(
                    stage_name,
                    event.result.tool_name or "<retry>",
                    event.tool_call_id,
                    event.result.content,
                    source=source_label,
                    kind="tool_retry",
                )
            ]

    return []


def make_live_tool_event_handler(stage_name: str, source_label: str):
    async def _handler(_ctx: Any, events: Any) -> None:
        async for event in events:
            state = _LIVE_TOOL_LOG_STATE.get()
            if state is None:
                continue
            _append_tool_log_entries(
                state,
                stage_name,
                _build_live_tool_log_entries(stage_name, source_label, event),
            )

    return _handler


def append_tool_log_delta(
    state: Dict[str, Any],
    stage_name: str,
    old_history: List[ModelMessage],
    new_history: List[ModelMessage],
) -> None:
    """
    Append only new tool logs (delta) to UI state to avoid duplicates.
    """
    old_len = len(old_history) if old_history else 0
    delta = new_history[old_len:]
    _append_tool_log_entries(state, stage_name, extract_tool_log_entries_from_messages(delta, stage_name))


def _sanitize_user_facing_output(text: str) -> str:
    output = re.sub(
        rf"{re.escape(GHIDRA_CHANGE_PROPOSALS_START)}[\s\S]*?{re.escape(GHIDRA_CHANGE_PROPOSALS_END)}",
        "",
        text or "",
        flags=re.DOTALL,
    )
    cleaned: List[str] = []
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        lowered = stripped.lower()
        if lowered.startswith(PATH_HANDOFF_LINE_PREFIX.lower()):
            continue
        if "validated_sample_path:" in lowered:
            continue
        if "validated_sample_path_source:" in lowered:
            continue
        if "validated_sample_md5:" in lowered:
            continue
        if "validated_sample_sha256:" in lowered:
            continue
        if "validated_sample_image_base:" in lowered:
            continue
        if "validated_sample_metadata_source:" in lowered:
            continue
        if "no validated sample path is currently available in shared context" in lowered:
            continue
        if lowered.startswith("- path rule:") or lowered.startswith("path rule:"):
            continue
        if lowered.startswith("- metadata trust rule:") or lowered.startswith("metadata trust rule:"):
            continue
        if lowered.startswith("- if you discover the real sample path"):
            continue
        cleaned.append(raw_line)

    output = "\n".join(cleaned)
    output = re.sub(r"\n{3,}", "\n\n", output).strip()
    return output


def _annotate_unapproved_ghidra_aliases(text: str, shared_state: Optional[Dict[str, Any]]) -> str:
    output = str(text or "")
    shared = shared_state or {}
    if not output:
        return output

    proposals = list(shared.get("ghidra_change_draft_proposals") or shared.get("ghidra_change_proposals") or [])
    if not proposals:
        return output

    replacements: List[Tuple[str, str]] = []
    for proposal in proposals:
        if not isinstance(proposal, dict):
            continue
        status = str(proposal.get("status") or "").strip().lower()
        if status == "applied":
            continue
        action = str(proposal.get("action") or "").strip().lower()
        if action not in {"rename_function", "rename_function_by_address"}:
            continue
        proposed_name = str(proposal.get("proposed_name") or "").strip()
        current_name = str(
            proposal.get("current_name")
            or proposal.get("function_name")
            or proposal.get("function_address")
            or ""
        ).strip()
        if not proposed_name or not current_name or proposed_name == current_name:
            continue
        replacements.append((proposed_name, current_name))

    if not replacements:
        return output

    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    for proposed_name, current_name in replacements:
        replacement_text = f"{current_name} (proposed alias: {proposed_name})"
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_]){re.escape(proposed_name)}(?![A-Za-z0-9_])"
        )

        def _replace(match: re.Match[str]) -> str:
            start, end = match.span()
            window = output[max(0, start - 120): min(len(output), end + 120)]
            lowered_window = window.lower()
            if "proposed alias:" in lowered_window:
                return match.group(0)
            if current_name in window:
                return match.group(0)
            return replacement_text

        output = pattern.sub(_replace, output)

    return output


# ----------------------------
# Multi-agent shared state helpers
# ----------------------------
def _status_ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _shorten(text: str, max_chars: int = 120) -> str:
    t = " ".join((text or "").strip().split())
    if len(t) <= max_chars:
        return t
    return t[: max_chars - 3] + "..."


def append_status(state: Dict[str, Any], message: str) -> None:
    line = f"[{_status_ts()}] {message}"
    with _STATE_MUTATION_LOCK:
        lines = (state.get("status_log") or "").splitlines()
        lines.append(line)
        if len(lines) > MAX_STATUS_LOG_LINES:
            lines = lines[-MAX_STATUS_LOG_LINES:]
        state["status_log"] = "\n".join(lines)
    _store_ui_snapshot(state=state)
    if STATUS_LOG_STDOUT:
        print(line, flush=True)


def get_role_history(state: Dict[str, Any], role_key: str) -> List[ModelMessage]:
    return (state.get("role_histories") or {}).get(role_key, []) or []


def _message_has_part(msg: ModelMessage, part_type: type) -> bool:
    return any(isinstance(p, part_type) for p in (getattr(msg, "parts", []) or []))


def _is_user_request_message(msg: ModelMessage) -> bool:
    return isinstance(msg, ModelRequest) and _message_has_part(msg, UserPromptPart)


def _trim_role_history_safely(history: List[ModelMessage]) -> List[ModelMessage]:
    if len(history) <= MAX_ROLE_HISTORY_MESSAGES:
        return history

    window = history[-MAX_ROLE_HISTORY_MESSAGES:]
    for i, msg in enumerate(window):
        if _is_user_request_message(msg):
            return window[i:]

    # If no user boundary exists in the capped window, keep the full last turn.
    # This avoids invalid orphan tool messages caused by truncating mid tool-call chain.
    for i in range(len(history) - 1, -1, -1):
        if _is_user_request_message(history[i]):
            return history[i:]

    return history


def set_role_history(state: Dict[str, Any], role_key: str, history: List[ModelMessage]) -> None:
    if history:
        history = _trim_role_history_safely(history)
    if "role_histories" not in state:
        state["role_histories"] = {}
    state["role_histories"][role_key] = history


def compact_shared_state(state: Dict[str, Any]) -> None:
    if "shared_state" not in state:
        return
    shared = state["shared_state"]
    outputs = shared.get("task_outputs", []) or []
    if len(outputs) > MAX_TASK_OUTPUTS:
        shared["task_outputs"] = outputs[-MAX_TASK_OUTPUTS:]
    automation_history = shared.get("automation_history", []) or []
    if len(automation_history) > 8:
        shared["automation_history"] = automation_history[-8:]
    auto_triage_runs = shared.get("auto_triage_runs", []) or []
    if len(auto_triage_runs) > 6:
        shared["auto_triage_runs"] = auto_triage_runs[-6:]
    generated_yara_rules = shared.get("generated_yara_rules", []) or []
    if len(generated_yara_rules) > 12:
        shared["generated_yara_rules"] = generated_yara_rules[-12:]


def _pending_parent_input(state: Dict[str, Any]) -> Dict[str, Any]:
    pending = state.get("pending_parent_input")
    if not isinstance(pending, dict):
        pending = _empty_parent_input()
        state["pending_parent_input"] = pending
    return pending


def _clear_pending_parent_input(state: Dict[str, Any], *, request_id: str = "") -> None:
    pending = _pending_parent_input(state)
    if request_id and str(pending.get("request_id") or "") != request_id:
        return
    state["pending_parent_input"] = _empty_parent_input()
    _store_ui_snapshot(state=state)


def _start_parent_input_request(
    state: Dict[str, Any],
    *,
    question: str,
    options: List[Dict[str, str]],
    source: str,
) -> Tuple[str, Event, str]:
    pending = _pending_parent_input(state)
    current_id = str(pending.get("request_id") or "")
    if current_id and str(pending.get("status") or "") == "waiting":
        return "", Event(), "Error: Another parent-input question is already pending"

    request_id = uuid4().hex
    event = Event()
    with _PARENT_INPUT_LOCK:
        _PARENT_INPUT_REQUESTS[request_id] = {
            "event": event,
            "response": None,
        }

    state["pending_parent_input"] = {
        "request_id": request_id,
        "question": str(question or "").strip(),
        "options": list(options or []),
        "response": "",
        "source": source,
        "asked_at": datetime.now().isoformat(timespec="seconds"),
        "status": "waiting",
    }
    append_status(state, f"Parent input requested by {source}")
    _store_ui_snapshot(state=state)
    return request_id, event, ""


def _resolve_parent_input_request(
    state: Dict[str, Any],
    *,
    response: str,
    declined: bool = False,
) -> bool:
    pending = _pending_parent_input(state)
    request_id = str(pending.get("request_id") or "")
    if not request_id:
        return False

    with _PARENT_INPUT_LOCK:
        request = _PARENT_INPUT_REQUESTS.get(request_id)
    if request is None:
        _clear_pending_parent_input(state, request_id=request_id)
        return False

    text = (response or "").strip()
    final_response = "Error: Parent declined to provide input" if declined else (text or "Error: Parent provided an empty response")
    request["response"] = final_response
    event = request.get("event")
    if isinstance(event, Event):
        event.set()

    append_status(
        state,
        "Parent input declined" if declined else "Parent input submitted",
    )
    _clear_pending_parent_input(state, request_id=request_id)
    return True


def _wait_for_parent_input_response(
    state: Dict[str, Any],
    *,
    question: str,
    options: List[Dict[str, str]],
    source: str,
    timeout_sec: float = 300.0,
) -> str:
    request_id, event, error = _start_parent_input_request(
        state,
        question=question,
        options=options,
        source=source,
    )
    if error:
        return error

    if not event.wait(timeout_sec):
        with _PARENT_INPUT_LOCK:
            _PARENT_INPUT_REQUESTS.pop(request_id, None)
        append_status(state, f"Parent input timed out for {source}")
        _clear_pending_parent_input(state, request_id=request_id)
        return "Error: Parent did not respond in time"

    with _PARENT_INPUT_LOCK:
        request = _PARENT_INPUT_REQUESTS.pop(request_id, None)

    response = str((request or {}).get("response") or "").strip()
    if not response:
        response = "Error: Parent response was unavailable"
    _clear_pending_parent_input(state, request_id=request_id)
    return response


def _make_parent_input_callback(state: Dict[str, Any], source: str):
    async def _callback(question: str, options: List[Dict[str, str]]) -> str:
        if bool(state.get("cancel_requested")):
            return "Error: Pipeline canceled by user"
        if not bool(state.get("allow_parent_input")):
            return "Error: Parent input is disabled for this run"
        normalized_options: List[Dict[str, str]] = []
        for item in options or []:
            if not isinstance(item, dict):
                continue
            normalized_options.append({str(k): str(v) for k, v in item.items()})
        return await asyncio.to_thread(
            _wait_for_parent_input_response,
            state,
            question=str(question or ""),
            options=normalized_options,
            source=source,
        )

    return _callback


def render_parent_input_panel(state: Dict[str, Any]) -> str:
    pending = _pending_parent_input(state or {})
    if str(pending.get("status") or "") != "waiting":
        return ""

    question = html.escape(str(pending.get("question") or ""))
    source = html.escape(str(pending.get("source") or "agent"))
    asked_at = html.escape(str(pending.get("asked_at") or ""))
    options = pending.get("options") or []
    options_html = ""
    if options:
        rows: List[str] = []
        for item in options:
            if not isinstance(item, dict):
                continue
            label = html.escape(str(item.get("label") or "option"))
            description = html.escape(str(item.get("description") or ""))
            rows.append(f"<li><strong>{label}</strong>{': ' + description if description else ''}</li>")
        if rows:
            options_html = (
                "<div style='margin-top: 8px; color: #202124;'>Suggested options:</div>"
                f"<ul style='margin-top: 4px; padding-left: 18px;'>{''.join(rows)}</ul>"
            )

    return (
        "<div style='padding: 12px; border: 1px solid #f0c36d; border-radius: 10px; background: #fff8e1; margin-top: 12px;'>"
        "<div style='display: flex; justify-content: space-between; gap: 12px; align-items: baseline;'>"
        "<strong>Follow-up Question</strong>"
        f"<span style='color: #5f6368; font-size: 12px;'>{source} | {asked_at}</span>"
        "</div>"
        f"<div style='margin-top: 8px; color: #202124;'>{question}</div>"
        + options_html
        + "</div>"
    )


def _normalize_path_candidate(candidate: str) -> str:
    value = (candidate or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    value = value.strip().rstrip(".,;:")
    if value.endswith(")") and value.count("(") < value.count(")"):
        value = value[:-1]
    if value.endswith("]") and value.count("[") < value.count("]"):
        value = value[:-1]
    return value.strip()


def _looks_like_placeholder_path(candidate: str) -> bool:
    normalized = _normalize_path_candidate(candidate).lower().replace("\\", "/")
    if not normalized:
        return True
    placeholder_markers = (
        "/path/to/",
        "c:/path/to/",
        "path/to/your/",
        "path/to/sample",
        "path/to/program",
        "your/program",
        "your/sample",
        "<sample",
        "<path",
        "{sample",
        "{path",
    )
    return any(marker in normalized for marker in placeholder_markers)


def _validate_existing_sample_path(candidate: str) -> Optional[str]:
    normalized = _normalize_path_candidate(candidate)
    if not normalized or _looks_like_placeholder_path(normalized):
        return None

    expanded = os.path.expandvars(os.path.expanduser(normalized))
    if not os.path.exists(expanded):
        return None

    try:
        return str(Path(expanded).resolve())
    except Exception:
        return os.path.abspath(expanded)


def _extract_validated_path_handoff(text: str) -> Optional[str]:
    for raw_line in (text or "").splitlines():
        if PATH_HANDOFF_LINE_PREFIX.lower() not in raw_line.lower():
            continue
        _, _, candidate = raw_line.partition(":")
        validated = _validate_existing_sample_path(candidate)
        if validated:
            return validated
    return None


def _extract_sample_path_candidates(text: str) -> List[str]:
    seen: set[str] = set()
    candidates: List[str] = []

    for pattern in (SAMPLE_PATH_QUOTED_RE, SAMPLE_PATH_WINDOWS_RE, SAMPLE_PATH_POSIX_RE):
        for match in pattern.finditer(text or ""):
            validated = _validate_existing_sample_path(match.group(1))
            if not validated or validated in seen:
                continue
            seen.add(validated)
            candidates.append(validated)

    return candidates


def _coerce_tool_return_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(item) for item in content)
    return str(content)


def _extract_ghidra_executable_path(text: str) -> Optional[str]:
    match = GHIDRA_EXECUTABLE_PATH_RE.search(text or "")
    if not match:
        return None
    return _validate_existing_sample_path(match.group(1))


def _normalize_digest(value: str, expected_len: int) -> str:
    digest = (value or "").strip().lower()
    if len(digest) != expected_len:
        return ""
    return digest if all(ch in "0123456789abcdef" for ch in digest) else ""


def _extract_ghidra_program_metadata(text: str) -> Dict[str, str]:
    content = text or ""
    metadata: Dict[str, str] = {}
    path = _extract_ghidra_executable_path(content)
    if path:
        metadata["path"] = path
    md5_match = GHIDRA_EXECUTABLE_MD5_RE.search(content)
    if md5_match:
        md5 = _normalize_digest(md5_match.group(1), 32)
        if md5:
            metadata["md5"] = md5
    sha256_match = GHIDRA_EXECUTABLE_SHA256_RE.search(content)
    if sha256_match:
        sha256 = _normalize_digest(sha256_match.group(1), 64)
        if sha256:
            metadata["sha256"] = sha256
    image_base_match = GHIDRA_IMAGE_BASE_RE.search(content)
    if image_base_match:
        image_base = image_base_match.group(1).strip()
        if image_base:
            metadata["image_base"] = image_base
    return metadata


def _payload_nested_value(payload: Dict[str, Any], *keys: str) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def apply_automation_payload_to_state(state: Dict[str, Any], payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        return

    shared = state.setdefault("shared_state", _new_shared_state())
    normalized_payload = _json_safe(payload)
    shared["automation_trigger_payload"] = normalized_payload
    shared["automation_trigger_source"] = str(payload.get("source") or "").strip()
    shared["automation_program_key"] = str(
        payload.get("automation_program_key")
        or payload.get("program_key")
        or payload.get("ghidra_project_path")
        or payload.get("executable_path")
        or payload.get("program_name")
        or ""
    ).strip()
    shared["automation_analysis_token"] = str(
        payload.get("analysis_token")
        or payload.get("automation_signature")
        or payload.get("analysis_completed_at_epoch_ms")
        or ""
    ).strip()
    shared["automation_rerun_reason"] = str(
        payload.get("rerun_reason")
        or payload.get("trigger_reason")
        or ""
    ).strip()

    candidate_path = _validate_existing_sample_path(
        str(
            payload.get("executable_path")
            or _payload_nested_value(payload, "program_info", "program", "executablePath")
            or ""
        )
    )
    candidate_md5 = _normalize_digest(
        str(
            payload.get("executable_md5")
            or _payload_nested_value(payload, "program_info", "program", "executableMD5")
            or ""
        ),
        32,
    )
    candidate_sha256 = _normalize_digest(
        str(
            payload.get("executable_sha256")
            or _payload_nested_value(payload, "program_info", "program", "executableSHA256")
            or ""
        ),
        64,
    )
    candidate_image_base = str(
        payload.get("image_base")
        or _payload_nested_value(payload, "program_info", "program", "imageBase")
        or ""
    ).strip()

    previous_path = shared.get("validated_sample_path")
    if candidate_path:
        if previous_path and previous_path != candidate_path:
            _clear_validated_sample_metadata(shared)
        shared["validated_sample_path"] = candidate_path
        shared["validated_sample_path_source"] = "automation_payload"
    if candidate_md5:
        shared["validated_sample_md5"] = candidate_md5
        shared["validated_sample_metadata_source"] = "automation_payload"
    if candidate_sha256:
        shared["validated_sample_sha256"] = candidate_sha256
        shared["validated_sample_metadata_source"] = "automation_payload"
    if candidate_image_base:
        shared["validated_sample_image_base"] = candidate_image_base
        shared["validated_sample_metadata_source"] = "automation_payload"

    shared["automation_bootstrap_metadata"] = {
        "program_name": str(
            payload.get("program_name") or _payload_nested_value(payload, "program_info", "program", "name") or ""
        ).strip(),
        "ghidra_project_path": str(
            payload.get("ghidra_project_path")
            or _payload_nested_value(payload, "program_info", "program", "ghidraProjectPath")
            or ""
        ).strip(),
        "language": str(
            payload.get("language") or _payload_nested_value(payload, "program_info", "program", "language") or ""
        ).strip(),
        "compiler": str(
            payload.get("compiler") or _payload_nested_value(payload, "program_info", "program", "compiler") or ""
        ).strip(),
        "image_base": candidate_image_base,
        "entry_point": str(payload.get("entry_point") or "").strip(),
        "section_summary": list(payload.get("section_summary") or []),
        "import_summary": list(payload.get("import_summary") or []),
        "export_summary": list(payload.get("export_summary") or []),
        "root_functions": list(payload.get("root_functions") or []),
        "counts": payload.get("counts") if isinstance(payload.get("counts"), dict) else {},
        "auto_analysis_warnings": list(payload.get("auto_analysis_warnings") or []),
        "auto_analysis_failures": list(payload.get("auto_analysis_failures") or []),
    }
    _store_ui_snapshot(state=state)


def record_automation_event(
    state: Dict[str, Any],
    *,
    status: str,
    source: str = "",
    program_key: str = "",
    reason: str = "",
    detail: str = "",
) -> None:
    shared = state.setdefault("shared_state", _new_shared_state())
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    normalized_status = str(status or "").strip() or "unknown"
    normalized_source = str(source or shared.get("automation_trigger_source") or "").strip()
    normalized_program_key = str(program_key or shared.get("automation_program_key") or "").strip()
    normalized_reason = str(reason or "").strip()
    normalized_detail = str(detail or "").strip()

    shared["automation_status"] = normalized_status
    shared["automation_last_source"] = normalized_source
    shared["automation_last_program_key"] = normalized_program_key
    shared["automation_last_reason"] = normalized_reason
    shared["automation_last_detail"] = normalized_detail
    shared["automation_last_at"] = timestamp

    history = shared.setdefault("automation_history", [])
    history.append(
        {
            "at": timestamp,
            "status": normalized_status,
            "source": normalized_source,
            "program_key": normalized_program_key,
            "reason": normalized_reason,
            "detail": normalized_detail,
        }
    )
    if len(history) > 8:
        shared["automation_history"] = history[-8:]

    _store_ui_snapshot(state=state)


def preserved_automation_shared_state(shared: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(shared, dict):
        return {}
    keys = (
        "automation_trigger_payload",
        "automation_trigger_source",
        "automation_program_key",
        "automation_analysis_token",
        "automation_rerun_reason",
        "automation_bootstrap_metadata",
        "automation_status",
        "automation_last_reason",
        "automation_last_source",
        "automation_last_program_key",
        "automation_last_at",
        "automation_last_detail",
        "automation_history",
        "auto_triage_status",
        "auto_triage_last_error",
        "auto_triage_last_run_at",
    )
    preserved: Dict[str, Any] = {}
    for key in keys:
        if key in shared:
            preserved[key] = _json_safe(shared.get(key))
    return preserved


def _clear_validated_sample_metadata(shared: Dict[str, Any]) -> None:
    shared["validated_sample_md5"] = ""
    shared["validated_sample_sha256"] = ""
    shared["validated_sample_image_base"] = ""
    shared["validated_sample_metadata_source"] = ""


def update_validated_sample_path(
    state: Dict[str, Any],
    text: str,
    source: str,
    *,
    explicit_only: bool,
) -> Optional[str]:
    shared = state.setdefault("shared_state", {})
    previous = shared.get("validated_sample_path")
    validated = _extract_validated_path_handoff(text) if explicit_only else None

    if validated is None and not explicit_only:
        candidates = _extract_sample_path_candidates(text)
        validated = candidates[0] if candidates else None

    if not validated:
        return previous

    if previous and previous != validated:
        _clear_validated_sample_metadata(shared)
    shared["validated_sample_path"] = validated
    shared["validated_sample_path_source"] = source
    if previous != validated:
        append_status(state, f"Validated sample path set from {source}: {validated}")
    return validated


def update_validated_sample_path_from_messages(
    state: Dict[str, Any],
    messages: List[ModelMessage],
    source: str,
) -> Optional[str]:
    for msg in messages:
        if not isinstance(msg, (ModelRequest, ModelResponse)):
            continue
        for part in getattr(msg, "parts", []) or []:
            if not isinstance(part, ToolReturnPart):
                continue
            text = _coerce_tool_return_text(part.content)
            metadata = _extract_ghidra_program_metadata(text)
            validated = metadata.get("path")
            if not metadata:
                continue
            shared = state.setdefault("shared_state", _new_shared_state())
            previous = shared.get("validated_sample_path")
            if validated:
                if previous and previous != validated:
                    _clear_validated_sample_metadata(shared)
                shared["validated_sample_path"] = validated
                shared["validated_sample_path_source"] = source
                if previous != validated:
                    append_status(state, f"Validated sample path set from {source}: {validated}")
            metadata_changed = False
            if metadata.get("md5") and shared.get("validated_sample_md5") != metadata["md5"]:
                shared["validated_sample_md5"] = metadata["md5"]
                metadata_changed = True
            if metadata.get("sha256") and shared.get("validated_sample_sha256") != metadata["sha256"]:
                shared["validated_sample_sha256"] = metadata["sha256"]
                metadata_changed = True
            if metadata.get("image_base") and shared.get("validated_sample_image_base") != metadata["image_base"]:
                shared["validated_sample_image_base"] = metadata["image_base"]
                metadata_changed = True
            if metadata_changed:
                shared["validated_sample_metadata_source"] = source
                append_status(state, f"Trusted sample metadata set from {source}.")
            if validated:
                return validated
    return state.setdefault("shared_state", _new_shared_state()).get("validated_sample_path")


def _new_shared_state() -> Dict[str, Any]:
    return {
        "artifacts": [],
        "findings": [],
        "task_outputs": [],
        "run_count": 0,
        "turn_task_runs": 0,
        "total_task_runs": 0,
        "validated_sample_path": "",
        "validated_sample_path_source": "",
        "validated_sample_md5": "",
        "validated_sample_sha256": "",
        "validated_sample_image_base": "",
        "validated_sample_metadata_source": "",
        "planned_work_items": [],
        "planned_work_item_status": {},
        "planned_work_items_parse_error": "",
        "ghidra_change_proposals": [],
        "ghidra_change_draft_proposals": [],
        "ghidra_change_queue_finalized": False,
        "ghidra_change_parse_error": "",
        "generated_yara_rules": [],
        "generated_yara_rule_parse_error": "",
        "pipeline_stage_outputs": [],
        "pipeline_stage_progress": [],
        "available_static_tools": [],
        "available_dynamic_tools": [],
        "available_sandbox_tools": [],
        "supports_dynamic_analysis": False,
        "supports_sandboxed_execution": False,
        "automation_trigger_payload": {},
        "automation_trigger_source": "",
        "automation_program_key": "",
        "automation_analysis_token": "",
        "automation_rerun_reason": "",
        "automation_bootstrap_metadata": {},
        "automation_status": "",
        "automation_last_reason": "",
        "automation_last_source": "",
        "automation_last_program_key": "",
        "automation_last_at": "",
        "automation_last_detail": "",
        "automation_history": [],
        "auto_triage_pre_sweeps": {},
        "auto_triage_pre_sweep_summary": "",
        "auto_triage_report": "",
        "auto_triage_context_summary": "",
        "auto_triage_status": "",
        "auto_triage_last_error": "",
        "auto_triage_last_run_at": "",
        "auto_triage_sample_path": "",
        "auto_triage_sample_sha256": "",
        "auto_triage_runs": [],
        "shell_execution_mode": DEFAULT_SHELL_EXECUTION_MODE,
        "validator_review_level": "default",
        "validation_retry_count": 0,
        "validation_max_retries": MAX_VALIDATION_REPLAN_RETRIES,
        "validation_last_decision": "",
        "validation_replan_feedback": "",
        "validation_history": [],
    }


def _empty_parent_input() -> Dict[str, Any]:
    return {
        "request_id": "",
        "question": "",
        "options": [],
        "response": "",
        "source": "",
        "asked_at": "",
        "status": "idle",
    }


_UI_SNAPSHOT_LOCK = Lock()
_UI_SNAPSHOT: Dict[str, Any] = {
    "chat_history": [],
    "state": {
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
        "pending_parent_input": _empty_parent_input(),
        "shared_state": _new_shared_state(),
    },
    "tool_log": "",
    "run_active": False,
    "composer_visible": True,
    "send_visible": True,
    "clear_visible": True,
    "todo_visible": False,
    "tool_log_visible": False,
}


def _snapshot_state_default() -> Dict[str, Any]:
    default_pipeline_selector_value = "dynamic" if DEEP_AGENT_AUTO_SELECT_PIPELINE else DEEP_AGENT_PIPELINE_NAME
    return {
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
        "deep_agent_pipeline_name": default_pipeline_selector_value,
        "pending_parent_input": _empty_parent_input(),
        "shared_state": _new_shared_state(),
    }


def _store_ui_snapshot(
    *,
    chat_history: Optional[List[Dict[str, str]]] = None,
    state: Optional[Dict[str, Any]] = None,
    run_active: Optional[bool] = None,
    composer_visible: Optional[bool] = None,
    send_visible: Optional[bool] = None,
    clear_visible: Optional[bool] = None,
    todo_visible: Optional[bool] = None,
    tool_log_visible: Optional[bool] = None,
    force: bool = False,
) -> None:
    with _UI_SNAPSHOT_LOCK:
        current_state = _UI_SNAPSHOT.get("state") or {}
        current_run_id = str((current_state or {}).get("active_run_id") or "").strip()
        incoming_run_id = str((state or {}).get("active_run_id") or "").strip()
        if (
            not force
            and current_run_id
            and incoming_run_id
            and current_run_id != incoming_run_id
        ):
            return
        if chat_history is not None:
            _UI_SNAPSHOT["chat_history"] = chat_history
        if state is not None:
            _UI_SNAPSHOT["state"] = state
            _UI_SNAPSHOT["tool_log"] = state.get("tool_log", "")
        if run_active is not None:
            _UI_SNAPSHOT["run_active"] = run_active
        if composer_visible is not None:
            _UI_SNAPSHOT["composer_visible"] = composer_visible
        if send_visible is not None:
            _UI_SNAPSHOT["send_visible"] = send_visible
        if clear_visible is not None:
            _UI_SNAPSHOT["clear_visible"] = clear_visible
        if todo_visible is not None:
            _UI_SNAPSHOT["todo_visible"] = todo_visible
        if tool_log_visible is not None:
            _UI_SNAPSHOT["tool_log_visible"] = tool_log_visible


def _get_ui_snapshot() -> Dict[str, Any]:
    with _UI_SNAPSHOT_LOCK:
        return dict(_UI_SNAPSHOT)
