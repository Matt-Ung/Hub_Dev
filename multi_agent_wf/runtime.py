import asyncio
import json
import re
import sys
import time
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

import pydantic_deep as pydantic_deep_pkg
from pydantic_deep import create_deep_agent, create_default_deps, create_sliding_window_processor

from .config import (
    AGENT_ARCHETYPE_PROMPTS,
    AGENT_ARCHETYPE_SPECS,
    DEEP_AGENT_ARCHITECTURE,
    DEEP_AGENT_ARCHITECTURE_DESCRIPTIONS,
    DEEP_AGENT_ARCHITECTURE_NAME,
    DEEP_AGENT_ARCHITECTURE_FALLBACK_NAME,
    DEEP_AGENT_ARCHITECTURE_PRESETS,
    DEEP_AGENT_AUTO_SELECT_PIPELINE,
    DEEP_AGENT_PIPELINE_DESCRIPTIONS,
    DEEP_AGENT_PIPELINE_NAME,
    DEEP_AGENT_PIPELINE_PRESETS,
    DEEP_AGENT_PIPELINE_ROUTER_MODEL,
    DEEP_AGENT_RETRIES,
    DEEP_BACKEND_ROOT,
    DEEP_CONTEXT_MAX_TOKENS,
    DEEP_ENABLE_MEMORY,
    DEEP_ENABLE_SKILLS,
    DEEP_FORCE_MODEL_ID,
    DEEP_INCLUDE_BUNDLED_SKILLS,
    DEEP_MEMORY_DIR,
    DEEP_PERSIST_BACKEND,
    DEEP_SKILL_DIRS,
    DEEP_WORKER_PERSONA_PROFILE,
    DEEP_WORKER_SUBAGENT_PROFILE,
    DEFAULT_SHELL_EXECUTION_MODE,
    GHIDRA_CHANGE_PROPOSALS_END,
    GHIDRA_CHANGE_PROPOSALS_START,
    MAX_TOOL_RESULT_CACHE_ENTRIES,
    MAX_VALIDATION_REPLAN_RETRIES,
    MCP_SERVER_MANIFEST_PATH,
    OPENAI_MODEL_ID,
    PATH_HANDOFF_LINE_PREFIX,
    PIPELINE_STAGE_MANAGER_PROMPTS,
    PIPELINE_STAGE_OUTPUT_CONTRACTS,
    REPO_ROOT,
    SERIAL_MCP_SERVER_MARKERS,
    SHELL_EXECUTION_MODE_LABELS,
    stage_kind_flag,
    get_stage_kind_metadata,
    TOOL_RESULT_CACHE_SERVER_MARKERS,
    VALIDATOR_REVIEW_LEVEL_LABELS,
    WORKER_PERSONA_PROFILES,
    YARA_RULE_PROPOSALS_END,
    YARA_RULE_PROPOSALS_START,
    _normalize_shell_execution_mode,
    _normalize_validator_review_level,
    _resolve_repo_relative_path,
    resolve_pipeline_definition,
)
from .shared_state import (
    _append_tool_log_entries,
    _annotate_unapproved_ghidra_aliases,
    _LIVE_TOOL_LOG_STATE,
    _json_safe,
    _sanitize_user_facing_output,
    _shorten,
    _wait_for_parent_input_response,
    append_status,
    make_live_tool_event_handler,
)

# ----------------------------
# MCP server loading
# ----------------------------
_PIPELINE_ROUTER_AGENT: Agent | None = None
_ARCHITECTURE_ROUTER_AGENT: Agent | None = None
_AUTO_TRIAGE_HASHDB_ALGORITHMS = ("crc32", "fnv1a32", "djb2", "sdbm")
_HASHLIKE_STRING_RE = re.compile(r"(?i)\b(?:0x)?([0-9a-f]{8,16})\b")
_AUTO_TRIAGE_UPX_OUTPUT_DIR = REPO_ROOT / ".deep" / "auto_triage_unpack"
_FUNCTION_NAME_LIKE_RE = re.compile(r"^(?:FUN_|sub_|LAB_|thunk_)?[A-Za-z_~?][A-Za-z0-9_@$?~:<>\.-]*$")
_FUNCTION_SELECTOR_WITH_ADDRESS_RE = re.compile(
    r"^\s*(?P<name>.+?)\s*@\s*(?P<address>(?:0x)?[0-9A-Fa-f]+)\s*$"
)


def _normalize_worker_subagent_profile(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"default", "single_generalist"}:
        return normalized
    return "default"


def _normalize_worker_persona_profile(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in WORKER_PERSONA_PROFILES:
        return normalized
    return "default"


def _worker_persona_overlay(stage_name: str) -> str:
    if str(stage_name or "").split(".", 1)[0] != "workers":
        return ""
    profile_name = _normalize_worker_persona_profile(DEEP_WORKER_PERSONA_PROFILE)
    if profile_name == "default":
        return ""
    entry = WORKER_PERSONA_PROFILES.get(profile_name) or {}
    rules = [
        str(rule).strip()
        for rule in (entry.get("specialization") or [])
        if str(rule).strip()
    ]
    if not rules:
        return ""
    return (
        f"\n\nWorker persona overlay (`{profile_name}`):\n"
        + "\n".join(f"- {rule}" for rule in rules)
        + "\n"
    )


def _resolve_model_id(*candidates: Optional[str]) -> str:
    forced = str(DEEP_FORCE_MODEL_ID or "").strip()
    if forced:
        return forced
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text:
            return text
    return str(OPENAI_MODEL_ID or "").strip()


def _apply_worker_subagent_profile(architecture: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    profile = _normalize_worker_subagent_profile(DEEP_WORKER_SUBAGENT_PROFILE)
    selected = list(architecture or [])
    if profile == "single_generalist" and selected:
        return [("static_generalist", 1)]
    return selected


def load_mcp_servers(path: str) -> List[MCPServerStdio]:
    """
    Expects:
      {
        "ghidramcp": {"transport":"stdio","command":"python","args":["bridge.py","--transport","stdio"]},
        ...
      }
    """
    p = Path(path).expanduser().resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("servers.json must be an object: {name: {transport, command, args, ...}, ...}")

    servers: List[MCPServerStdio] = []
    for name, cfg in raw.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"{name}: config must be an object")

        transport = cfg.get("transport")
        if transport != "stdio":
            raise ValueError(f"{name}: this client expects transport='stdio' (got {transport!r})")

        command = cfg.get("command")
        args = cfg.get("args")

        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"{name}: stdio requires 'command' (string)")
        if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
            raise ValueError(f"{name}: stdio requires 'args' (list[str])")

        # Normalize python -> current interpreter
        if command.lower() in {"python", "python3"}:
            command = sys.executable

        # Resolve relative .py script paths relative to the servers.json directory
        if args and args[0].endswith(".py"):
            script_path = (p.parent / args[0]).expanduser().resolve()
            args = [str(script_path), *args[1:]]

        server = MCPServerStdio(
            command,
            args=args,
            timeout=30,
            id=name,
            process_tool_call=_make_cached_tool_call_processor(name),
        )
        servers.append(server)

    return servers


def partition_toolsets(toolsets: List[MCPServerStdio]) -> Tuple[List[MCPServerStdio], List[MCPServerStdio]]:
    """
    Heuristic split:
    - static: ghidra/strings/floss/hashdb/capa/binwalk/upx/yara (if static)
    - dynamic: vm/procmon/wireshark/sandbox/run/execute
    """
    static_tools: List[MCPServerStdio] = []
    dynamic_tools: List[MCPServerStdio] = []

    for s in toolsets:
        sid = (s.id or "").lower()
        if any(k in sid for k in ["ghidra", "string", "floss", "hashdb", "capa", "binwalk", "upx", "yara", "modelgateway", "altmodel", "inference", "artifact"]):
            static_tools.append(s)
        elif any(k in sid for k in ["vm", "procmon", "wireshark", "sandbox", "run", "exec"]):
            dynamic_tools.append(s)
        else:
            # Default unknown tools to static first (safer for your current setup)
            static_tools.append(s)

    return static_tools, dynamic_tools


def _sandbox_tool_ids(toolsets: List[MCPServerStdio]) -> List[str]:
    out: List[str] = []
    for tool in toolsets:
        sid = (tool.id or "").lower()
        if any(marker in sid for marker in ("vm", "sandbox", "snapshot", "isolat")):
            out.append(tool.id or "")
    return out


def _server_allows_result_cache(server_id: str) -> bool:
    sid = (server_id or "").lower()
    return bool(sid) and any(marker in sid for marker in TOOL_RESULT_CACHE_SERVER_MARKERS)


def _server_requires_serial_calls(server_id: str) -> bool:
    sid = (server_id or "").lower()
    return bool(sid) and any(marker in sid for marker in SERIAL_MCP_SERVER_MARKERS)


def _normalize_tool_args_for_execution(server_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(tool_args or {})
    sid = (server_id or "").lower()
    normalized_tool_name = str(tool_name or "").strip()

    if "ghidra" in sid:
        if normalized_tool_name in {"decompile_function", "get_function_xrefs"}:
            raw_name = str(normalized.get("name") or "").strip()
            match = _FUNCTION_SELECTOR_WITH_ADDRESS_RE.match(raw_name)
            if match and _looks_like_function_name(match.group("name")):
                normalized["name"] = match.group("name").strip()
        elif normalized_tool_name == "search_functions_by_name":
            raw_query = str(normalized.get("query") or "").strip()
            match = _FUNCTION_SELECTOR_WITH_ADDRESS_RE.match(raw_query)
            if match and _looks_like_function_name(match.group("name")):
                normalized["query"] = match.group("name").strip()

    return normalized


def _tool_call_allows_result_cache(server_id: str, tool_name: str) -> bool:
    normalized_tool_name = str(tool_name or "").strip()
    if not _server_allows_result_cache(server_id):
        return False
    if "ghidra" in str(server_id or "").lower() and normalized_tool_name in _GHIDRA_MUTATING_TOOL_NAMES:
        return False
    return True


def _tool_result_cache_key(server_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
    payload = {
        "server_id": server_id,
        "tool_name": tool_name,
        "tool_args": _json_safe(tool_args),
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


def _prune_tool_result_cache(state: Dict[str, Any]) -> None:
    cache = state.setdefault("tool_result_cache", {})
    while len(cache) > MAX_TOOL_RESULT_CACHE_ENTRIES:
        oldest_key = next(iter(cache), None)
        if oldest_key is None:
            break
        cache.pop(oldest_key, None)


def _is_cacheable_tool_result(result: Any) -> bool:
    if result is None:
        return False

    if isinstance(result, str):
        stripped = result.strip()
        if not stripped:
            return False
        if stripped.lower().startswith("error:"):
            return False
        return True

    if isinstance(result, dict):
        error_value = result.get("error")
        if error_value:
            return False
        return True

    if isinstance(result, list):
        return True

    return True


def _append_tool_cache_note(
    state: Dict[str, Any],
    stage_name: str,
    kind: str,
    server_id: str,
    tool_name: str,
    tool_args: Dict[str, Any],
) -> None:
    _append_tool_log_entries(
        state,
        stage_name,
        [
            {
                "stage": stage_name,
                "kind": kind,
                "server_id": server_id,
                "tool_name": tool_name,
                "args": _json_safe(tool_args),
                "event_at": datetime.now().isoformat(timespec="seconds"),
            }
        ],
    )


def _make_cached_tool_call_processor(server_id: str):
    requires_serial_calls = _server_requires_serial_calls(server_id)

    async def _processor(ctx: Any, direct_call: Any, tool_name: str, tool_args: Dict[str, Any]) -> Any:
        normalized_tool_name = str(tool_name or "").strip()
        normalized_tool_args = _normalize_tool_args_for_execution(server_id, normalized_tool_name, tool_args)
        cacheable = _tool_call_allows_result_cache(server_id, normalized_tool_name)
        if (
            "ghidra" in str(server_id or "").lower()
            and normalized_tool_name in _GHIDRA_MUTATING_TOOL_NAMES
            and not _ALLOW_GHIDRA_MUTATIONS.get()
        ):
            state = _ACTIVE_PIPELINE_STATE.get()
            if state is not None:
                append_status(state, f"Blocked direct Ghidra mutation tool during agent run: {normalized_tool_name}")
            return (
                "Error: Direct Ghidra mutation tools are blocked during agent execution. "
                "Emit a structured Ghidra change proposal instead and wait for user approval."
            )

        async def _direct_call_once() -> Any:
            if not requires_serial_calls:
                return await direct_call(normalized_tool_name, normalized_tool_args)
            lock = _SERIAL_MCP_CALL_LOCKS.setdefault(server_id, Lock())
            await asyncio.to_thread(lock.acquire)
            try:
                return await direct_call(normalized_tool_name, normalized_tool_args)
            finally:
                lock.release()

        if not cacheable:
            return await _direct_call_once()

        state = _ACTIVE_PIPELINE_STATE.get()
        stage_name = _ACTIVE_PIPELINE_STAGE.get() or "pipeline"
        if state is None:
            return await _direct_call_once()

        cache = state.setdefault("tool_result_cache", {})
        cache_key = _tool_result_cache_key(server_id, normalized_tool_name, normalized_tool_args)
        cached = cache.get(cache_key)
        if cached and cached.get("ok"):
            cached["hit_count"] = int(cached.get("hit_count", 0)) + 1
            _append_tool_cache_note(
                state,
                stage_name,
                "tool_cache_hit",
                server_id,
                normalized_tool_name,
                normalized_tool_args,
            )
            return cached.get("result")

        current_loop = asyncio.get_running_loop()
        owner = False
        task: asyncio.Task[Any]
        with _TOOL_RESULT_CACHE_INFLIGHT_LOCK:
            inflight_record = _TOOL_RESULT_CACHE_INFLIGHT.get(cache_key)
            if inflight_record is None:
                task = asyncio.create_task(_direct_call_once())
                _TOOL_RESULT_CACHE_INFLIGHT[cache_key] = (task, current_loop)
                owner = True
            else:
                task, owner_loop = inflight_record
                if owner_loop is current_loop:
                    owner = False
                else:
                    task = asyncio.create_task(_direct_call_once())
                    _TOOL_RESULT_CACHE_INFLIGHT[cache_key] = (task, current_loop)
                    owner = True

        if not owner:
            _append_tool_cache_note(
                state,
                stage_name,
                "tool_cache_wait",
                server_id,
                normalized_tool_name,
                normalized_tool_args,
            )
            return await task

        try:
            result = await task
        except Exception:
            raise
        finally:
            with _TOOL_RESULT_CACHE_INFLIGHT_LOCK:
                inflight_record = _TOOL_RESULT_CACHE_INFLIGHT.get(cache_key)
                if inflight_record is not None and inflight_record[0] is task:
                    _TOOL_RESULT_CACHE_INFLIGHT.pop(cache_key, None)

        if _is_cacheable_tool_result(result):
            cache[cache_key] = {
                "ok": True,
                "server_id": server_id,
                "tool_name": normalized_tool_name,
                "args": _json_safe(normalized_tool_args),
                "result": result,
                "cached_at": datetime.now().isoformat(timespec="seconds"),
                "hit_count": 0,
            }
            _prune_tool_result_cache(state)
            _append_tool_cache_note(
                state,
                stage_name,
                "tool_cache_store",
                server_id,
                normalized_tool_name,
                normalized_tool_args,
            )
        else:
            _append_tool_cache_note(
                state,
                stage_name,
                "tool_cache_skip",
                server_id,
                normalized_tool_name,
                normalized_tool_args,
            )
        return result

    return _processor


def _clone_mcp_server(server: MCPServerStdio) -> MCPServerStdio:
    return MCPServerStdio(
        server.command,
        args=list(server.args),
        env=dict(server.env) if server.env else None,
        cwd=server.cwd,
        tool_prefix=server.tool_prefix,
        log_level=server.log_level,
        log_handler=server.log_handler,
        timeout=server.timeout,
        read_timeout=server.read_timeout,
        process_tool_call=_make_cached_tool_call_processor(server.id or ""),
        allow_sampling=server.allow_sampling,
        sampling_model=server.sampling_model,
        max_retries=server.max_retries,
        elicitation_callback=server.elicitation_callback,
        cache_tools=server.cache_tools,
        cache_resources=server.cache_resources,
        id=server.id,
        client_info=server.client_info,
    )

def _toolsets_for_domain(
    tool_domain: str,
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
) -> List[MCPServerStdio]:
    # Tutorial 3.6 in extension_tutorial.md: if a new role introduces a new
    # `tool_domain`, add the mapping here before referencing that domain from
    # `agent_archetype_specs.json`.
    if tool_domain == "none":
        return []
    if tool_domain == "preflight":
        preferred = [
            tool
            for tool in static_tools
            if any(marker in (tool.id or "").lower() for marker in ("ghidra", "string", "hashdb", "upx"))
        ]
        return preferred or static_tools
    if tool_domain == "static":
        return static_tools
    if tool_domain == "dynamic":
        return dynamic_tools
    if tool_domain == "all":
        ordered = list(static_tools) + list(dynamic_tools)
        deduped: List[MCPServerStdio] = []
        seen: set[str] = set()
        for tool in ordered:
            key = tool.id or repr(tool)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(tool)
        return deduped
    raise RuntimeError(f"Unknown tool_domain={tool_domain!r}")


def _string_or_empty(value: Any) -> str:
    return str(value or "").strip()


def _normalize_ghidra_target_kind(value: Any) -> str:
    raw = _string_or_empty(value).lower().replace("-", "_").replace(" ", "_")
    mapping = {
        "func": "function",
        "function": "function",
        "procedure": "function",
        "method": "function",
        "prototype": "function",
        "local": "variable",
        "localvar": "variable",
        "local_variable": "variable",
        "stack_variable": "variable",
        "var": "variable",
        "variable": "variable",
        "parameter": "variable",
        "param": "variable",
        "type": "variable",
        "data": "data",
        "global": "data",
        "global_data": "data",
        "label": "data",
        "string": "data",
        "comment": "decompiler_comment",
        "decompiler_comment": "decompiler_comment",
        "disassembly_comment": "disassembly_comment",
        "struct": "struct",
        "struct_definition": "struct",
        "enum": "enum",
    }
    return mapping.get(raw, raw)


def _looks_like_function_name(value: str) -> bool:
    candidate = _string_or_empty(value)
    if not candidate:
        return False
    return bool(_FUNCTION_NAME_LIKE_RE.match(candidate))


def normalize_ghidra_change_proposal(proposal: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(proposal or {})
    raw_action = _string_or_empty(
        normalized.get("action")
        or normalized.get("operation")
        or normalized.get("change_type")
        or normalized.get("kind")
    ).lower().replace("-", "_").replace(" ", "_")
    target_kind = _normalize_ghidra_target_kind(
        normalized.get("target_kind")
        or normalized.get("target")
        or normalized.get("entity_kind")
        or normalized.get("subject")
    )

    function_address = _string_or_empty(
        normalized.get("function_address")
        or normalized.get("target_address")
        or normalized.get("address")
    )
    function_name = _string_or_empty(
        normalized.get("function_name")
        or normalized.get("parent_function_name")
        or normalized.get("function")
    )
    current_name = _string_or_empty(normalized.get("current_name") or normalized.get("old_name") or normalized.get("current"))
    proposed_name = _string_or_empty(normalized.get("proposed_name") or normalized.get("new_name") or normalized.get("proposed"))
    variable_name = _string_or_empty(normalized.get("variable_name") or normalized.get("local_name") or normalized.get("var_name"))
    current_type = _string_or_empty(normalized.get("current_type") or normalized.get("old_type"))
    proposed_type = _string_or_empty(normalized.get("proposed_type") or normalized.get("new_type"))
    prototype = _string_or_empty(normalized.get("prototype") or normalized.get("proposed_prototype"))
    comment = str(normalized.get("comment") or normalized.get("proposed_comment") or "").strip()

    if not target_kind or target_kind == "unknown":
        if prototype or function_address or (function_name and not variable_name):
            target_kind = "function"
        elif proposed_type and (function_address or function_name):
            target_kind = "variable"
        elif variable_name:
            target_kind = "variable"
        elif function_address and proposed_name:
            target_kind = "function"
        elif current_name and proposed_name and _looks_like_function_name(current_name):
            target_kind = "function"
        elif comment and function_address:
            target_kind = "decompiler_comment"
        elif proposed_name and normalized.get("address"):
            target_kind = "data"

    if not function_name and target_kind == "function" and _looks_like_function_name(current_name):
        function_name = current_name
    if not current_name and target_kind == "function":
        current_name = function_name
    if not variable_name and target_kind == "variable":
        variable_name = current_name
    if not current_name and target_kind == "variable":
        current_name = variable_name

    action_aliases = {
        "set_prototype": "set_function_prototype",
        "update_prototype": "set_function_prototype",
        "change_prototype": "set_function_prototype",
        "prototype": "set_function_prototype",
        "set_type": "set_local_variable_type",
        "update_type": "set_local_variable_type",
        "change_type": "set_local_variable_type",
        "retype": "set_local_variable_type",
        "retype_variable": "set_local_variable_type",
        "set_comment": "set_decompiler_comment",
        "add_comment": "set_decompiler_comment",
        "annotate": "set_decompiler_comment",
        "comment": "set_decompiler_comment",
        "decompiler_comment": "set_decompiler_comment",
        "disassembly_comment": "set_disassembly_comment",
        "rename_data_label": "rename_data",
        "create_struct": "create_struct_definition",
        "struct_definition": "suggest_struct_definition",
        "suggest_struct": "suggest_struct_definition",
        "enum_definition": "suggest_enum_definition",
    }
    if raw_action in action_aliases:
        raw_action = action_aliases[raw_action]

    if raw_action in {"", "unknown", "rename", "rename_symbol", "rename_name", "rename_identifier"}:
        if proposed_name:
            if target_kind == "function" and (function_address or current_name or function_name):
                raw_action = "rename_function_by_address" if function_address else "rename_function"
            elif target_kind == "variable" and (variable_name or current_name) and (function_name or function_address):
                raw_action = "rename_variable"
            elif target_kind == "data" and _string_or_empty(normalized.get("address")):
                raw_action = "rename_data"
        elif prototype and function_address:
            raw_action = "set_function_prototype"
        elif proposed_type and function_address and (variable_name or current_name):
            raw_action = "set_local_variable_type"
        elif comment and _string_or_empty(normalized.get("address") or function_address):
            raw_action = "set_disassembly_comment" if target_kind == "disassembly_comment" else "set_decompiler_comment"

    normalized["action"] = raw_action
    normalized["target_kind"] = target_kind
    normalized["function_address"] = function_address
    normalized["function_name"] = function_name
    normalized["current_name"] = current_name
    normalized["proposed_name"] = proposed_name
    normalized["variable_name"] = variable_name
    normalized["current_type"] = current_type
    normalized["proposed_type"] = proposed_type
    normalized["prototype"] = prototype
    normalized["comment"] = comment
    normalized["address"] = _string_or_empty(normalized.get("address") or function_address)
    return normalized


def _coerce_direct_tool_result_text(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result.strip()
    if isinstance(result, list):
        return "\n".join(str(item) for item in result).strip()
    if isinstance(result, dict):
        try:
            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception:
            return str(result)
    return str(result).strip()


def prepare_ghidra_change_operation(proposal: Dict[str, Any]) -> Dict[str, Any]:
    proposal = normalize_ghidra_change_proposal(proposal)
    action = _string_or_empty(proposal.get("action")).lower()
    target_kind = _string_or_empty(proposal.get("target_kind")).lower()
    function_address = _string_or_empty(proposal.get("function_address") or proposal.get("address"))
    function_name = _string_or_empty(proposal.get("function_name") or proposal.get("parent_function_name"))
    current_name = _string_or_empty(proposal.get("current_name") or proposal.get("old_name"))
    proposed_name = _string_or_empty(proposal.get("proposed_name") or proposal.get("new_name"))
    variable_name = _string_or_empty(proposal.get("variable_name") or current_name)
    proposed_type = _string_or_empty(proposal.get("proposed_type") or proposal.get("new_type"))
    prototype = _string_or_empty(proposal.get("prototype") or proposal.get("proposed_prototype"))
    comment = _string_or_empty(proposal.get("comment") or proposal.get("proposed_comment"))
    address = _string_or_empty(proposal.get("address") or function_address)

    unsupported = {
        "suggest_struct_definition": "Struct-definition suggestions are not yet auto-applied through the current Ghidra MCP surface.",
        "create_struct_definition": "Creating new struct data types is not yet wired for host-side auto-apply.",
        "suggest_enum_definition": "Enum-definition suggestions are proposal-only right now.",
        "patch_bytes": "Arbitrary binary patching is not yet auto-applied through the current approval queue.",
    }
    if action in unsupported:
        return {
            "can_apply": False,
            "summary": _string_or_empty(proposal.get("summary") or action or "proposal"),
            "reason": unsupported[action],
            "tool_name": "",
            "tool_args": {},
        }

    if action in {"rename_function", "rename_function_by_address"}:
        if function_address and proposed_name:
            return {
                "can_apply": True,
                "summary": f"Rename function {function_address} -> {proposed_name}",
                "reason": "",
                "tool_name": "rename_function_by_address",
                "tool_args": {"function_address": function_address, "new_name": proposed_name},
            }
        if current_name and proposed_name:
            return {
                "can_apply": True,
                "summary": f"Rename function {current_name} -> {proposed_name}",
                "reason": "",
                "tool_name": "rename_function",
                "tool_args": {"old_name": current_name, "new_name": proposed_name},
            }
        return {
            "can_apply": False,
            "summary": "Rename function proposal",
            "reason": "Missing function address or current function name, or missing proposed name.",
            "tool_name": "",
            "tool_args": {},
        }

    if action == "rename_data":
        if address and proposed_name:
            return {
                "can_apply": True,
                "summary": f"Rename data {address} -> {proposed_name}",
                "reason": "",
                "tool_name": "rename_data",
                "tool_args": {"address": address, "new_name": proposed_name},
            }
        return {
            "can_apply": False,
            "summary": "Rename data proposal",
            "reason": "Missing target address or proposed data name.",
            "tool_name": "",
            "tool_args": {},
        }

    if action == "rename_variable":
        if function_name and variable_name and proposed_name:
            return {
                "can_apply": True,
                "summary": f"Rename variable {variable_name} -> {proposed_name} in {function_name}",
                "reason": "",
                "tool_name": "rename_variable",
                "tool_args": {
                    "function_name": function_name,
                    "old_name": variable_name,
                    "new_name": proposed_name,
                },
            }
        return {
            "can_apply": False,
            "summary": "Rename variable proposal",
            "reason": "Missing function name, current variable name, or proposed variable name.",
            "tool_name": "",
            "tool_args": {},
        }

    if action == "set_function_prototype":
        if function_address and prototype:
            return {
                "can_apply": True,
                "summary": f"Set prototype for {function_address}",
                "reason": "",
                "tool_name": "set_function_prototype",
                "tool_args": {"function_address": function_address, "prototype": prototype},
            }
        return {
            "can_apply": False,
            "summary": "Set function prototype proposal",
            "reason": "Missing function address or proposed prototype.",
            "tool_name": "",
            "tool_args": {},
        }

    if action == "set_local_variable_type":
        if function_address and variable_name and proposed_type:
            return {
                "can_apply": True,
                "summary": f"Set local variable type for {variable_name} in {function_address}",
                "reason": "",
                "tool_name": "set_local_variable_type",
                "tool_args": {
                    "function_address": function_address,
                    "variable_name": variable_name,
                    "new_type": proposed_type,
                },
            }
        return {
            "can_apply": False,
            "summary": "Set local variable type proposal",
            "reason": "Missing function address, variable name, or proposed type.",
            "tool_name": "",
            "tool_args": {},
        }

    if action == "set_decompiler_comment":
        if address and comment:
            return {
                "can_apply": True,
                "summary": f"Set decompiler comment at {address}",
                "reason": "",
                "tool_name": "set_decompiler_comment",
                "tool_args": {"address": address, "comment": comment},
            }
        return {
            "can_apply": False,
            "summary": "Set decompiler comment proposal",
            "reason": "Missing target address or comment text.",
            "tool_name": "",
            "tool_args": {},
        }

    if action == "set_disassembly_comment":
        if address and comment:
            return {
                "can_apply": True,
                "summary": f"Set disassembly comment at {address}",
                "reason": "",
                "tool_name": "set_disassembly_comment",
                "tool_args": {"address": address, "comment": comment},
            }
        return {
            "can_apply": False,
            "summary": "Set disassembly comment proposal",
            "reason": "Missing target address or comment text.",
            "tool_name": "",
            "tool_args": {},
        }

    return {
        "can_apply": False,
        "summary": _string_or_empty(proposal.get("summary") or action or "proposal"),
        "reason": f"Unsupported Ghidra change action: {action or 'unknown'}",
        "tool_name": "",
        "tool_args": {},
    }


def apply_ghidra_change_proposal_sync(
    proposal: Dict[str, Any],
    *,
    pipeline_name: Optional[str] = None,
    state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    prepared = prepare_ghidra_change_operation(proposal)
    if not prepared.get("can_apply"):
        return {
            "ok": False,
            "status": "proposal_only",
            "summary": prepared.get("summary") or "proposal",
            "tool_name": "",
            "tool_args": {},
            "result_text": "",
            "error": prepared.get("reason") or "Change is not auto-applicable.",
        }

    runtime = get_runtime_sync(pipeline_name=pipeline_name)
    ghidra_server = next(
        (tool for tool in runtime.static_tools if "ghidra" in (tool.id or "").lower()),
        None,
    )
    if ghidra_server is None:
        return {
            "ok": False,
            "status": "failed",
            "summary": prepared.get("summary") or "proposal",
            "tool_name": prepared.get("tool_name") or "",
            "tool_args": dict(prepared.get("tool_args") or {}),
            "result_text": "",
            "error": "No Ghidra MCP server is configured in the active runtime.",
        }

    cloned_server = _clone_mcp_server(ghidra_server)

    async def _apply() -> Any:
        return await cloned_server.direct_call_tool(
            str(prepared.get("tool_name") or ""),
            dict(prepared.get("tool_args") or {}),
        )

    try:
        mutation_token = _ALLOW_GHIDRA_MUTATIONS.set(True)
        try:
            raw_result = asyncio.run(_apply())
        finally:
            _ALLOW_GHIDRA_MUTATIONS.reset(mutation_token)
    except Exception as exc:
        if isinstance(state, dict):
            append_status(state, f"Ghidra change apply failed: {prepared.get('summary')} ({type(exc).__name__})")
        return {
            "ok": False,
            "status": "failed",
            "summary": prepared.get("summary") or "proposal",
            "tool_name": prepared.get("tool_name") or "",
            "tool_args": dict(prepared.get("tool_args") or {}),
            "result_text": "",
            "error": f"{type(exc).__name__}: {exc}",
        }

    result_text = _coerce_direct_tool_result_text(raw_result)
    if result_text.lower().startswith("error") or result_text.lower().startswith("request failed"):
        if isinstance(state, dict):
            append_status(state, f"Ghidra change apply failed: {prepared.get('summary')} (tool returned error)")
        return {
            "ok": False,
            "status": "failed",
            "summary": prepared.get("summary") or "proposal",
            "tool_name": prepared.get("tool_name") or "",
            "tool_args": dict(prepared.get("tool_args") or {}),
            "result_text": result_text,
            "error": result_text or "Tool returned an error.",
        }

    if isinstance(state, dict):
        append_status(state, f"Ghidra change applied: {prepared.get('summary')}")
    return {
        "ok": True,
        "status": "applied",
        "summary": prepared.get("summary") or "proposal",
        "tool_name": prepared.get("tool_name") or "",
        "tool_args": dict(prepared.get("tool_args") or {}),
        "result_text": result_text,
        "error": "",
    }


def build_subagent_architecture(
    stage_name: str,
    architecture: List[Tuple[str, int]],
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
    *,
    stage_model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    subagents: List[Dict[str, Any]] = []

    for archetype_name, quantity in architecture:
        if archetype_name not in AGENT_ARCHETYPE_SPECS:
            raise RuntimeError(f"Unknown deep-agent archetype: {archetype_name!r}")
        if archetype_name not in AGENT_ARCHETYPE_PROMPTS:
            raise RuntimeError(f"Missing prompt definition for deep-agent archetype: {archetype_name!r}")
        if quantity < 1:
            raise RuntimeError(f"Deep-agent archetype quantity must be >= 1 for {archetype_name!r}")

        spec = AGENT_ARCHETYPE_SPECS[archetype_name]
        resolved_model = _resolve_model_id(spec.get("model"), stage_model, OPENAI_MODEL_ID)
        toolsets = _toolsets_for_domain(spec["tool_domain"], static_tools, dynamic_tools)
        if spec["tool_domain"] != "none" and not toolsets:
            raise RuntimeError(
                f"Deep-agent architecture requested {archetype_name!r}, but no {spec['tool_domain']} MCP toolsets are configured."
            )

        for idx in range(quantity):
            instance_name = archetype_name if quantity == 1 else f"{archetype_name}_{idx + 1}"
            instructions = AGENT_ARCHETYPE_PROMPTS[archetype_name] + _worker_persona_overlay(stage_name)
            can_ask_questions = archetype_name not in {"evidence_validator", "reporting_analyst"}
            max_questions = 1 if can_ask_questions else 0
            if quantity > 1:
                instructions += (
                    "\n\nCollaboration note:\n"
                    f"- You are instance {idx + 1} of {quantity} for the `{archetype_name}` role.\n"
                    "- Work independently, surface disagreements when they matter, and avoid assuming sibling agents saw the same evidence.\n"
                )

            subagents.append(
                {
                    "name": instance_name,
                    "description": spec["description"],
                    "instructions": instructions,
                    "model": resolved_model,
                    "toolsets": toolsets,
                    "preferred_mode": spec["preferred_mode"],
                    "typical_complexity": spec["typical_complexity"],
                    "can_ask_questions": can_ask_questions,
                    "max_questions": max_questions,
                    "agent_kwargs": {
                        "event_stream_handler": make_live_tool_event_handler(stage_name, instance_name),
                    },
                }
            )

    return subagents


def expand_architecture_names(architecture: List[Tuple[str, int]]) -> List[str]:
    names: List[str] = []
    for archetype_name, quantity in architecture:
        if quantity < 1:
            continue
        if quantity == 1:
            names.append(archetype_name)
            continue
        for idx in range(quantity):
            names.append(f"{archetype_name}_{idx + 1}")
    return names

def build_stage_manager_instructions(stage_name: str, stage_kind: str, architecture: List[Tuple[str, int]]) -> str:
    if stage_kind not in PIPELINE_STAGE_MANAGER_PROMPTS:
        raise RuntimeError(f"Unknown pipeline stage kind: {stage_kind!r}")

    stage_meta = get_stage_kind_metadata(stage_kind)
    base = PIPELINE_STAGE_MANAGER_PROMPTS[stage_kind].rstrip()
    delegated_roles = ", ".join(expand_architecture_names(architecture)) or "none"
    path_handoff_lines = ""
    if not stage_meta["finalizes_report"]:
        path_handoff_lines = (
            "- If this stage discovers or confirms the real sample path, include a line exactly like:\n"
            f"  {PATH_HANDOFF_LINE_PREFIX} <exact existing path>\n"
        )
    if stage_meta["supports_parallel_assignments"]:
        delegation_mode_lines = (
            "- Independent work items may be delegated in async parallel batches when they do not share prerequisites or state.\n"
            "- Keep parallel fan-out bounded and join results before final worker-stage synthesis.\n"
        )
    else:
        delegation_mode_lines = "- Prefer normal synchronous delegation for stage work unless there is a strong reason to launch background tasks.\n"
    return (
        f"{base}\n\n"
        "Current stage configuration:\n"
        f"- stage_name: {stage_name}\n"
        f"- stage_kind: {stage_kind}\n"
        f"- delegated roles: {delegated_roles}\n"
        f"{delegation_mode_lines}"
        "- Do not use async task-management tools (`check_task`, `wait_tasks`, `list_active_tasks`, `answer_subagent`) unless you"
        " first launched a background task with `task(..., mode=\"async\")` in this same stage.\n"
        "- `answer_subagent` is only for replying to a subagent question after `check_task` shows that exact returned task ID is"
        " `WAITING_FOR_ANSWER`.\n"
        "- Numbered plan items like `1`, `2`, `3` are work-item labels, not subagent task IDs.\n"
        "- If shared context provides `validated_sample_path`, treat it as the canonical sample path and reuse it verbatim.\n"
        "- Never invent placeholder/example targets such as `/path/to/...` or `C:\\path\\to\\...`.\n"
        "- Do not surface internal workflow metadata such as `validated_sample_path` or handoff instructions in the final"
        " user-facing report.\n"
        f"{path_handoff_lines}"
        "- Follow the stage output contract exactly.\n"
    )


def build_stage_prompt(
    stage_name: str,
    stage_kind: str,
    user_text: str,
    prior_stage_outputs: Dict[str, str],
    architecture: List[Tuple[str, int]],
    shared_state: Optional[Dict[str, Any]] = None,
) -> str:
    # Tutorial 2.6 in extension_tutorial.md: only add stage-specific prompt
    # shaping here when the JSON prompt/contract are not enough. Keep any new
    # `stage_kind` logic aligned with the execution branch in `pipeline.py`.
    shared = shared_state or {}
    stage_meta = get_stage_kind_metadata(stage_kind)
    selected_pipeline_name = str(shared.get("selected_pipeline_name") or "").strip()
    deep_pipeline = shared.get("deep_pipeline") or []
    pipeline_has_validators = False
    if isinstance(deep_pipeline, list) and deep_pipeline:
        pipeline_has_validators = any(
            stage_kind_flag(str((stage or {}).get("stage_kind") or "").strip(), "runs_validation_gate")
            for stage in deep_pipeline
            if isinstance(stage, dict)
        )
    elif selected_pipeline_name:
        selected_pipeline = DEEP_AGENT_PIPELINE_PRESETS.get(selected_pipeline_name) or []
        pipeline_has_validators = any(
            stage_kind_flag(str((stage or {}).get("stage_kind") or "").strip(), "runs_validation_gate")
            for stage in selected_pipeline
            if isinstance(stage, dict)
        )
    sections = [
        f"Pipeline stage: {stage_name} ({stage_kind})",
        "Original user request:",
        user_text.strip(),
        "",
        "Current stage output contract:",
        PIPELINE_STAGE_OUTPUT_CONTRACTS[stage_kind],
    ]

    validated_sample_path = (shared.get("validated_sample_path") or "").strip()
    validated_sample_path_source = (shared.get("validated_sample_path_source") or "").strip()
    validated_sample_md5 = (shared.get("validated_sample_md5") or "").strip()
    validated_sample_sha256 = (shared.get("validated_sample_sha256") or "").strip()
    validated_sample_image_base = (shared.get("validated_sample_image_base") or "").strip()
    validated_sample_metadata_source = (shared.get("validated_sample_metadata_source") or "").strip()
    auto_triage_status = str(shared.get("auto_triage_status") or "").strip()
    auto_triage_context_summary = str(shared.get("auto_triage_context_summary") or "").strip()
    auto_triage_pre_sweep_summary = str(shared.get("auto_triage_pre_sweep_summary") or "").strip()
    auto_triage_sample_path = str(shared.get("auto_triage_sample_path") or "").strip()
    auto_triage_sample_sha256 = str(shared.get("auto_triage_sample_sha256") or "").strip()
    sections.extend(["", "Shared execution context:"])
    if validated_sample_path:
        sections.extend(
            [
                f"- validated_sample_path: {validated_sample_path}",
                f"- validated_sample_path_source: {validated_sample_path_source or 'unknown'}",
                "- Path rule: use this exact path verbatim in every tool call that requires the sample target.",
            ]
        )
        metadata_lines: List[str] = []
        if validated_sample_md5:
            metadata_lines.append(f"- validated_sample_md5: {validated_sample_md5}")
        if validated_sample_sha256:
            metadata_lines.append(f"- validated_sample_sha256: {validated_sample_sha256}")
        if validated_sample_image_base:
            metadata_lines.append(f"- validated_sample_image_base: {validated_sample_image_base}")
        if metadata_lines:
            sections.extend(metadata_lines)
            sections.append(
                f"- validated_sample_metadata_source: {validated_sample_metadata_source or validated_sample_path_source or 'unknown'}"
            )
            sections.append(
                "- Metadata trust rule: if these hashes or image-base values came from Ghidra `get_program_info` "
                "or preflight shared context, treat them as trusted canonical sample metadata for this run. Do not "
                "create a separate work item only to recompute them unless the user explicitly requested independent "
                "verification or conflicting evidence appears."
            )
    else:
        sections.append("- No validated sample path is currently available in shared context.")
        if not stage_meta["finalizes_report"]:
            sections.append(
                f"- If you discover the real sample path during this stage, emit a line exactly like "
                f"`{PATH_HANDOFF_LINE_PREFIX} <exact existing path>` near the top of your response."
            )
        else:
            sections.append("- Do not mention missing internal path metadata in the final user-facing report.")

    available_static_tools = [str(x).strip() for x in (shared.get("available_static_tools") or []) if str(x).strip()]
    available_dynamic_tools = [str(x).strip() for x in (shared.get("available_dynamic_tools") or []) if str(x).strip()]
    available_sandbox_tools = [str(x).strip() for x in (shared.get("available_sandbox_tools") or []) if str(x).strip()]
    supports_dynamic_analysis = bool(shared.get("supports_dynamic_analysis"))
    supports_sandboxed_execution = bool(shared.get("supports_sandboxed_execution"))
    allow_parent_input = bool(shared.get("allow_parent_input"))
    shell_execution_mode = _normalize_shell_execution_mode(
        shared.get("shell_execution_mode", DEFAULT_SHELL_EXECUTION_MODE)
    )
    shell_execution_label = SHELL_EXECUTION_MODE_LABELS.get(shell_execution_mode, shell_execution_mode)
    validator_review_level = _normalize_validator_review_level(
        shared.get("validator_review_level", shared.get("validator_strict_mode", "default"))
    )
    validator_review_label = VALIDATOR_REVIEW_LEVEL_LABELS.get(validator_review_level, validator_review_level)
    sections.extend(["", "Available execution capabilities:"])
    sections.append(f"- static_tools: {', '.join(available_static_tools) if available_static_tools else 'none'}")
    sections.append(f"- dynamic_tools: {', '.join(available_dynamic_tools) if available_dynamic_tools else 'none'}")
    sections.append(f"- sandbox_tools: {', '.join(available_sandbox_tools) if available_sandbox_tools else 'none'}")
    sections.append(f"- supports_dynamic_analysis: {'yes' if supports_dynamic_analysis else 'no'}")
    sections.append(f"- supports_sandboxed_execution: {'yes' if supports_sandboxed_execution else 'no'}")
    sections.append(f"- allow_parent_input: {'yes' if allow_parent_input else 'no'}")
    sections.append(f"- shell_execution_mode: {shell_execution_mode}")
    sections.append(f"- shell_execution_profile: {shell_execution_label}")
    sections.append(f"- validator_review_level: {validator_review_level}")
    sections.append(f"- validator_review_profile: {validator_review_label}")
    if allow_parent_input:
        sections.append("- Clarification rule: if a critical ambiguity remains after reading provided context, you may ask at most one concise parent question.")
    else:
        sections.append("- Clarification rule: parent input is disabled for this run; do not rely on follow-up questions.")

    same_sample_auto_triage = bool(
        auto_triage_context_summary
        and (
            (validated_sample_sha256 and auto_triage_sample_sha256 and validated_sample_sha256 == auto_triage_sample_sha256)
            or (validated_sample_path and auto_triage_sample_path and validated_sample_path == auto_triage_sample_path)
            or (not validated_sample_path and not validated_sample_sha256)
        )
    )

    if selected_pipeline_name == "preflight_direct_answer":
        sections.extend(
            [
                "",
                "Direct-answer mode:",
                "- This run is for a simple lookup question, not a full analysis handoff.",
            ]
        )
        if stage_kind == "preflight":
            sections.extend(
                [
                    "- Gather only the directly requested fact and the minimum supporting metadata needed to answer accurately.",
                    "- Do not include high-value pivots, next steps, or extra metadata unless the user explicitly asked for them.",
                ]
            )
        elif stage_kind == "reporter":
            sections.extend(
                [
                    "- Answer only the user's requested fact in 1-3 short sentences.",
                    "- Do not include section headers, preflight summaries, pivot lists, unrelated hashes, imports, strings, or next steps unless they were explicitly requested.",
                    "- If one short supporting detail helps disambiguate the answer, include only that detail.",
                ]
            )
    elif selected_pipeline_name == "auto_triage":
        sections.extend(
            [
                "",
                "Auto-triage mode:",
                "- This is an automated initial triage after Ghidra auto-analysis, not a normal open-ended chat run.",
                "- Prefer bounded synthesis over exploratory re-discovery.",
                "- Do not auto-apply Ghidra edits, do not launch dynamic analysis automatically, and do not generate validator-heavy appendices by default.",
            ]
        )
        if stage_kind == "preflight":
            sections.extend(
                [
                    "- Use the automation bootstrap metadata to confirm the canonical sample path and only the minimum extra context needed before the deterministic sweep stage.",
                    "- Do not broaden into behavior explanation or wide pivot chasing here.",
                ]
            )
        elif stage_kind == "planner":
            sections.extend(
                [
                    "- Treat the deterministic pre-sweep bundle as already collected evidence.",
                    "- Plan only the smallest follow-on work needed to synthesize or clarify program purpose, key control-flow, capabilities, obfuscation, packed-binary indicators, known-malware context, hashed-API opportunities, and naming/type opportunities from that bundle.",
                    "- If the bundle includes capa-derived analysis leads or matched capability rules, convert the strongest ones into bounded work items with explicit evidence targets instead of leaving them as background context.",
                    "- Do not create work items that merely repeat the same bootstrap sweeps unless a sweep explicitly failed or the prior result was insufficient for the user-facing triage.",
                    "- If the pre-sweep bundle suggests likely packing, unpacking opportunities, meaningful function renames, variable renames, local type improvements, or candidate struct definitions, plan those as bounded follow-on items rather than leaving them implicit.",
                ]
            )
        elif stage_kind == "workers":
            sections.extend(
                [
                    "- Use the deterministic pre-sweep bundle and automation bootstrap metadata as the primary starting point.",
                    "- Do not rerun full strings/FLOSS/capa/YARA/binwalk sweeps unless the stage context shows that one of them failed, was unavailable, or is materially insufficient.",
                    "- Treat capa-derived analysis leads as concrete hypotheses to confirm or narrow in code, not as mere labels to repeat back.",
                    "- Explicitly assess whether the sample appears packed, whether any unpacked output from the deterministic stage materially changes interpretation, whether the sample seems previously encountered from the available hash/intel context, and whether hashed APIs or encoded strings deserve follow-up.",
                    "- If you identify useful rename/type suggestions, candidate struct declarations, function names, or variable names, keep them evidence-backed and proposal-first.",
                    "- When the evidence is strong enough to justify analyst review, emit those naming/type/struct improvements as approval-queue proposals rather than burying them in prose.",
                    "- If you emit a YARA proposal, anchor it to the distinct combination of behaviors, strings, constants, imports, or decode logic confirmed during analysis rather than generic PE/CRT/startup patterns.",
                ]
            )
        elif stage_kind == "reporter":
            sections.extend(
                [
                    "- Produce an initial triage artifact that can be reused by later interactive queries.",
                    "- Keep the report analyst-facing, concise, and forward-looking about the highest-value next pivots.",
                    "- If the run yielded strong, bounded rename/type/struct suggestions, finalize them into approval-ready Ghidra proposals instead of dropping them.",
                    "- If the run yielded a high-signal detection idea with stable strings/imports/behavioral pivots, emit a concise YARA rule proposal block so the host can write it through yaraMCP.",
                    "- Do not propose a YARA rule that mainly keys on generic starter code, DOS stub text, CRT/runtime scaffolding, or other broad compiler boilerplate.",
                ]
            )
        if auto_triage_pre_sweep_summary:
            sections.extend(["", "Deterministic pre-sweep bundle:", auto_triage_pre_sweep_summary])
    elif same_sample_auto_triage:
        sections.extend(
            [
                "",
                "Reusable prior auto-triage context:",
                auto_triage_context_summary,
                "- Reuse this earlier automated triage and its deterministic sweep outputs when relevant.",
                "- Do not rerun the same bootstrap sweeps unless the sample changed, the prior auto-triage failed, or the user explicitly asks for a rerun.",
            ]
        )
        if auto_triage_status and auto_triage_status != "succeeded":
            sections.append(f"- Prior auto-triage status: {auto_triage_status}")
    if shell_execution_mode == "none":
        sections.append("- Shell rule: do not call `execute`. Shell command execution is disabled for this run.")
    elif shell_execution_mode == "ask":
        sections.append("- Shell rule: `execute` is available only with explicit user approval per command. Keep commands minimal, local, and explainable.")
    else:
        sections.append("- Shell rule: `execute` is enabled. Use it sparingly for bounded local verification only.")
    sections.append(
        "- Safety rule: shell execution access does not authorize detonating or recklessly running a potentially malicious sample outside approved sandboxing controls."
    )
    if stage_meta["supports_parallel_assignments"]:
        if pipeline_has_validators:
            if validator_review_level == "easy":
                sections.append("- Validator mode rule: easy mode is enabled. Assume reviewers mainly care that the output is relevant, understandable, and technically substantial-sounding; prioritize clear high-level relevance over exhaustive artifact collection.")
                sections.append("- Easy evidence threshold: for major claims, representative artifacts are enough. Do not spend time collecting exact VA-qualified disassembly for every API call, full raw import dumps, or minor metadata fields unless the user explicitly asked for that depth or the claim would otherwise be weak.")
                sections.append("- Easy tool-output rule: do not include full raw capa/FLOSS output in the main worker bundle. Extract only the relevant matched rules, strings, offsets, and short excerpts that support the current claim.")
            elif validator_review_level == "strict":
                sections.append("- Validator mode rule: strict mode is enabled. Assume validators will expect stronger raw artifacts, exact excerpts, explicit proof for key claims, and minimal reliance on inference.")
            elif validator_review_level == "intermediate":
                sections.append("- Validator mode rule: intermediate mode is enabled. Expect methodical review with representative artifacts for major claims, but not exhaustive appendices for every minor point.")
                sections.append("- Intermediate tool-output rule: keep only the relevant capa/FLOSS excerpts in the main worker bundle; use full raw output only when a major disputed claim cannot be resolved otherwise.")
            else:
                sections.append("- Validator mode rule: default mode is enabled. Prioritize adequately answering the user request with concrete evidence without over-collecting exhaustive raw appendices unless needed.")
                sections.append("- Default evidence threshold: use representative decompiler/disassembly/import/string artifacts for the most important claims. Exact instruction-address bundles, full raw appendices, and minor forensic metadata are optional unless they are central to the disputed point.")
                sections.append("- Default tool-output rule: include only the relevant capa/FLOSS matches, strings, and short supporting excerpts in the worker output. Avoid pasting full raw tool output unless the user explicitly asked for it or a key claim cannot be checked without it.")
        else:
            sections.append("- Pipeline review rule: this pipeline has no validator stage. Focus on adequately answering the user request with representative supporting evidence, not on building a validator-oriented appendix.")
            sections.append("- No-validator evidence threshold: include the minimum concrete artifacts needed to support the key claims and make the report trustworthy. Prefer targeted excerpts over exhaustive raw bundles.")
            sections.append("- No-validator tool-output rule: keep capa/FLOSS/import/string evidence concise and relevant to the claim being made. Do not gather extra validation-only artifacts unless the user explicitly asks for them.")
    elif stage_meta["runs_validation_gate"]:
        if validator_review_level == "easy":
            sections.append("- Validator mode rule: easy mode is enabled. Review like a business manager: accept output that is relevant to the request, plausible, and communicates technical complexity clearly, without demanding deep artifact-level proof.")
            sections.append("- Easy acceptance threshold: do not reject solely because exact VA-qualified disassembly snippets, raw import-table dumps, verbatim tool formatting, or minor metadata fields are missing if representative evidence already supports the main claims and there are no major contradictions.")
            sections.append("- Easy fix-request rule: do not ask for full raw capa/FLOSS output. If a fix is needed, request only the smallest relevant excerpt or metadata needed to resolve the doubt.")
        elif validator_review_level == "strict":
            sections.append("- Validator mode rule: strict mode is enabled. Review like a seasoned professional malware analyst: require strong exact proof for key claims before signoff.")
        elif validator_review_level == "intermediate":
            sections.append("- Validator mode rule: intermediate mode is enabled. Review like a CS professor: require methodical reasoning and representative artifacts for major claims, while allowing minor non-critical gaps.")
            sections.append("- Intermediate acceptance threshold: require enough concrete excerpts to re-check the key claims, but do not demand exhaustive per-call-site disassembly or every minor metadata field when the answer is otherwise well-supported.")
            sections.append("- Intermediate fix-request rule: ask for targeted capa/FLOSS excerpts or addresses when needed, but avoid requesting full raw tool dumps unless the dispute genuinely turns on the omitted context.")
        else:
            sections.append("- Validator mode rule: default mode is enabled. Review like a technically strong CS background reader: focus on whether the user request is adequately answered with enough evidence, not exhaustive proof for every sub-claim.")
            sections.append("- Default acceptance threshold: prefer representative evidence over exhaustive appendices. Do not reject solely for missing exact addresses, verbatim formatting, or minor metadata unless those omissions materially undermine a major claim.")
            sections.append("- Default fix-request rule: prefer targeted additional excerpts over full raw capa/FLOSS output. Only request full raw tool output when a central claim cannot be evaluated from the representative excerpts already provided.")

    planned_work_items = shared.get("planned_work_items") or []
    if planned_work_items and not stage_meta["parses_planner_work_items"]:
        sections.extend(["", "Host-managed planner work items:"])
        for item in planned_work_items:
            item_id = str(item.get("id") or "")
            objective = str(item.get("objective") or "")
            roles = ", ".join(item.get("recommended_roles") or []) or "unspecified"
            targets = "; ".join(item.get("evidence_targets") or []) or "none specified"
            sections.append(f"- {item_id}: {objective}")
            sections.append(f"  recommended_roles: {roles}")
            sections.append(f"  evidence_targets: {targets}")

    validation_retry_count = int(shared.get("validation_retry_count") or 0)
    validation_max_retries = int(shared.get("validation_max_retries") or MAX_VALIDATION_REPLAN_RETRIES)
    validation_last_decision = str(shared.get("validation_last_decision") or "").strip()
    validation_replan_feedback = str(shared.get("validation_replan_feedback") or "").strip()
    if pipeline_has_validators and (validation_retry_count or validation_last_decision or validation_replan_feedback):
        sections.extend(
            [
                "",
                "Validation loop context:",
                f"- validation_retry_count: {validation_retry_count}",
                f"- validation_max_retries: {validation_max_retries}",
            ]
        )
        if validation_last_decision:
            sections.append(f"- validation_last_decision: {validation_last_decision}")
        if validation_replan_feedback and (
            stage_meta["parses_planner_work_items"]
            or stage_meta["supports_parallel_assignments"]
            or stage_meta["runs_validation_gate"]
        ):
            sections.extend(["", "Latest validator feedback to address:", validation_replan_feedback])

    stage_roles = expand_architecture_names(architecture)
    if stage_roles:
        sections.extend(["", "Configured stage roles:", ", ".join(stage_roles)])

    if stage_meta["supports_parallel_assignments"] and (
        str(shared.get("deep_architecture_name") or "").strip() == "ghidra_editing"
        or "ghidra_refactor_analyst" in stage_roles
    ):
        sections.extend(
            [
                "",
                "Ghidra approval queue contract:",
                "- If this run produces rename/type/comment/prototype suggestions for later approval, include exactly one machine-readable JSON block between "
                f"`{GHIDRA_CHANGE_PROPOSALS_START}` and `{GHIDRA_CHANGE_PROPOSALS_END}`.",
                "- The JSON payload must be an array of proposal objects.",
                "- Proposal object keys should include: `id`, `action`, `target_kind`, `summary`, `rationale`, `evidence`, and the action-specific fields needed to apply the change.",
                "- `evidence` must be a non-empty array of short concrete support points. Prefer 1-3 bullets such as function/address anchors, relevant strings, xrefs, imports/APIs, decoded constants, or short decompiler observations that justify the edit.",
                "- Supported auto-apply actions are: `rename_function`, `rename_function_by_address`, `rename_data`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`, `set_decompiler_comment`, and `set_disassembly_comment`.",
                "- Only include proposals in this machine-readable block if they map directly to one of those supported actions and contain the exact fields needed for the corresponding MCP tool call.",
                "- Do not emit a proposal with an empty `evidence` array. If the evidence is too weak to name concrete support points, keep the edit idea in prose instead of the approval queue.",
                "- Unsupported ideas such as new struct definitions, enum creation, or binary patch concepts must stay in normal prose, not in the machine-readable approval queue block.",
                "- If there are no concrete proposals for approval, emit an empty array in the machine-readable block rather than omitting the block.",
                "- Naming rule: unless a proposal is explicitly marked as applied, do not speak as though the rename already exists in Ghidra. In prose, refer to the current canonical symbol/address and optionally show the suggested alias in parentheses.",
            ]
        )
        if selected_pipeline_name == "auto_triage":
            sections.append("- Auto-triage edit rule: bounded, evidence-backed naming/type/struct proposals are allowed when they materially improve future analysis, but keep them conservative and approval-first.")

    if stage_meta["supports_parallel_assignments"] or stage_meta["finalizes_report"]:
        sections.extend(
            [
                "",
                "YARA rule proposal contract:",
                "- If this run yields a strong, specific detection idea, include exactly one machine-readable JSON block between "
                f"`{YARA_RULE_PROPOSALS_START}` and `{YARA_RULE_PROPOSALS_END}`.",
                "- The JSON payload must be an array of rule proposal objects.",
                "- Rule proposal keys should include: `id`, `summary`, `filename`, `rule_text`, and `rationale`.",
                "- Only emit rules when they are specific, evidence-backed, and likely useful. Prefer no rule over a weak or overbroad rule.",
                "- Distinct rules should key on unique combinations of decoded strings, constants, imports, structural markers, or behavior-specific pivots confirmed during analysis.",
                "- Do not emit rules that mainly match DOS stub text, generic CRT/startup scaffolding, broad PE header checks, or other compiler boilerplate.",
                "- Do not emit placeholder or pseudo-YARA syntax.",
            ]
        )

    if prior_stage_outputs:
        sections.extend(["", "Prior stage outputs:"])
        for prev_name, prev_output in prior_stage_outputs.items():
            sanitized_prev_output = _sanitize_user_facing_output(prev_output or "")
            sanitized_prev_output = _annotate_unapproved_ghidra_aliases(sanitized_prev_output, shared)
            sections.extend([f"## {prev_name}", sanitized_prev_output.strip()])

    return "\n".join(sections).strip()


# ----------------------------
# Runtime container
# ----------------------------
@dataclass
class PipelineStageRuntime:
    name: str
    stage_kind: str
    model: str
    architecture: List[Tuple[str, int]]
    subagent_names: List[str]
    agent: Agent
    deps: Any


@dataclass
class MultiAgentRuntime:
    pipeline_name: str
    worker_architecture_name: str
    worker_architecture: List[Tuple[str, int]]
    pipeline_definition: List[Dict[str, Any]]
    stages: List[PipelineStageRuntime]
    static_tool_ids: List[str]
    dynamic_tool_ids: List[str]
    sandbox_tool_ids: List[str]
    static_tools: List[MCPServerStdio]
    dynamic_tools: List[MCPServerStdio]
    skill_directories: List[str]
    deep_backend: Any


@dataclass
class RuntimeSharedAssets:
    toolsets: List[MCPServerStdio]
    static_tools: List[MCPServerStdio]
    dynamic_tools: List[MCPServerStdio]
    skill_directories: List[str]
    deep_backend: Any


_RUNTIME_SHARED_ASSETS: Optional[RuntimeSharedAssets] = None
_RUNTIME_CACHE: Dict[Tuple[str, str], MultiAgentRuntime] = {}
_ACTIVE_PIPELINE_STATE: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "active_pipeline_state",
    default=None,
)
_ACTIVE_PIPELINE_STAGE: ContextVar[Optional[str]] = ContextVar(
    "active_pipeline_stage",
    default=None,
)
_ALLOW_GHIDRA_MUTATIONS: ContextVar[bool] = ContextVar(
    "allow_ghidra_mutations",
    default=False,
)
_TOOL_RESULT_CACHE_INFLIGHT_LOCK = Lock()
_TOOL_RESULT_CACHE_INFLIGHT: Dict[str, Tuple[asyncio.Task[Any], Any]] = {}
_SERIAL_MCP_CALL_LOCKS: Dict[str, Lock] = {}
_GHIDRA_MUTATING_TOOL_NAMES = {
    "rename_function",
    "rename_function_by_address",
    "rename_data",
    "rename_variable",
    "set_function_prototype",
    "set_local_variable_type",
    "set_decompiler_comment",
    "set_disassembly_comment",
}


def _is_affirmative_response(value: str) -> bool:
    normalized = (value or "").strip().lower()
    return normalized in {
        "y",
        "yes",
        "approve",
        "approved",
        "allow",
        "allowed",
        "run",
        "proceed",
        "continue",
        "ok",
        "okay",
    }


def _request_shell_execute_approval(
    state: Optional[Dict[str, Any]],
    *,
    command: str,
    source: str,
    timeout_sec: float = 300.0,
) -> bool:
    if not isinstance(state, dict):
        return False

    response = _wait_for_parent_input_response(
        state,
        question=(
            f"Shell execution approval requested by {source}.\n\n"
            f"Command:\n{command}\n\n"
            "Type YES / APPROVE / ALLOW to run this command once, or click Decline to block it."
        ),
        options=[
            {
                "label": "Approve",
                "description": "Allow this exact shell command to run once for the current step.",
            },
            {
                "label": "Decline",
                "description": "Block this command and let the agent continue without shell execution.",
            },
        ],
        source=f"{source} shell approval",
        timeout_sec=timeout_sec,
    )
    return _is_affirmative_response(response)


class _ControlledLocalBackend:
    def __init__(self, root_dir: str | Path):
        from pydantic_ai_backends import LocalBackend

        self._root_dir = Path(root_dir).expanduser().resolve()
        self._backend = LocalBackend(root_dir=str(self._root_dir), enable_execute=True)

    def _current_mode(self) -> str:
        state = _ACTIVE_PIPELINE_STATE.get()
        if isinstance(state, dict):
            return _normalize_shell_execution_mode(state.get("shell_execution_mode", DEFAULT_SHELL_EXECUTION_MODE))
        return DEFAULT_SHELL_EXECUTION_MODE

    @property
    def id(self) -> str:
        return getattr(self._backend, "id")

    @property
    def root_dir(self) -> Path:
        return getattr(self._backend, "root_dir")

    @property
    def execute_enabled(self) -> bool:
        return self._current_mode() != "none"

    @property
    def permissions(self) -> Any:
        return getattr(self._backend, "permissions", None)

    @property
    def permission_checker(self) -> Any:
        return getattr(self._backend, "permission_checker", None)

    def execute(self, command: str, timeout: int | None = 120) -> Any:
        mode = self._current_mode()
        if mode == "none":
            raise RuntimeError("Shell execution is disabled for this backend")

        state = _ACTIVE_PIPELINE_STATE.get()
        source = _ACTIVE_PIPELINE_STAGE.get() or "pipeline"
        command_preview = _shorten(str(command or ""), max_chars=320)

        if mode == "ask":
            if isinstance(state, dict):
                append_status(state, f"Shell approval requested by {source}: {command_preview}")
            approved = _request_shell_execute_approval(
                state,
                command=str(command or ""),
                source=str(source),
            )
            if not approved:
                if isinstance(state, dict):
                    append_status(state, f"Shell execution denied for {source}: {command_preview}")
                from pydantic_ai_backends.types import ExecuteResponse

                return ExecuteResponse(output="Shell execution denied by user", exit_code=1, truncated=False)
            if isinstance(state, dict):
                append_status(state, f"Shell execution approved for {source}: {command_preview}")
        elif isinstance(state, dict):
            append_status(state, f"Shell execution started for {source}: {command_preview}")

        return self._backend.execute(command, timeout)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._backend, name)


def _build_history_processors() -> List[Any]:
    return [
        create_sliding_window_processor(
            trigger=("messages", 80),
            keep=("messages", 40),
        )
    ]


def _build_skill_directories() -> List[str]:
    skill_directories: List[str] = []
    if DEEP_ENABLE_SKILLS:
        for path in DEEP_SKILL_DIRS:
            p = _resolve_repo_relative_path(path)
            if p.exists() and p.is_dir():
                skill_directories.append(str(p))

        local_skills = (REPO_ROOT / "skills").resolve()
        if local_skills.exists() and local_skills.is_dir():
            skill_directories.append(str(local_skills))

        if DEEP_INCLUDE_BUNDLED_SKILLS:
            bundled = Path(pydantic_deep_pkg.__file__).resolve().parent / "bundled_skills"
            if bundled.exists() and bundled.is_dir():
                skill_directories.append(str(bundled))

        # Keep order stable and remove duplicates
        skill_directories = list(dict.fromkeys(skill_directories))
    return skill_directories


def _build_deep_backend() -> Any:
    deep_backend = None
    if DEEP_PERSIST_BACKEND:
        try:
            deep_root = _resolve_repo_relative_path(DEEP_BACKEND_ROOT)
            deep_backend = _ControlledLocalBackend(root_dir=deep_root)
        except Exception as e:
            print(f"[deep backend] persistent LocalBackend unavailable, using StateBackend: {e}")
            deep_backend = None
    return deep_backend


def _find_mcp_server_by_marker(
    runtime: "MultiAgentRuntime",
    marker: str,
    *,
    include_dynamic: bool = False,
) -> Optional[MCPServerStdio]:
    marker_lower = str(marker or "").strip().lower()
    toolsets = list(runtime.static_tools)
    if include_dynamic:
        toolsets.extend(runtime.dynamic_tools)
    for server in toolsets:
        if marker_lower in str(server.id or "").lower():
            return server
    return None


def _render_tool_log_entry_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(_json_safe(value), indent=2, ensure_ascii=False)
    except Exception:
        return str(value)


def _direct_mcp_tool_call_sync(
    runtime: "MultiAgentRuntime",
    state: Optional[Dict[str, Any]],
    *,
    stage_name: str,
    server_marker: str,
    tool_name: str,
    tool_args: Dict[str, Any],
    include_dynamic: bool = False,
) -> Dict[str, Any]:
    server = _find_mcp_server_by_marker(runtime, server_marker, include_dynamic=include_dynamic)
    if server is None:
        return {
            "ok": False,
            "server_id": "",
            "tool_name": tool_name,
            "result": None,
            "text": "",
            "error": f"No MCP server matching marker `{server_marker}` is configured.",
        }

    normalized_tool_name = str(tool_name or "").strip()
    normalized_tool_args = _normalize_tool_args_for_execution(server.id or "", normalized_tool_name, tool_args)
    cacheable = _tool_call_allows_result_cache(server.id or "", normalized_tool_name)
    call_id = f"presweep_{tool_name}_{int(time.time() * 1000)}"
    if isinstance(state, dict):
        _append_tool_log_entries(
            state,
            stage_name,
            [
                {
                    "stage": stage_name,
                    "kind": "tool_call",
                    "tool_name": normalized_tool_name,
                    "tool_call_id": call_id,
                    "server_id": server.id or "",
                    "args": _json_safe(normalized_tool_args),
                    "source": "deterministic_presweeps.host",
                }
            ],
        )
        if cacheable:
            cache = state.setdefault("tool_result_cache", {})
            cache_key = _tool_result_cache_key(server.id or "", normalized_tool_name, normalized_tool_args)
            cached = cache.get(cache_key)
            if cached and cached.get("ok"):
                cached["hit_count"] = int(cached.get("hit_count", 0)) + 1
                _append_tool_cache_note(
                    state,
                    stage_name,
                    "tool_cache_hit",
                    server.id or "",
                    normalized_tool_name,
                    normalized_tool_args,
                )
                _append_tool_log_entries(
                    state,
                    stage_name,
                    [
                        {
                            "stage": stage_name,
                            "kind": "tool_return",
                            "tool_name": normalized_tool_name,
                            "tool_call_id": call_id,
                            "server_id": server.id or "",
                            "content": _render_tool_log_entry_content(cached.get("result")),
                            "source": "deterministic_presweeps.host",
                            "cached": True,
                        }
                    ],
                )
                return {
                    "ok": True,
                    "server_id": server.id or "",
                    "tool_name": normalized_tool_name,
                    "result": cached.get("result"),
                    "text": _coerce_direct_tool_result_text(cached.get("result")),
                    "error": "",
                }

    cloned_server = _clone_mcp_server(server)

    async def _call() -> Any:
        return await cloned_server.direct_call_tool(normalized_tool_name, dict(normalized_tool_args or {}))

    try:
        if _server_requires_serial_calls(server.id or ""):
            lock = _SERIAL_MCP_CALL_LOCKS.setdefault(server.id or "", Lock())
            lock.acquire()
            try:
                raw_result = asyncio.run(_call())
            finally:
                lock.release()
        else:
            raw_result = asyncio.run(_call())
        text_result = _coerce_direct_tool_result_text(raw_result)
        if isinstance(state, dict):
            _append_tool_log_entries(
                state,
                stage_name,
                [
                    {
                        "stage": stage_name,
                        "kind": "tool_return",
                        "tool_name": normalized_tool_name,
                        "tool_call_id": call_id,
                        "server_id": server.id or "",
                        "content": _render_tool_log_entry_content(raw_result),
                        "source": "deterministic_presweeps.host",
                    }
                ],
            )
            if cacheable and _is_cacheable_tool_result(raw_result):
                cache = state.setdefault("tool_result_cache", {})
                cache[_tool_result_cache_key(server.id or "", normalized_tool_name, normalized_tool_args)] = {
                    "ok": True,
                    "server_id": server.id or "",
                    "tool_name": normalized_tool_name,
                    "args": _json_safe(normalized_tool_args),
                    "result": raw_result,
                    "cached_at": datetime.now().isoformat(timespec="seconds"),
                    "hit_count": 0,
                }
                _prune_tool_result_cache(state)
                _append_tool_cache_note(
                    state,
                    stage_name,
                    "tool_cache_store",
                    server.id or "",
                    normalized_tool_name,
                    normalized_tool_args,
                )
            elif cacheable:
                _append_tool_cache_note(
                    state,
                    stage_name,
                    "tool_cache_skip",
                    server.id or "",
                    normalized_tool_name,
                    normalized_tool_args,
                )
        return {
            "ok": True,
            "server_id": server.id or "",
            "tool_name": normalized_tool_name,
            "result": raw_result,
            "text": text_result,
            "error": "",
        }
    except Exception as exc:
        error_text = f"{type(exc).__name__}: {exc}"
        if isinstance(state, dict):
            _append_tool_log_entries(
                state,
                stage_name,
                [
                    {
                        "stage": stage_name,
                        "kind": "tool_return",
                        "tool_name": normalized_tool_name,
                        "tool_call_id": call_id,
                        "server_id": server.id or "",
                        "content": error_text,
                        "source": "deterministic_presweeps.host",
                    }
                ],
            )
        return {
            "ok": False,
            "server_id": server.id or "",
            "tool_name": normalized_tool_name,
            "result": None,
            "text": "",
            "error": error_text,
        }


def _parse_jsonish_tool_result(value: Any) -> Optional[Any]:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    text = _coerce_direct_tool_result_text(value)
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
        try:
            return json.loads(stripped)
        except Exception:
            return None
    return None


def _compact_text_block(text: str, *, max_lines: int = 24, max_chars: int = 4000) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    lines = [line.rstrip() for line in raw.splitlines() if line.strip()]
    compact = "\n".join(lines[:max_lines]).strip()
    if len(compact) > max_chars:
        compact = compact[: max_chars - 15].rstrip() + "\n...[truncated]..."
    return compact


def _parse_ghidra_string_lines(value: Any, *, max_items: int = 40) -> List[Dict[str, str]]:
    if isinstance(value, list):
        lines = [str(item) for item in value]
    else:
        lines = _coerce_direct_tool_result_text(value).splitlines()

    out: List[Dict[str, str]] = []
    for raw_line in lines:
        line = str(raw_line or "").strip()
        if not line or len(out) >= max_items:
            continue
        if ": " in line:
            address, _, remainder = line.partition(":")
            value_text = remainder.strip().strip("\"")
            out.append({"address": address.strip(), "value": value_text})
        else:
            out.append({"address": "", "value": line})
    return out


def _extract_hashdb_candidates_from_strings(strings_preview: List[Dict[str, str]], *, max_candidates: int = 6) -> List[str]:
    candidates: List[str] = []
    seen: set[str] = set()
    for item in strings_preview:
        value = str(item.get("value") or "")
        for match in _HASHLIKE_STRING_RE.finditer(value):
            candidate = match.group(1).lower()
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
            if len(candidates) >= max_candidates:
                return candidates
    return candidates


def _compact_capa_summary(parsed: Any) -> Dict[str, Any]:
    if not isinstance(parsed, dict):
        return {"available": False, "error": "Unable to parse capa output."}
    result = parsed.get("result") if isinstance(parsed.get("result"), dict) else {}
    rules = result.get("rules") if isinstance(result.get("rules"), list) else []
    top_rules: List[str] = []
    for rule in rules[:8]:
        if not isinstance(rule, dict):
            continue
        name = str(rule.get("name") or "").strip()
        if name:
            top_rules.append(name)
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    analysis = meta.get("analysis") if isinstance(meta.get("analysis"), dict) else {}
    return {
        "available": True,
        "total_rules": summary.get("total_rules"),
        "returned_rules": summary.get("returned_rules"),
        "top_rules": top_rules,
        "analysis": {
            "format": analysis.get("format"),
            "arch": analysis.get("arch"),
            "os": analysis.get("os"),
            "extractor": analysis.get("extractor"),
        },
    }


def _derive_capa_analysis_leads(capa_section: Dict[str, Any]) -> List[Dict[str, str]]:
    rules = [str(item).strip() for item in (capa_section.get("top_rules") or []) if str(item).strip()]
    if not rules:
        return []

    leads: List[Dict[str, str]] = []
    seen_focus: set[str] = set()
    heuristic_map = [
        (("packed", "packer", "upx", "compressed"), "packing", "Validate packer behavior, unpacking opportunities, and whether unpacked content changes interpretation."),
        (("resolve function", "runtime linking", "hash", "getprocaddress", "loadlibrary"), "api_resolution", "Trace the concrete resolver path, hashed APIs, or runtime-linked imports behind the rule match."),
        (("screenshot", "dib", "bitblt", "capture"), "screen_capture", "Confirm screenshot or display-capture behavior and recover output format and filenames."),
        (("terminate process", "openprocess", "process", "kill"), "process_manipulation", "Verify process-targeting behavior, required arguments, and the real call chain to the termination path."),
        (("encrypt", "decrypt", "decode", "xor", "base64"), "encoding_or_crypto", "Recover encoded or encrypted material and identify the decode/decrypt entry points."),
        (("registry", "service", "autorun", "startup"), "persistence", "Check for persistence-related writes, keys, or service-install flows tied to the rule."),
        (("http", "dns", "socket", "connect", "download", "upload"), "networking", "Find the concrete network setup logic, endpoints, and protocol artifacts behind the capability."),
        (("debugger", "sandbox", "vm", "anti-analysis"), "anti_analysis", "Corroborate anti-analysis logic with the controlling branches, strings, and API calls."),
        (("inject", "shellcode", "thread", "memory permission"), "code_injection", "Locate the real allocation/write/execute path and identify what payload or region is being staged."),
        (("file", "writefile", "createfile", "drop"), "file_activity", "Confirm file-system side effects, written filenames/paths, and whether the file is a payload or an output artifact."),
    ]

    for rule_name in rules[:10]:
        lower = rule_name.lower()
        matched = False
        for tokens, focus, follow_up in heuristic_map:
            if focus in seen_focus:
                continue
            if any(token in lower for token in tokens):
                leads.append({"rule": rule_name, "focus": focus, "follow_up": follow_up})
                seen_focus.add(focus)
                matched = True
                break
        if not matched and rule_name not in {lead["rule"] for lead in leads}:
            leads.append(
                {
                    "rule": rule_name,
                    "focus": "capability_follow_up",
                    "follow_up": "Use this capa match as a bounded lead and confirm the concrete implementation path in Ghidra before treating it as a core finding.",
                }
            )
        if len(leads) >= 6:
            break
    return leads


def _compact_yara_summary(parsed: Any) -> Dict[str, Any]:
    if not isinstance(parsed, dict):
        return {"available": False, "error": "Unable to parse YARA output."}
    stats = parsed.get("stats") if isinstance(parsed.get("stats"), dict) else {}
    return {
        "available": bool(parsed.get("ok")),
        "match_count": stats.get("match_count"),
        "rules": list(stats.get("rules") or [])[:10],
        "error": str(parsed.get("error") or "").strip(),
    }


def _compact_binwalk_summary(parsed: Any) -> Dict[str, Any]:
    if not isinstance(parsed, dict):
        return {"available": False, "error": "Unable to parse binwalk output."}
    stats = parsed.get("stats") if isinstance(parsed.get("stats"), dict) else {}
    signatures = parsed.get("signatures") if isinstance(parsed.get("signatures"), list) else []
    preview: List[str] = []
    for item in signatures[:8]:
        if isinstance(item, dict):
            description = str(item.get("description") or item.get("type") or "").strip()
            if description:
                preview.append(description)
        elif str(item).strip():
            preview.append(str(item).strip())
    return {
        "available": bool(parsed.get("ok")),
        "signature_count": stats.get("signature_count"),
        "signatures": preview,
        "stderr": _compact_text_block(str(parsed.get("stderr") or ""), max_lines=8, max_chars=1200),
        "error": str(parsed.get("error") or "").strip(),
    }


def _derive_packed_binary_assessment(
    *,
    binwalk_section: Dict[str, Any],
    capa_section: Dict[str, Any],
    raw_strings_section: Dict[str, Any],
    floss_section: Dict[str, Any],
    ghidra_strings_section: Dict[str, Any],
) -> Dict[str, Any]:
    indicators: List[str] = []
    likely_packer = ""

    signature_text = " ".join(str(item) for item in (binwalk_section.get("signatures") or []))
    top_rules_text = " ".join(str(item) for item in (capa_section.get("top_rules") or []))
    raw_preview = str(raw_strings_section.get("preview") or "")
    floss_preview = str(floss_section.get("preview") or "")
    ghidra_values = " ".join(
        str(item.get("value") or "")
        for item in (ghidra_strings_section.get("items") or [])
        if isinstance(item, dict)
    )
    combined = " ".join([signature_text, top_rules_text, raw_preview, floss_preview, ghidra_values]).lower()

    if "upx" in combined:
        likely_packer = "upx"
        indicators.append("UPX-related signatures or strings were observed across presweep artifacts.")
    if any(token in combined for token in ("packed", "packer", "compressed", "runtime modified", "self-extracting")):
        indicators.append("Static artifacts suggest packing or compression behavior.")
    if "section" in signature_text.lower() and "entropy" in str(binwalk_section.get("stderr") or "").lower():
        indicators.append("Binwalk entropy output is available for manual packer review.")

    packed_likely = bool(indicators)
    return {
        "available": True,
        "packed_likely": packed_likely,
        "likely_packer": likely_packer,
        "should_try_upx": packed_likely and likely_packer == "upx",
        "indicators": indicators[:8],
    }


def _default_upx_unpack_output_path(validated_sample_path: str, sample_sha256: str) -> str:
    source = Path(validated_sample_path)
    stem = source.stem or "sample"
    suffix = source.suffix or ".bin"
    digest = (sample_sha256 or "sample").strip()[:12] or "sample"
    _AUTO_TRIAGE_UPX_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return str((_AUTO_TRIAGE_UPX_OUTPUT_DIR / f"{stem}_{digest}_upx_unpacked{suffix}").resolve())


def _build_auto_triage_presweep_summary(bundle: Dict[str, Any]) -> str:
    summary_lines: List[str] = ["Deterministic pre-sweep bundle"]
    sample_path = str(bundle.get("validated_sample_path") or "").strip()
    if sample_path:
        summary_lines.append(f"- validated_sample_path: {sample_path}")
    if bundle.get("sample_sha256"):
        summary_lines.append(f"- sample_sha256: {bundle.get('sample_sha256')}")
    if bundle.get("sample_md5"):
        summary_lines.append(f"- sample_md5: {bundle.get('sample_md5')}")
    program = bundle.get("program") if isinstance(bundle.get("program"), dict) else {}
    program_bits: List[str] = []
    for label in ("name", "language", "compiler", "image_base", "entry_point"):
        value = str(program.get(label) or "").strip()
        if value:
            program_bits.append(f"{label}={value}")
    if program_bits:
        summary_lines.append(f"- program: {', '.join(program_bits)}")

    counts = bundle.get("counts") if isinstance(bundle.get("counts"), dict) else {}
    if counts:
        count_bits = [f"{k}={v}" for k, v in counts.items() if v not in ("", None)]
        if count_bits:
            summary_lines.append(f"- counts: {', '.join(count_bits)}")

    sections = list(bundle.get("section_summary") or [])
    if sections:
        summary_lines.append("- section_summary:")
        summary_lines.extend(f"  - {line}" for line in sections[:6])
    imports = list(bundle.get("import_summary") or [])
    if imports:
        summary_lines.append("- import_summary:")
        summary_lines.extend(f"  - {line}" for line in imports[:10])
    exports = list(bundle.get("export_summary") or [])
    if exports:
        summary_lines.append("- export_summary:")
        summary_lines.extend(f"  - {line}" for line in exports[:8])
    roots = list(bundle.get("root_functions") or [])
    if roots:
        summary_lines.append("- root_functions:")
        summary_lines.extend(f"  - {line}" for line in roots[:8])

    known_context = bundle.get("known_malware_context") if isinstance(bundle.get("known_malware_context"), dict) else {}
    if known_context:
        summary_lines.append(
            "- known_malware_context: "
            + str(known_context.get("summary") or known_context.get("reason") or "").strip()
        )

    strings_preview = bundle.get("ghidra_strings") if isinstance(bundle.get("ghidra_strings"), dict) else {}
    string_items = list(strings_preview.get("items") or [])
    if string_items:
        summary_lines.append("- ghidra_strings_preview:")
        for item in string_items[:8]:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value") or "").strip()
            address = str(item.get("address") or "").strip()
            if value:
                summary_lines.append(f"  - {address}: {value}" if address else f"  - {value}")

    for label in ("raw_strings", "floss", "capa", "hashdb", "entropy_packer", "packed_binary_assessment", "upx_unpack", "baseline_yara"):
        section = bundle.get(label)
        if not section:
            continue
        if isinstance(section, dict):
            if label in {"raw_strings", "floss"}:
                available = "yes" if section.get("available") else "no"
                error = str(section.get("error") or "").strip()
                preview = _compact_text_block(str(section.get("preview") or ""), max_lines=8, max_chars=800)
                summary_lines.append(f"- {label}: available={available}")
                if error:
                    summary_lines.append(f"  error: {error}")
                if preview:
                    summary_lines.append("  preview:")
                    summary_lines.extend(f"    {line}" for line in preview.splitlines())
            else:
                compact = json.dumps(_json_safe(section), ensure_ascii=False)
                summary_lines.append(f"- {label}: {compact}")
        else:
            summary_lines.append(f"- {label}: {section}")

    capa_leads = list(bundle.get("capa_analysis_leads") or [])
    if capa_leads:
        summary_lines.append("- capa_analysis_leads:")
        for item in capa_leads[:6]:
            if not isinstance(item, dict):
                continue
            rule_name = str(item.get("rule") or "").strip()
            focus = str(item.get("focus") or "").strip()
            follow_up = str(item.get("follow_up") or "").strip()
            bits = [bit for bit in [rule_name, f"focus={focus}" if focus else "", follow_up] if bit]
            if bits:
                summary_lines.append(f"  - {' | '.join(bits)}")

    return "\n".join(summary_lines).strip()


def run_deterministic_presweeps_sync(runtime: "MultiAgentRuntime", state: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    shared = state.setdefault("shared_state", {})
    payload = shared.get("automation_trigger_payload") if isinstance(shared.get("automation_trigger_payload"), dict) else {}
    stage_name = "presweeps"
    append_status(state, "Deterministic pre-sweeps started")

    program_info_payload = payload.get("program_info") if isinstance(payload.get("program_info"), dict) else {}
    program_block = program_info_payload.get("program") if isinstance(program_info_payload.get("program"), dict) else {}
    counts_block = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    validated_sample_path = str(shared.get("validated_sample_path") or payload.get("executable_path") or "").strip()
    validated_sample_md5 = str(shared.get("validated_sample_md5") or payload.get("executable_md5") or "").strip()
    validated_sample_sha256 = str(shared.get("validated_sample_sha256") or payload.get("executable_sha256") or "").strip()
    validated_sample_image_base = str(shared.get("validated_sample_image_base") or payload.get("image_base") or "").strip()

    bundle: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "validated_sample_path": validated_sample_path,
        "sample_md5": validated_sample_md5,
        "sample_sha256": validated_sample_sha256,
        "program": {
            "name": str(payload.get("program_name") or program_block.get("name") or "").strip(),
            "ghidra_project_path": str(
                payload.get("ghidra_project_path") or program_block.get("ghidraProjectPath") or ""
            ).strip(),
            "language": str(payload.get("language") or program_block.get("language") or "").strip(),
            "compiler": str(payload.get("compiler") or program_block.get("compiler") or "").strip(),
            "image_base": validated_sample_image_base or str(program_block.get("imageBase") or "").strip(),
            "entry_point": str(payload.get("entry_point") or "").strip(),
        },
        "counts": dict(counts_block) if counts_block else {},
        "section_summary": list(payload.get("section_summary") or []),
        "import_summary": list(payload.get("import_summary") or []),
        "export_summary": list(payload.get("export_summary") or []),
        "root_functions": list(payload.get("root_functions") or []),
        "auto_analysis_warnings": list(payload.get("auto_analysis_warnings") or []),
        "auto_analysis_failures": list(payload.get("auto_analysis_failures") or []),
        "known_malware_context": {
            "available": False,
            "summary": "Offline fallback only. Preserve hashes for later VirusTotal/MalwareBazaar lookup; no intel MCP server is configured in this hub.",
            "reason": "No VirusTotal or MalwareBazaar MCP tooling is currently configured.",
        },
    }

    ghidra_info = _direct_mcp_tool_call_sync(
        runtime,
        state,
        stage_name=stage_name,
        server_marker="ghidra",
        tool_name="get_program_info",
        tool_args={},
    )
    parsed_program_info = _parse_jsonish_tool_result(ghidra_info.get("result"))
    if isinstance(parsed_program_info, list) and len(parsed_program_info) == 1:
        parsed_program_info = _parse_jsonish_tool_result(parsed_program_info[0])
    if isinstance(parsed_program_info, dict):
        bundle["canonical_program_info"] = parsed_program_info
        program_from_tool = parsed_program_info.get("program") if isinstance(parsed_program_info.get("program"), dict) else {}
        counts_from_tool = parsed_program_info.get("counts") if isinstance(parsed_program_info.get("counts"), dict) else {}
        if not bundle["program"].get("name"):
            bundle["program"]["name"] = str(program_from_tool.get("name") or "").strip()
        if not bundle["program"].get("ghidra_project_path"):
            bundle["program"]["ghidra_project_path"] = str(program_from_tool.get("ghidraProjectPath") or "").strip()
        if not validated_sample_path:
            validated_sample_path = str(program_from_tool.get("executablePath") or "").strip()
            bundle["validated_sample_path"] = validated_sample_path
        if not validated_sample_md5:
            validated_sample_md5 = str(program_from_tool.get("executableMD5") or "").strip()
            bundle["sample_md5"] = validated_sample_md5
        if not validated_sample_sha256:
            validated_sample_sha256 = str(program_from_tool.get("executableSHA256") or "").strip()
            bundle["sample_sha256"] = validated_sample_sha256
        if not bundle["program"].get("language"):
            bundle["program"]["language"] = str(program_from_tool.get("language") or "").strip()
        if not bundle["program"].get("compiler"):
            bundle["program"]["compiler"] = str(program_from_tool.get("compiler") or "").strip()
        if not bundle["program"].get("image_base"):
            bundle["program"]["image_base"] = str(program_from_tool.get("imageBase") or "").strip()
        if counts_from_tool:
            merged_counts = dict(counts_from_tool)
            merged_counts.update({k: v for k, v in bundle["counts"].items() if v not in ("", None)})
            bundle["counts"] = merged_counts
    elif ghidra_info.get("error"):
        bundle["canonical_program_info_error"] = ghidra_info["error"]

    if not bundle["section_summary"]:
        segment_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="ghidra",
            tool_name="list_segments",
            tool_args={"offset": 0, "limit": 24},
        )
        segment_lines = [line for line in _coerce_direct_tool_result_text(segment_result.get("result")).splitlines() if line.strip()]
        if segment_lines:
            bundle["section_summary"] = segment_lines[:12]
    if not bundle["import_summary"]:
        import_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="ghidra",
            tool_name="list_imports",
            tool_args={"offset": 0, "limit": 40},
        )
        import_lines = [line for line in _coerce_direct_tool_result_text(import_result.get("result")).splitlines() if line.strip()]
        if import_lines:
            bundle["import_summary"] = import_lines[:20]
    if not bundle["export_summary"]:
        export_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="ghidra",
            tool_name="list_exports",
            tool_args={"offset": 0, "limit": 20},
        )
        export_lines = [line for line in _coerce_direct_tool_result_text(export_result.get("result")).splitlines() if line.strip()]
        if export_lines:
            bundle["export_summary"] = export_lines[:12]
    if not bundle["root_functions"]:
        call_graph_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="ghidra",
            tool_name="get_call_graph",
            tool_args={"maxDepth": 2, "maxNodes": 12},
        )
        parsed_graph = _parse_jsonish_tool_result(call_graph_result.get("result"))
        if isinstance(parsed_graph, list) and len(parsed_graph) == 1:
            parsed_graph = _parse_jsonish_tool_result(parsed_graph[0])
        if isinstance(parsed_graph, dict):
            meta = parsed_graph.get("meta") if isinstance(parsed_graph.get("meta"), dict) else {}
            root_addrs = [str(item).strip() for item in meta.get("roots") or [] if str(item).strip()]
            node_map = {
                str(node.get("addr") or "").strip(): str(node.get("name") or "").strip()
                for node in parsed_graph.get("nodes") or []
                if isinstance(node, dict)
            }
            bundle["root_functions"] = [
                f"{node_map.get(addr) or '<unknown>'} @ {addr}"
                for addr in root_addrs[:8]
            ]
            if not bundle["program"].get("entry_point") and root_addrs:
                bundle["program"]["entry_point"] = root_addrs[0]

    ghidra_strings_result = _direct_mcp_tool_call_sync(
        runtime,
        state,
        stage_name=stage_name,
        server_marker="ghidra",
        tool_name="list_strings",
        tool_args={"offset": 0, "limit": 120},
    )
    ghidra_strings_items = _parse_ghidra_string_lines(ghidra_strings_result.get("result"), max_items=40)
    if ghidra_strings_items:
        bundle["ghidra_strings"] = {
            "available": True,
            "count": len(ghidra_strings_items),
            "items": ghidra_strings_items,
        }
        bundle["counts"].setdefault("strings_preview", len(ghidra_strings_items))
    elif ghidra_strings_result.get("error"):
        bundle["ghidra_strings"] = {
            "available": False,
            "error": ghidra_strings_result["error"],
            "items": [],
        }

    if validated_sample_path:
        raw_strings_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="string",
            tool_name="callStrings",
            tool_args={"file_path": validated_sample_path, "min_len": 4},
        )
        raw_strings_text = _compact_text_block(raw_strings_result.get("text") or "", max_lines=20, max_chars=1800)
        bundle["raw_strings"] = {
            "available": bool(raw_strings_text) and not raw_strings_text.lower().startswith("error:"),
            "preview": raw_strings_text,
            "error": "" if raw_strings_text and not raw_strings_text.lower().startswith("error:") else raw_strings_text,
        }

        floss_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="floss",
            tool_name="runFloss",
            tool_args={"command": f'floss "{validated_sample_path}"', "timeout_sec": 180},
        )
        floss_text = _compact_text_block(floss_result.get("text") or "", max_lines=30, max_chars=2800)
        bundle["floss"] = {
            "available": bool(floss_text) and not floss_text.lower().startswith("error:"),
            "preview": floss_text,
            "error": "" if floss_text and not floss_text.lower().startswith("error:") else floss_text,
        }

        capa_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="capa",
            tool_name="runCapa",
            tool_args={
                "command": f'capa -- "{validated_sample_path}"',
                "timeout_sec": 180,
                "output_mode": "json_compact",
                "max_rules": 40,
            },
        )
        bundle["capa"] = _compact_capa_summary(_parse_jsonish_tool_result(capa_result.get("result")))
        bundle["capa_analysis_leads"] = _derive_capa_analysis_leads(
            bundle.get("capa") if isinstance(bundle.get("capa"), dict) else {}
        )

        binwalk_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="binwalk",
            tool_name="binwalkScan",
            tool_args={"file_path": validated_sample_path, "entropy": True, "timeout_sec": 180},
        )
        bundle["entropy_packer"] = _compact_binwalk_summary(binwalk_result.get("result"))

        yara_result = _direct_mcp_tool_call_sync(
            runtime,
            state,
            stage_name=stage_name,
            server_marker="yara",
            tool_name="yaraScan",
            tool_args={"target_path": validated_sample_path, "recursive": False, "show_strings": False, "timeout_sec": 180},
        )
        bundle["baseline_yara"] = _compact_yara_summary(yara_result.get("result"))

        bundle["packed_binary_assessment"] = _derive_packed_binary_assessment(
            binwalk_section=bundle.get("entropy_packer") if isinstance(bundle.get("entropy_packer"), dict) else {},
            capa_section=bundle.get("capa") if isinstance(bundle.get("capa"), dict) else {},
            raw_strings_section=bundle.get("raw_strings") if isinstance(bundle.get("raw_strings"), dict) else {},
            floss_section=bundle.get("floss") if isinstance(bundle.get("floss"), dict) else {},
            ghidra_strings_section=bundle.get("ghidra_strings") if isinstance(bundle.get("ghidra_strings"), dict) else {},
        )
        packed_assessment = bundle["packed_binary_assessment"] if isinstance(bundle.get("packed_binary_assessment"), dict) else {}
        if packed_assessment.get("should_try_upx") and _find_mcp_server_by_marker(runtime, "upx"):
            unpack_path = _default_upx_unpack_output_path(validated_sample_path, validated_sample_sha256)
            upx_result = _direct_mcp_tool_call_sync(
                runtime,
                state,
                stage_name=stage_name,
                server_marker="upx",
                tool_name="upxUnpack",
                tool_args={"file_path": validated_sample_path, "output_path": unpack_path, "force": True, "timeout_sec": 180},
            )
            parsed_upx = _parse_jsonish_tool_result(upx_result.get("result"))
            if isinstance(parsed_upx, dict):
                bundle["upx_unpack"] = _json_safe(parsed_upx)
            else:
                bundle["upx_unpack"] = {
                    "ok": False,
                    "error": str(upx_result.get("error") or "Unable to parse UPX unpack result.").strip(),
                    "output_path": unpack_path,
                }
        elif packed_assessment.get("should_try_upx"):
            bundle["upx_unpack"] = {
                "ok": False,
                "error": "UPX indicators were present, but no UPX MCP server is configured.",
            }
        else:
            bundle["upx_unpack"] = {
                "ok": False,
                "error": "No strong UPX indicators were found during deterministic presweeps.",
            }
    else:
        bundle["raw_strings"] = {
            "available": False,
            "error": "Validated sample path was unavailable for raw strings sweep.",
        }
        bundle["floss"] = {
            "available": False,
            "error": "Validated sample path was unavailable for FLOSS sweep.",
        }
        bundle["capa"] = {
            "available": False,
            "error": "Validated sample path was unavailable for capa sweep.",
        }
        bundle["capa_analysis_leads"] = []
        bundle["entropy_packer"] = {
            "available": False,
            "error": "Validated sample path was unavailable for binwalk entropy sweep.",
        }
        bundle["baseline_yara"] = {
            "available": False,
            "error": "Validated sample path was unavailable for baseline YARA sweep.",
        }
        bundle["packed_binary_assessment"] = {
            "available": False,
            "error": "Validated sample path was unavailable for packer assessment.",
        }
        bundle["upx_unpack"] = {
            "ok": False,
            "error": "Validated sample path was unavailable for UPX unpack attempt.",
        }

    hash_candidates = _extract_hashdb_candidates_from_strings(
        list((bundle.get("ghidra_strings") or {}).get("items") or [])
    )
    hashdb_section: Dict[str, Any] = {
        "available": bool(_find_mcp_server_by_marker(runtime, "hashdb")),
        "candidate_source": "ghidra_strings_hex_literals",
        "candidates": hash_candidates,
        "results": [],
    }
    if hashdb_section["available"] and hash_candidates:
        for candidate in hash_candidates[:4]:
            matched = False
            for algorithm in _AUTO_TRIAGE_HASHDB_ALGORITHMS:
                lookup_result = _direct_mcp_tool_call_sync(
                    runtime,
                    state,
                    stage_name=stage_name,
                    server_marker="hashdb",
                    tool_name="resolve_hash_in_hashdb_to_plain",
                    tool_args={"algorithm": algorithm, "hash_value": candidate},
                )
                parsed_lookup = _parse_jsonish_tool_result(lookup_result.get("result"))
                if isinstance(parsed_lookup, dict) and parsed_lookup.get("ok"):
                    hashdb_section["results"].append(
                        {
                            "candidate": candidate,
                            "algorithm": algorithm,
                            "result": _json_safe(parsed_lookup.get("result")),
                        }
                    )
                    matched = True
                    break
            if not matched:
                hashdb_section["results"].append(
                    {
                        "candidate": candidate,
                        "algorithm": "",
                        "result": "no_match",
                    }
                )
    elif not hash_candidates:
        hashdb_section["summary"] = "No bounded hash-like candidates were identified from the Ghidra string sweep."
    else:
        hashdb_section["summary"] = "HashDB MCP server is not configured."
    bundle["hashdb"] = hashdb_section

    summary_text = _build_auto_triage_presweep_summary(bundle)
    append_status(state, "Deterministic pre-sweeps finished")
    return summary_text, bundle


def get_architecture_definition_sync(architecture_name: Optional[str] = None) -> List[Tuple[str, int]]:
    selected_name = str(architecture_name or DEEP_AGENT_ARCHITECTURE_NAME).strip() or DEEP_AGENT_ARCHITECTURE_NAME
    if selected_name.lower() in {"dynamic", "auto"}:
        selected_name = DEEP_AGENT_ARCHITECTURE_FALLBACK_NAME
    if selected_name not in DEEP_AGENT_ARCHITECTURE_PRESETS:
        raise RuntimeError(
            f"Unknown architecture preset {selected_name!r}. "
            f"Available presets: {', '.join(sorted(DEEP_AGENT_ARCHITECTURE_PRESETS))}"
        )
    return _apply_worker_subagent_profile(list(DEEP_AGENT_ARCHITECTURE_PRESETS[selected_name]))


def get_pipeline_definition_sync(
    pipeline_name: Optional[str] = None,
    *,
    architecture_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    selected_name = str(pipeline_name or DEEP_AGENT_PIPELINE_NAME).strip() or DEEP_AGENT_PIPELINE_NAME
    if selected_name not in DEEP_AGENT_PIPELINE_PRESETS:
        raise RuntimeError(
            f"Unknown pipeline preset {selected_name!r}. "
            f"Available presets: {', '.join(sorted(DEEP_AGENT_PIPELINE_PRESETS))}"
        )
    worker_architecture = get_architecture_definition_sync(architecture_name)
    return resolve_pipeline_definition(DEEP_AGENT_PIPELINE_PRESETS[selected_name], worker_architecture)


def _pipeline_router_prompt(default_pipeline_name: str) -> str:
    available_lines: List[str] = []
    for name in sorted(DEEP_AGENT_PIPELINE_PRESETS):
        description = str(DEEP_AGENT_PIPELINE_DESCRIPTIONS.get(name) or "").strip()
        if description:
            available_lines.append(f"- {name}: {description}")
        else:
            available_lines.append(f"- {name}")
    available = "\n".join(available_lines)
    return (
        "Choose exactly one pipeline preset name for this malware-analysis request.\n"
        "Return only the pipeline preset name. Do not explain.\n\n"
        "Select the preset whose ideal use case best matches the user request.\n"
        "Prefer the smallest sufficient pipeline.\n"
        "Do not choose a direct-answer pipeline when the user asks for real analysis, evidence gathering, or any change to symbols, types, comments, or program structure.\n"
        "Choose `auto_triage` only for automated Ghidra-load bootstrap requests or when the user explicitly asks to rerun the automated triage bootstrap.\n"
        f"- If unsure, choose `{default_pipeline_name}`.\n\n"
        f"Available presets:\n{available}"
    )


def _build_pipeline_router_agent() -> Agent:
    global _PIPELINE_ROUTER_AGENT
    if _PIPELINE_ROUTER_AGENT is None:
        _PIPELINE_ROUTER_AGENT = Agent(
            _resolve_model_id(DEEP_AGENT_PIPELINE_ROUTER_MODEL, OPENAI_MODEL_ID),
            output_type=str,
            instructions=_pipeline_router_prompt(DEEP_AGENT_PIPELINE_NAME),
            retries=1,
        )
    return _PIPELINE_ROUTER_AGENT


def _extract_pipeline_name_from_router_output(raw_output: Any) -> str:
    text = str(raw_output or "").strip()
    if not text:
        return ""
    stripped = text.strip("` \n\r\t")
    if stripped in DEEP_AGENT_PIPELINE_PRESETS:
        return stripped
    for line in stripped.splitlines():
        candidate = line.strip().strip("`*- ").split()[0].strip("`*,.:")
        if candidate in DEEP_AGENT_PIPELINE_PRESETS:
            return candidate
    for name in sorted(DEEP_AGENT_PIPELINE_PRESETS, key=len, reverse=True):
        if name in stripped:
            return name
    return ""


def _architecture_router_prompt(default_architecture_name: str) -> str:
    available_lines: List[str] = []
    for name in sorted(DEEP_AGENT_ARCHITECTURE_PRESETS):
        description = str(DEEP_AGENT_ARCHITECTURE_DESCRIPTIONS.get(name) or "").strip()
        if description:
            available_lines.append(f"- {name}: {description}")
        else:
            available_lines.append(f"- {name}")
    available = "\n".join(available_lines)
    return (
        "Choose exactly one worker architecture preset name for this malware-analysis request.\n"
        "Return only the architecture preset name. Do not explain.\n\n"
        "Select the architecture whose ideal use case best matches the user request and selected pipeline.\n"
        "Prefer the smallest sufficient architecture.\n"
        "Choose `ghidra_editing` when the user wants rename, retype, comment, refactor, or approval-ready Ghidra edit proposals.\n"
        "Choose `code_reconstruction` when the user mainly wants source-like C/C++ understanding or reconstruction.\n"
        "Choose `ghidra_focused` when the work is mainly deep Ghidra analysis without requested edits.\n"
        f"- If unsure, choose `{default_architecture_name}`.\n\n"
        f"Available presets:\n{available}"
    )


def _build_architecture_router_agent() -> Agent:
    global _ARCHITECTURE_ROUTER_AGENT
    if _ARCHITECTURE_ROUTER_AGENT is None:
        _ARCHITECTURE_ROUTER_AGENT = Agent(
            _resolve_model_id(DEEP_AGENT_PIPELINE_ROUTER_MODEL, OPENAI_MODEL_ID),
            output_type=str,
            instructions=_architecture_router_prompt(DEEP_AGENT_ARCHITECTURE_FALLBACK_NAME),
            retries=1,
        )
    return _ARCHITECTURE_ROUTER_AGENT


def _extract_architecture_name_from_router_output(raw_output: Any) -> str:
    text = str(raw_output or "").strip()
    if not text:
        return ""
    stripped = text.strip("` \n\r\t")
    if stripped in DEEP_AGENT_ARCHITECTURE_PRESETS:
        return stripped
    for line in stripped.splitlines():
        candidate = line.strip().strip("`*- ").split()[0].strip("`*,.:")
        if candidate in DEEP_AGENT_ARCHITECTURE_PRESETS:
            return candidate
    for name in sorted(DEEP_AGENT_ARCHITECTURE_PRESETS, key=len, reverse=True):
        if name in stripped:
            return name
    return ""


def _looks_like_binary_edit_request(text: str) -> bool:
    return bool(
        re.search(
            r"\b("
            r"rename|renam(e|ing)|change (?:its |the )?name|rename to|more descriptive|"
            r"retype|retype|prototype|signature|comment|annotat(?:e|ion)|"
            r"patch|edit|modify|apply change|apply patch|approve change|"
            r"variable name|function name|type name|struct definition|enum definition"
            r")\b",
            text,
        )
    )


def is_edit_intent_query(user_text: str) -> bool:
    text = " ".join(str(user_text or "").lower().split())
    if not text:
        return False
    return _looks_like_binary_edit_request(text)


def select_pipeline_name_for_query_sync(user_text: str, state: Optional[Dict[str, Any]] = None) -> str:
    selected_pipeline_setting = str(
        ((state or {}).get("deep_agent_pipeline_name") or DEEP_AGENT_PIPELINE_NAME)
    ).strip() or DEEP_AGENT_PIPELINE_NAME
    auto_select_pipeline = selected_pipeline_setting.lower() in {"dynamic", "auto"} or bool(
        (state or {}).get("deep_agent_auto_select_pipeline", DEEP_AGENT_AUTO_SELECT_PIPELINE)
    )
    default_pipeline_name = (
        DEEP_AGENT_PIPELINE_NAME
        if selected_pipeline_setting.lower() in {"dynamic", "auto"}
        else selected_pipeline_setting
    )
    if default_pipeline_name not in DEEP_AGENT_PIPELINE_PRESETS:
        default_pipeline_name = DEEP_AGENT_PIPELINE_NAME
    if not auto_select_pipeline:
        return default_pipeline_name

    try:
        result = _build_pipeline_router_agent().run_sync(
            (
                f"User request:\n{str(user_text or '').strip()}\n\n"
                "Choose the best pipeline preset name for this request."
            )
        )
        selected = _extract_pipeline_name_from_router_output(result.output)
        if selected:
            if isinstance(state, dict):
                append_status(state, f"Auto-selected pipeline via router agent: {selected}")
            return selected
        if isinstance(state, dict):
            append_status(state, f"Pipeline router returned an invalid preset; using default {default_pipeline_name}.")
    except Exception as e:
        if isinstance(state, dict):
            append_status(state, f"Pipeline router failed ({type(e).__name__}); using default {default_pipeline_name}.")

    return default_pipeline_name


def select_architecture_name_for_query_sync(
    user_text: str,
    state: Optional[Dict[str, Any]] = None,
) -> str:
    selected_architecture_setting = str(
        ((state or {}).get("deep_agent_architecture_name") or DEEP_AGENT_ARCHITECTURE_NAME)
    ).strip() or DEEP_AGENT_ARCHITECTURE_NAME
    auto_select_architecture = selected_architecture_setting.lower() in {"dynamic", "auto"}
    default_architecture_name = (
        DEEP_AGENT_ARCHITECTURE_NAME
        if auto_select_architecture
        else selected_architecture_setting
    )
    if default_architecture_name not in DEEP_AGENT_ARCHITECTURE_PRESETS:
        default_architecture_name = DEEP_AGENT_ARCHITECTURE_NAME

    if not auto_select_architecture:
        return default_architecture_name

    selected_pipeline_name = str(
        ((state or {}).get("shared_state") or {}).get("selected_pipeline_name")
        or ((state or {}).get("selected_pipeline_name") or "")
    ).strip()

    try:
        result = _build_architecture_router_agent().run_sync(
            (
                f"User request:\n{str(user_text or '').strip()}\n\n"
                f"Selected pipeline preset:\n{selected_pipeline_name or 'unknown'}\n\n"
                "Choose the best worker architecture preset name for this request."
            )
        )
        selected = _extract_architecture_name_from_router_output(result.output)
        if selected:
            if isinstance(state, dict):
                append_status(state, f"Auto-selected architecture via router agent: {selected}")
            return selected
        if isinstance(state, dict):
            append_status(
                state,
                f"Architecture router returned an invalid preset; using default {default_architecture_name}.",
            )
    except Exception as e:
        if isinstance(state, dict):
            append_status(
                state,
                f"Architecture router failed ({type(e).__name__}); using default {default_architecture_name}.",
            )

    return default_architecture_name


def expand_architecture_slots(architecture: List[Tuple[str, int]]) -> List[Dict[str, str]]:
    slots: List[Dict[str, str]] = []
    for archetype_name, quantity in architecture:
        if quantity < 1:
            continue
        if quantity == 1:
            slots.append({"slot_name": archetype_name, "archetype_name": archetype_name})
            continue
        for idx in range(quantity):
            slots.append(
                {
                    "slot_name": f"{archetype_name}_{idx + 1}",
                    "archetype_name": archetype_name,
                }
            )
    return slots


def build_host_worker_assignment_executor(
    runtime: MultiAgentRuntime,
    *,
    stage_name: str,
    slot_name: str,
    archetype_name: str,
    stage_model: Optional[str] = None,
) -> Tuple[Agent, Any, str]:
    if archetype_name not in AGENT_ARCHETYPE_SPECS:
        raise RuntimeError(f"Unknown deep-agent archetype: {archetype_name!r}")
    if archetype_name not in AGENT_ARCHETYPE_PROMPTS:
        raise RuntimeError(f"Missing prompt definition for deep-agent archetype: {archetype_name!r}")

    spec = AGENT_ARCHETYPE_SPECS[archetype_name]
    resolved_model = _resolve_model_id(spec.get("model"), stage_model, OPENAI_MODEL_ID)
    # Reuse the runtime's shared MCP connections for host-managed workers so
    # parallel assignments do not relaunch a fresh stdio server fleet per work item.
    toolsets = list(_toolsets_for_domain(spec["tool_domain"], runtime.static_tools, runtime.dynamic_tools))
    if spec["tool_domain"] != "none" and not toolsets:
        raise RuntimeError(
            f"Host-parallel worker requested {archetype_name!r}, but no {spec['tool_domain']} MCP toolsets are configured."
        )

    instructions = (AGENT_ARCHETYPE_PROMPTS[archetype_name] + _worker_persona_overlay(stage_name)).rstrip()
    instructions += (
        "\n\nExecution note:\n"
        "- You are a host-scheduled worker executing one assigned work item.\n"
        "- Focus on the assigned work item only. Do not broaden into unrelated plan items.\n"
        "- Parallel peer workers may be running on other independent work items at the same time.\n"
        "- Reuse shared context and existing canonical sample metadata instead of re-deriving it unless conflicting evidence appears.\n"
        "- Before issuing a broad catalog call such as `list_functions`, `list_imports`, `list_strings`, or `list_data_items`, check whether the needed catalog is already present in shared context or a recent tool result.\n"
        "- Treat selectors like `function_name @ 0xADDRESS` as display hints, not canonical names. Strip the `@ address` suffix for name-based tools, or use the address with an address-based tool.\n"
        "- Once you have mapped a dispatcher and its relevant handler family well enough for the current work item, stop re-probing the same handlers unless a new evidence target requires it.\n"
        "- Return a strong evidence bundle for this one work item.\n"
    )
    if slot_name != archetype_name:
        instructions += (
            "\nCollaboration note:\n"
            f"- You are `{slot_name}` for the `{archetype_name}` role.\n"
            "- Work independently on your assigned item and do not assume peer workers saw the same evidence.\n"
        )

    memory_root = Path(DEEP_MEMORY_DIR).expanduser()
    if runtime.deep_backend is not None:
        memory_dir = str(memory_root / stage_name / slot_name)
        if memory_dir.startswith("/"):
            memory_dir = memory_dir.lstrip("/")
    else:
        if not memory_root.is_absolute():
            memory_root = REPO_ROOT / memory_root
        memory_dir = str((memory_root / stage_name / slot_name).resolve())

    agent = create_deep_agent(
        model=resolved_model,
        instructions=instructions,
        include_todo=False,
        include_filesystem=False,
        include_subagents=False,
        include_general_purpose_subagent=False,
        include_plan=False,
        include_skills=bool(runtime.skill_directories),
        skill_directories=runtime.skill_directories or None,
        include_memory=DEEP_ENABLE_MEMORY,
        memory_dir=memory_dir,
        include_history_archive=False,
        context_manager=True,
        context_manager_max_tokens=DEEP_CONTEXT_MAX_TOKENS,
        history_processors=_build_history_processors(),
        retries=DEEP_AGENT_RETRIES,
        cost_tracking=False,
        toolsets=toolsets,
        event_stream_handler=make_live_tool_event_handler(stage_name, slot_name),
    )
    deps = create_default_deps(backend=runtime.deep_backend) if runtime.deep_backend is not None else create_default_deps()
    return agent, deps, resolved_model


def build_stage_runtime(
    stage_definition: Dict[str, Any],
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
    skill_directories: List[str],
    deep_backend: Any,
) -> PipelineStageRuntime:
    # Tutorial 2.4 in extension_tutorial.md: once a stage is added to a preset,
    # this function can build its manager runtime automatically. It does not
    # define the stage semantics; Tutorial 2.5 does that in `pipeline.py`.
    stage_name = str(stage_definition["name"])
    stage_kind = str(stage_definition["stage_kind"])
    architecture = list(stage_definition.get("architecture") or [])
    stage_model = _resolve_model_id(stage_definition.get("model"), OPENAI_MODEL_ID)
    subagents = (
        build_subagent_architecture(
            stage_name,
            architecture,
            static_tools,
            dynamic_tools,
            stage_model=stage_model,
        )
        if architecture
        else []
    )
    tool_free_stage = stage_kind_flag(stage_kind, "tool_free")
    stage_skill_directories = [] if tool_free_stage else list(skill_directories)
    memory_root = Path(DEEP_MEMORY_DIR).expanduser()
    if deep_backend is not None:
        memory_dir = str(memory_root / stage_name)
        if memory_dir.startswith("/"):
            memory_dir = memory_dir.lstrip("/")
    else:
        if not memory_root.is_absolute():
            memory_root = REPO_ROOT / memory_root
        memory_dir = str((memory_root / stage_name).resolve())

    try:
        stage_agent = create_deep_agent(
            model=stage_model,
            instructions=build_stage_manager_instructions(stage_name, stage_kind, architecture),
            subagents=subagents or None,
            include_todo=True,
            include_filesystem=False,
            include_subagents=bool(subagents),
            include_general_purpose_subagent=False,
            include_plan=False,
            include_skills=bool(stage_skill_directories),
            skill_directories=stage_skill_directories or None,
            include_memory=DEEP_ENABLE_MEMORY,
            memory_dir=memory_dir,
            include_history_archive=False,
            context_manager=True,
            context_manager_max_tokens=DEEP_CONTEXT_MAX_TOKENS,
            history_processors=_build_history_processors(),
            retries=DEEP_AGENT_RETRIES,
            cost_tracking=False,
            event_stream_handler=make_live_tool_event_handler(stage_name, f"{stage_name}.manager"),
        )
        stage_deps = create_default_deps(backend=deep_backend) if deep_backend is not None else create_default_deps()
        return PipelineStageRuntime(
            name=stage_name,
            stage_kind=stage_kind,
            model=stage_model,
            architecture=architecture,
            subagent_names=expand_architecture_names(architecture),
            agent=stage_agent,
            deps=stage_deps,
        )
    except Exception as e:
        raise RuntimeError(
            f"Deep-agent initialization failed for stage {stage_name!r}: {type(e).__name__}: {e}"
        ) from e


def build_deep_runtime_components(
    pipeline_definition: List[Dict[str, Any]],
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
) -> Tuple[List[PipelineStageRuntime], List[str], Any]:
    skill_directories = _build_skill_directories()
    deep_backend = _build_deep_backend()
    stages = [
        build_stage_runtime(stage_definition, static_tools, dynamic_tools, skill_directories, deep_backend)
        for stage_definition in pipeline_definition
    ]
    return stages, skill_directories, deep_backend


def _get_runtime_shared_assets_sync() -> RuntimeSharedAssets:
    global _RUNTIME_SHARED_ASSETS
    if _RUNTIME_SHARED_ASSETS is not None:
        return _RUNTIME_SHARED_ASSETS

    toolsets = load_mcp_servers(str(MCP_SERVER_MANIFEST_PATH))
    static_tools, dynamic_tools = partition_toolsets(toolsets)
    skill_directories = _build_skill_directories()
    deep_backend = _build_deep_backend()

    print("Loaded MCP servers:", [s.id for s in toolsets])
    print("Static tools:", [s.id for s in static_tools])
    print("Dynamic tools:", [s.id for s in dynamic_tools])

    _RUNTIME_SHARED_ASSETS = RuntimeSharedAssets(
        toolsets=toolsets,
        static_tools=static_tools,
        dynamic_tools=dynamic_tools,
        skill_directories=skill_directories,
        deep_backend=deep_backend,
    )
    return _RUNTIME_SHARED_ASSETS


def get_runtime_sync(
    pipeline_name: Optional[str] = None,
    *,
    architecture_name: Optional[str] = None,
) -> MultiAgentRuntime:
    selected_pipeline_name = str(pipeline_name or DEEP_AGENT_PIPELINE_NAME).strip() or DEEP_AGENT_PIPELINE_NAME
    selected_architecture_name = (
        str(architecture_name or DEEP_AGENT_ARCHITECTURE_NAME).strip() or DEEP_AGENT_ARCHITECTURE_NAME
    )
    if selected_architecture_name.lower() in {"dynamic", "auto"}:
        selected_architecture_name = DEEP_AGENT_ARCHITECTURE_FALLBACK_NAME
    cache_key = (
        selected_pipeline_name,
        selected_architecture_name,
        _normalize_worker_subagent_profile(DEEP_WORKER_SUBAGENT_PROFILE),
        str(DEEP_FORCE_MODEL_ID or "").strip(),
    )
    cached_runtime = _RUNTIME_CACHE.get(cache_key)
    if cached_runtime is not None:
        return cached_runtime

    shared_assets = _get_runtime_shared_assets_sync()
    worker_architecture = get_architecture_definition_sync(selected_architecture_name)
    pipeline_definition = get_pipeline_definition_sync(
        selected_pipeline_name,
        architecture_name=selected_architecture_name,
    )
    stages = [
        build_stage_runtime(
            stage_definition,
            shared_assets.static_tools,
            shared_assets.dynamic_tools,
            shared_assets.skill_directories,
            shared_assets.deep_backend,
        )
        for stage_definition in pipeline_definition
    ]
    print("Deep-agent mode: required")
    print(
        "Deep config:",
        {
            "pipeline_name": selected_pipeline_name,
            "pipeline": pipeline_definition,
            "worker_architecture_name": selected_architecture_name,
            "worker_architecture": worker_architecture,
            "worker_subagents": expand_architecture_names(worker_architecture),
            "worker_subagent_profile": _normalize_worker_subagent_profile(DEEP_WORKER_SUBAGENT_PROFILE),
            "forced_model": str(DEEP_FORCE_MODEL_ID or "").strip(),
            "pipeline_stage_names": [stage.name for stage in stages],
            "memory": DEEP_ENABLE_MEMORY,
            "memory_dir": DEEP_MEMORY_DIR,
            "persist_backend": DEEP_PERSIST_BACKEND,
            "backend_root": str(_resolve_repo_relative_path(DEEP_BACKEND_ROOT)),
            "skills": DEEP_ENABLE_SKILLS,
            "skill_dirs": DEEP_SKILL_DIRS,
            "include_bundled_skills": DEEP_INCLUDE_BUNDLED_SKILLS,
            "deep_agent_retries": DEEP_AGENT_RETRIES,
        },
    )

    runtime = MultiAgentRuntime(
        pipeline_name=selected_pipeline_name,
        worker_architecture_name=selected_architecture_name,
        worker_architecture=worker_architecture,
        pipeline_definition=pipeline_definition,
        stages=stages,
        static_tool_ids=[s.id or "" for s in shared_assets.static_tools],
        dynamic_tool_ids=[s.id or "" for s in shared_assets.dynamic_tools],
        sandbox_tool_ids=_sandbox_tool_ids(shared_assets.dynamic_tools),
        static_tools=shared_assets.static_tools,
        dynamic_tools=shared_assets.dynamic_tools,
        skill_directories=shared_assets.skill_directories,
        deep_backend=shared_assets.deep_backend,
    )
    _RUNTIME_CACHE[cache_key] = runtime
    return runtime


async def _shutdown_runtime_async() -> None:
    global _RUNTIME_SHARED_ASSETS
    shared_assets = _RUNTIME_SHARED_ASSETS
    if shared_assets is None:
        return

    seen: set[int] = set()
    for server in list(shared_assets.static_tools) + list(shared_assets.dynamic_tools):
        key = id(server)
        if key in seen:
            continue
        seen.add(key)
        try:
            running_attr = getattr(server, "is_running", False)
            running = running_attr() if callable(running_attr) else bool(running_attr)
            if running:
                await server.__aexit__(None, None, None)
        except Exception as e:
            print(f"[runtime shutdown] warning: failed to close MCP server {getattr(server, 'id', 'unknown')}: {e}")

    _RUNTIME_CACHE.clear()
    _RUNTIME_SHARED_ASSETS = None


def shutdown_runtime_sync() -> None:
    try:
        asyncio.run(_shutdown_runtime_async())
    except RuntimeError as e:
        print(f"[runtime shutdown] warning: cleanup skipped ({e})")
