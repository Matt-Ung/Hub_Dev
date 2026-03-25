import asyncio
import json
import re
import sys
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from http.server import ThreadingHTTPServer
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
    DEEP_INCLUDE_BUNDLED_SKILLS,
    DEEP_MEMORY_DIR,
    DEEP_PERSIST_BACKEND,
    DEEP_SKILL_DIRS,
    DEFAULT_SHELL_EXECUTION_MODE,
    GHIDRA_CHANGE_PROPOSALS_END,
    GHIDRA_CHANGE_PROPOSALS_START,
    MAX_TOOL_RESULT_CACHE_ENTRIES,
    MAX_VALIDATION_REPLAN_RETRIES,
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
    _normalize_shell_execution_mode,
    _normalize_validator_review_level,
    _resolve_repo_relative_path,
    resolve_pipeline_definition,
)
from .shared_state import (
    _append_tool_log_entries,
    _LIVE_TOOL_LOG_STATE,
    _json_safe,
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
    - static: ghidra/strings/floss/hashdb/capa (if static)
    - dynamic: vm/procmon/wireshark/sandbox/run/execute
    """
    static_tools: List[MCPServerStdio] = []
    dynamic_tools: List[MCPServerStdio] = []

    for s in toolsets:
        sid = (s.id or "").lower()
        if any(k in sid for k in ["ghidra", "string", "floss", "hashdb", "capa"]):
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
    cacheable = _server_allows_result_cache(server_id)
    requires_serial_calls = _server_requires_serial_calls(server_id)

    async def _processor(ctx: Any, direct_call: Any, tool_name: str, tool_args: Dict[str, Any]) -> Any:
        normalized_tool_name = str(tool_name or "").strip()
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
                return await direct_call(normalized_tool_name, tool_args)
            lock = _SERIAL_MCP_CALL_LOCKS.setdefault(server_id, Lock())
            await asyncio.to_thread(lock.acquire)
            try:
                return await direct_call(normalized_tool_name, tool_args)
            finally:
                lock.release()

        if not cacheable:
            return await _direct_call_once()

        state = _ACTIVE_PIPELINE_STATE.get()
        stage_name = _ACTIVE_PIPELINE_STAGE.get() or "pipeline"
        if state is None:
            return await _direct_call_once()

        cache = state.setdefault("tool_result_cache", {})
        cache_key = _tool_result_cache_key(server_id, normalized_tool_name, tool_args)
        cached = cache.get(cache_key)
        if cached and cached.get("ok"):
            cached["hit_count"] = int(cached.get("hit_count", 0)) + 1
            _append_tool_cache_note(state, stage_name, "tool_cache_hit", server_id, normalized_tool_name, tool_args)
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
            _append_tool_cache_note(state, stage_name, "tool_cache_wait", server_id, normalized_tool_name, tool_args)
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
                "args": _json_safe(tool_args),
                "result": result,
                "cached_at": datetime.now().isoformat(timespec="seconds"),
                "hit_count": 0,
            }
            _prune_tool_result_cache(state)
            _append_tool_cache_note(state, stage_name, "tool_cache_store", server_id, normalized_tool_name, tool_args)
        else:
            _append_tool_cache_note(state, stage_name, "tool_cache_skip", server_id, normalized_tool_name, tool_args)
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
    if tool_domain == "none":
        return []
    if tool_domain == "preflight":
        preferred = [
            tool
            for tool in static_tools
            if any(marker in (tool.id or "").lower() for marker in ("ghidra", "string", "hashdb"))
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
    proposal = dict(proposal or {})
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
        resolved_model = str(spec.get("model") or stage_model or OPENAI_MODEL_ID)
        toolsets = _toolsets_for_domain(spec["tool_domain"], static_tools, dynamic_tools)
        if spec["tool_domain"] != "none" and not toolsets:
            raise RuntimeError(
                f"Deep-agent architecture requested {archetype_name!r}, but no {spec['tool_domain']} MCP toolsets are configured."
            )

        for idx in range(quantity):
            instance_name = archetype_name if quantity == 1 else f"{archetype_name}_{idx + 1}"
            instructions = AGENT_ARCHETYPE_PROMPTS[archetype_name]
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
                "- Supported auto-apply actions are: `rename_function`, `rename_function_by_address`, `rename_data`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`, `set_decompiler_comment`, and `set_disassembly_comment`.",
                "- Proposal-only actions such as new struct definitions or unsupported binary patches may still be included, but must use a distinct `action` and should not claim the change was applied.",
                "- If there are no concrete proposals for approval, emit an empty array in the machine-readable block rather than omitting the block.",
            ]
        )

    if prior_stage_outputs:
        sections.extend(["", "Prior stage outputs:"])
        for prev_name, prev_output in prior_stage_outputs.items():
            sections.extend([f"## {prev_name}", (prev_output or "").strip()])

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
_AUTOMATION_TRIGGER_SERVER: ThreadingHTTPServer | None = None
_AUTOMATION_TRIGGER_LOCK = Lock()
_AUTOMATION_TRIGGER_PENDING = False
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


def get_architecture_definition_sync(architecture_name: Optional[str] = None) -> List[Tuple[str, int]]:
    selected_name = str(architecture_name or DEEP_AGENT_ARCHITECTURE_NAME).strip() or DEEP_AGENT_ARCHITECTURE_NAME
    if selected_name.lower() in {"dynamic", "auto"}:
        selected_name = DEEP_AGENT_ARCHITECTURE_FALLBACK_NAME
    if selected_name not in DEEP_AGENT_ARCHITECTURE_PRESETS:
        raise RuntimeError(
            f"Unknown architecture preset {selected_name!r}. "
            f"Available presets: {', '.join(sorted(DEEP_AGENT_ARCHITECTURE_PRESETS))}"
        )
    return list(DEEP_AGENT_ARCHITECTURE_PRESETS[selected_name])


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
        f"- If unsure, choose `{default_pipeline_name}`.\n\n"
        f"Available presets:\n{available}"
    )


def _build_pipeline_router_agent() -> Agent:
    global _PIPELINE_ROUTER_AGENT
    if _PIPELINE_ROUTER_AGENT is None:
        _PIPELINE_ROUTER_AGENT = Agent(
            DEEP_AGENT_PIPELINE_ROUTER_MODEL,
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
            DEEP_AGENT_PIPELINE_ROUTER_MODEL,
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
) -> Tuple[Agent, Any]:
    if archetype_name not in AGENT_ARCHETYPE_SPECS:
        raise RuntimeError(f"Unknown deep-agent archetype: {archetype_name!r}")
    if archetype_name not in AGENT_ARCHETYPE_PROMPTS:
        raise RuntimeError(f"Missing prompt definition for deep-agent archetype: {archetype_name!r}")

    spec = AGENT_ARCHETYPE_SPECS[archetype_name]
    resolved_model = str(spec.get("model") or stage_model or OPENAI_MODEL_ID)
    toolsets = [
        _clone_mcp_server(tool)
        for tool in _toolsets_for_domain(spec["tool_domain"], runtime.static_tools, runtime.dynamic_tools)
    ]
    if spec["tool_domain"] != "none" and not toolsets:
        raise RuntimeError(
            f"Host-parallel worker requested {archetype_name!r}, but no {spec['tool_domain']} MCP toolsets are configured."
        )

    instructions = AGENT_ARCHETYPE_PROMPTS[archetype_name].rstrip()
    instructions += (
        "\n\nExecution note:\n"
        "- You are a host-scheduled worker executing one assigned work item.\n"
        "- Focus on the assigned work item only. Do not broaden into unrelated plan items.\n"
        "- Parallel peer workers may be running on other independent work items at the same time.\n"
        "- Reuse shared context and existing canonical sample metadata instead of re-deriving it unless conflicting evidence appears.\n"
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
    return agent, deps


def build_stage_runtime(
    stage_definition: Dict[str, Any],
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
    skill_directories: List[str],
    deep_backend: Any,
) -> PipelineStageRuntime:
    stage_name = str(stage_definition["name"])
    stage_kind = str(stage_definition["stage_kind"])
    architecture = list(stage_definition.get("architecture") or [])
    stage_model = str(stage_definition.get("model") or OPENAI_MODEL_ID)
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

    toolsets = load_mcp_servers(str(REPO_ROOT / "MCPServers" / "servers.json"))
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
    cache_key = (selected_pipeline_name, selected_architecture_name)
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
