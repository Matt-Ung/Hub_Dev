import asyncio
import json
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
    DEEP_AGENT_ARCHITECTURE_NAME,
    DEEP_AGENT_PIPELINE,
    DEEP_AGENT_PIPELINE_NAME,
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
    MAX_TOOL_RESULT_CACHE_ENTRIES,
    MAX_VALIDATION_REPLAN_RETRIES,
    OPENAI_MODEL_ID,
    PATH_HANDOFF_LINE_PREFIX,
    PIPELINE_STAGE_MANAGER_PROMPTS,
    PIPELINE_STAGE_OUTPUT_CONTRACTS,
    REPO_ROOT,
    SERIAL_MCP_SERVER_MARKERS,
    SHELL_EXECUTION_MODE_LABELS,
    TOOL_RESULT_CACHE_SERVER_MARKERS,
    VALIDATOR_REVIEW_LEVEL_LABELS,
    _normalize_shell_execution_mode,
    _normalize_validator_review_level,
    _resolve_repo_relative_path,
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
        async def _direct_call_once() -> Any:
            if not requires_serial_calls:
                return await direct_call(tool_name, tool_args)
            lock = _SERIAL_MCP_CALL_LOCKS.setdefault(server_id, Lock())
            await asyncio.to_thread(lock.acquire)
            try:
                return await direct_call(tool_name, tool_args)
            finally:
                lock.release()

        if not cacheable:
            return await _direct_call_once()

        state = _ACTIVE_PIPELINE_STATE.get()
        stage_name = _ACTIVE_PIPELINE_STAGE.get() or "pipeline"
        if state is None:
            return await _direct_call_once()

        cache = state.setdefault("tool_result_cache", {})
        cache_key = _tool_result_cache_key(server_id, tool_name, tool_args)
        cached = cache.get(cache_key)
        if cached and cached.get("ok"):
            cached["hit_count"] = int(cached.get("hit_count", 0)) + 1
            _append_tool_cache_note(state, stage_name, "tool_cache_hit", server_id, tool_name, tool_args)
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
            _append_tool_cache_note(state, stage_name, "tool_cache_wait", server_id, tool_name, tool_args)
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
                "tool_name": tool_name,
                "args": _json_safe(tool_args),
                "result": result,
                "cached_at": datetime.now().isoformat(timespec="seconds"),
                "hit_count": 0,
            }
            _prune_tool_result_cache(state)
            _append_tool_cache_note(state, stage_name, "tool_cache_store", server_id, tool_name, tool_args)
        else:
            _append_tool_cache_note(state, stage_name, "tool_cache_skip", server_id, tool_name, tool_args)
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

    base = PIPELINE_STAGE_MANAGER_PROMPTS[stage_kind].rstrip()
    delegated_roles = ", ".join(expand_architecture_names(architecture)) or "none"
    path_handoff_lines = ""
    if stage_kind != "reporter":
        path_handoff_lines = (
            "- If this stage discovers or confirms the real sample path, include a line exactly like:\n"
            f"  {PATH_HANDOFF_LINE_PREFIX} <exact existing path>\n"
        )
    if stage_kind == "workers":
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
        if stage_kind != "reporter":
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
    if shell_execution_mode == "none":
        sections.append("- Shell rule: do not call `execute`. Shell command execution is disabled for this run.")
    elif shell_execution_mode == "ask":
        sections.append("- Shell rule: `execute` is available only with explicit user approval per command. Keep commands minimal, local, and explainable.")
    else:
        sections.append("- Shell rule: `execute` is enabled. Use it sparingly for bounded local verification only.")
    sections.append(
        "- Safety rule: shell execution access does not authorize detonating or recklessly running a potentially malicious sample outside approved sandboxing controls."
    )
    if stage_kind == "workers":
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
    elif stage_kind == "validators":
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
    if planned_work_items and stage_kind != "planner":
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
    if validation_retry_count or validation_last_decision or validation_replan_feedback:
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
        if validation_replan_feedback and stage_kind in {"planner", "workers", "validators"}:
            sections.extend(["", "Latest validator feedback to address:", validation_replan_feedback])

    stage_roles = expand_architecture_names(architecture)
    if stage_roles:
        sections.extend(["", "Configured stage roles:", ", ".join(stage_roles)])

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
    stages: List[PipelineStageRuntime]
    static_tool_ids: List[str]
    dynamic_tool_ids: List[str]
    sandbox_tool_ids: List[str]
    static_tools: List[MCPServerStdio]
    dynamic_tools: List[MCPServerStdio]
    skill_directories: List[str]
    deep_backend: Any


_RUNTIME: Optional[MultiAgentRuntime] = None
_ACTIVE_PIPELINE_STATE: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "active_pipeline_state",
    default=None,
)
_ACTIVE_PIPELINE_STAGE: ContextVar[Optional[str]] = ContextVar(
    "active_pipeline_stage",
    default=None,
)
_TOOL_RESULT_CACHE_INFLIGHT_LOCK = Lock()
_TOOL_RESULT_CACHE_INFLIGHT: Dict[str, Tuple[asyncio.Task[Any], Any]] = {}
_SERIAL_MCP_CALL_LOCKS: Dict[str, Lock] = {}
_AUTOMATION_TRIGGER_SERVER: ThreadingHTTPServer | None = None
_AUTOMATION_TRIGGER_LOCK = Lock()
_AUTOMATION_TRIGGER_PENDING = False


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
        memory_dir = str(memory_root / "workers" / slot_name)
        if memory_dir.startswith("/"):
            memory_dir = memory_dir.lstrip("/")
    else:
        if not memory_root.is_absolute():
            memory_root = REPO_ROOT / memory_root
        memory_dir = str((memory_root / "workers" / slot_name).resolve())

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
    tool_free_stage = stage_kind in {"planner", "validators", "reporter"}
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
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
) -> Tuple[List[PipelineStageRuntime], List[str], Any]:
    skill_directories = _build_skill_directories()
    deep_backend = _build_deep_backend()
    stages = [
        build_stage_runtime(stage_definition, static_tools, dynamic_tools, skill_directories, deep_backend)
        for stage_definition in DEEP_AGENT_PIPELINE
    ]
    return stages, skill_directories, deep_backend


def get_runtime_sync() -> MultiAgentRuntime:
    global _RUNTIME
    if _RUNTIME is not None:
        return _RUNTIME

    toolsets = load_mcp_servers(str(REPO_ROOT / "MCPServers" / "servers.json"))
    static_tools, dynamic_tools = partition_toolsets(toolsets)

    print("Loaded MCP servers:", [s.id for s in toolsets])
    print("Static tools:", [s.id for s in static_tools])
    print("Dynamic tools:", [s.id for s in dynamic_tools])

    stages, skill_directories, deep_backend = build_deep_runtime_components(static_tools, dynamic_tools)
    print("Deep-agent mode: required")
    print(
        "Deep config:",
        {
            "pipeline_name": DEEP_AGENT_PIPELINE_NAME,
            "pipeline": DEEP_AGENT_PIPELINE,
            "worker_architecture_name": DEEP_AGENT_ARCHITECTURE_NAME,
            "worker_architecture": DEEP_AGENT_ARCHITECTURE,
            "worker_subagents": expand_architecture_names(DEEP_AGENT_ARCHITECTURE),
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

    _RUNTIME = MultiAgentRuntime(
        pipeline_name=DEEP_AGENT_PIPELINE_NAME,
        stages=stages,
        static_tool_ids=[s.id or "" for s in static_tools],
        dynamic_tool_ids=[s.id or "" for s in dynamic_tools],
        sandbox_tool_ids=_sandbox_tool_ids(dynamic_tools),
        static_tools=static_tools,
        dynamic_tools=dynamic_tools,
        skill_directories=skill_directories,
        deep_backend=deep_backend,
    )
    return _RUNTIME
