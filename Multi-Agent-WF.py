import os
import sys
import json
import time
import asyncio
import getpass
import html
import re
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from dataclasses import dataclass
from threading import Event, Thread, Lock

import gradio as gr

from pydantic_ai import Agent, ModelMessage
from pydantic_ai.mcp import MCPServerStdio
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

import pydantic_deep as pydantic_deep_pkg

from pydantic_deep import (
    create_deep_agent,
    create_default_deps,
    create_sliding_window_processor,
)
from workflow_config_loader import load_workflow_config


# ----------------------------
# Config
# ----------------------------
def _load_dotenv_if_present() -> None:
    raw_path = (os.environ.get("DOTENV_PATH") or "").strip()
    candidates: List[Path] = []
    if raw_path:
        candidates.append(Path(raw_path).expanduser())
    candidates.append(Path.cwd() / ".env")
    candidates.append(Path(__file__).resolve().parent / ".env")

    dotenv_path: Optional[Path] = None
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            continue
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        if resolved.exists() and resolved.is_file():
            dotenv_path = resolved
            break

    if dotenv_path is None:
        return

    try:
        from dotenv import load_dotenv

        load_dotenv(dotenv_path=dotenv_path, override=False)
        print(f"[env] loaded {dotenv_path}")
        return
    except Exception:
        pass

    # Fallback parser if python-dotenv is unavailable.
    try:
        for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or key in os.environ:
                continue

            if len(value) >= 2 and ((value[0] == value[-1] == "'") or (value[0] == value[-1] == '"')):
                value = value[1:-1]
            os.environ[key] = value

        print(f"[env] loaded {dotenv_path} (fallback parser)")
    except Exception as e:
        print(f"[env] warning: failed to parse {dotenv_path}: {e}")


_load_dotenv_if_present()

if not os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter your OpenAI API Key: ")

OPENAI_MODEL_ID = os.environ.get("OPENAI_MODEL_ID", "openai:gpt-4o-mini")
MAX_ROLE_HISTORY_MESSAGES = int(os.environ.get("MAX_ROLE_HISTORY_MESSAGES", "16"))
MAX_TASK_OUTPUTS = int(os.environ.get("MAX_TASK_OUTPUTS", "32"))
MAX_TOOL_LOG_CHARS = int(os.environ.get("MAX_TOOL_LOG_CHARS", "120000"))
MAX_TOOL_RESULT_CACHE_ENTRIES = int(os.environ.get("MAX_TOOL_RESULT_CACHE_ENTRIES", "64"))
PLANNER_WORK_ITEMS_START = "WORK_ITEMS_JSON_START"
PLANNER_WORK_ITEMS_END = "WORK_ITEMS_JSON_END"
TOOL_RESULT_CACHE_SERVER_MARKERS = tuple(
    marker.strip().lower()
    for marker in os.environ.get(
        "TOOL_RESULT_CACHE_SERVER_MARKERS",
        "capa,floss,string,hashdb,binwalk,yara,gitleaks,searchsploit,trivy",
    ).split(",")
    if marker.strip()
)


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_path_list(raw: str) -> List[str]:
    if not raw.strip():
        return []
    sep = os.pathsep if os.pathsep in raw else ","
    return [p.strip() for p in raw.split(sep) if p.strip()]


DEEP_ENABLE_MEMORY = _env_flag("DEEP_ENABLE_MEMORY", True)
DEEP_MEMORY_DIR = os.environ.get("DEEP_MEMORY_DIR", ".deep/memory")
DEEP_PERSIST_BACKEND = _env_flag("DEEP_PERSIST_BACKEND", True)
DEEP_BACKEND_ROOT = os.environ.get("DEEP_BACKEND_ROOT", "./.deep_backend")
DEEP_ENABLE_SKILLS = _env_flag("DEEP_ENABLE_SKILLS", True)
DEEP_INCLUDE_BUNDLED_SKILLS = _env_flag("DEEP_INCLUDE_BUNDLED_SKILLS", True)
DEEP_SKILL_DIRS = _parse_path_list(os.environ.get("DEEP_SKILL_DIRS", ""))
MAX_STATUS_LOG_LINES = int(os.environ.get("MAX_STATUS_LOG_LINES", "400"))
STATUS_LOG_STDOUT = _env_flag("STATUS_LOG_STDOUT", True)
DEEP_AGENT_RETRIES = int(os.environ.get("DEEP_AGENT_RETRIES", "4"))
PATH_HANDOFF_LINE_PREFIX = "Validated sample path:"
SAMPLE_PATH_SUFFIXES = ("exe", "dll", "sys", "scr", "ocx", "cpl", "bin", "elf", "so", "dylib")
SAMPLE_PATH_WINDOWS_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])([A-Za-z]:[\\/][^\r\n\"'<>|?*]+?\.(?:"
    + "|".join(SAMPLE_PATH_SUFFIXES)
    + r"))"
)
SAMPLE_PATH_POSIX_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])((?:/|\./|\.\./)[^\r\n\"']+?\.(?:"
    + "|".join(SAMPLE_PATH_SUFFIXES)
    + r"))"
)
SAMPLE_PATH_QUOTED_RE = re.compile(
    r"(?i)[\"']((?:[A-Za-z]:[\\/]|/|\./|\.\./)[^\"'\r\n]+?\.(?:"
    + "|".join(SAMPLE_PATH_SUFFIXES)
    + r"))[\"']"
)
GHIDRA_EXECUTABLE_PATH_RE = re.compile(r"(?im)^Executable Path:\s*(.+?)\s*$")

WORKFLOW_CONFIG = load_workflow_config(
    Path(__file__).resolve().parent / "workflow_config",
    placeholders={
        "PLANNER_WORK_ITEMS_START": PLANNER_WORK_ITEMS_START,
        "PLANNER_WORK_ITEMS_END": PLANNER_WORK_ITEMS_END,
    },
)
AGENT_ARCHETYPE_PROMPTS: Dict[str, str] = WORKFLOW_CONFIG["agent_archetype_prompts"]
PIPELINE_STAGE_MANAGER_PROMPTS: Dict[str, str] = WORKFLOW_CONFIG["stage_manager_prompts"]
DEEP_AGENT_ARCHITECTURE_PRESETS: Dict[str, List[Tuple[str, int]]] = WORKFLOW_CONFIG["architecture_presets"]
DEEP_AGENT_PIPELINE_PRESETS: Dict[str, List[Dict[str, Any]]] = WORKFLOW_CONFIG["pipeline_presets"]
AGENT_ARCHETYPE_SPECS: Dict[str, Dict[str, str]] = WORKFLOW_CONFIG["agent_archetype_specs"]
PIPELINE_STAGE_OUTPUT_CONTRACTS: Dict[str, str] = WORKFLOW_CONFIG["stage_output_contracts"]

# Worker analyst breadth configuration. Edit `workflow_config/architecture_presets.json`
# or set DEEP_AGENT_ARCHITECTURE_NAME to one of the named presets below.

DEEP_AGENT_ARCHITECTURE_NAME = (os.environ.get("DEEP_AGENT_ARCHITECTURE_NAME") or "aws_collaboration").strip()
if DEEP_AGENT_ARCHITECTURE_NAME not in DEEP_AGENT_ARCHITECTURE_PRESETS:
    raise RuntimeError(
        f"Unknown DEEP_AGENT_ARCHITECTURE_NAME={DEEP_AGENT_ARCHITECTURE_NAME!r}. "
        f"Available presets: {', '.join(sorted(DEEP_AGENT_ARCHITECTURE_PRESETS))}"
    )

DEEP_AGENT_ARCHITECTURE: List[Tuple[str, int]] = list(
    DEEP_AGENT_ARCHITECTURE_PRESETS[DEEP_AGENT_ARCHITECTURE_NAME]
)
# Optional direct override example for worker breadth:
# DEEP_AGENT_ARCHITECTURE = [
#     ("triage_analyst", 1),
#     ("control_flow_analyst", 2),
#     ("obfuscation_analyst", 1),
#     ("string_analyst", 1),
# ]

DEEP_AGENT_PIPELINE_NAME = (
    os.environ.get("DEEP_AGENT_PIPELINE_NAME") or "preflight_planner_workers_validators_reporter"
).strip()
if DEEP_AGENT_PIPELINE_NAME not in DEEP_AGENT_PIPELINE_PRESETS:
    raise RuntimeError(
        f"Unknown DEEP_AGENT_PIPELINE_NAME={DEEP_AGENT_PIPELINE_NAME!r}. "
        f"Available presets: {', '.join(sorted(DEEP_AGENT_PIPELINE_PRESETS))}"
    )


def resolve_pipeline_definition(
    pipeline_template: List[Dict[str, Any]],
    worker_architecture: List[Tuple[str, int]],
) -> List[Dict[str, Any]]:
    resolved: List[Dict[str, Any]] = []
    for raw_stage in pipeline_template:
        stage = dict(raw_stage)
        if stage.get("use_worker_architecture"):
            stage["architecture"] = list(worker_architecture)
        else:
            stage["architecture"] = list(stage.get("architecture") or [])
        resolved.append(stage)
    return resolved


DEEP_AGENT_PIPELINE: List[Dict[str, Any]] = resolve_pipeline_definition(
    DEEP_AGENT_PIPELINE_PRESETS[DEEP_AGENT_PIPELINE_NAME],
    DEEP_AGENT_ARCHITECTURE,
)
PIPELINE_LOG_SLOTS: List[Tuple[str, str]] = [
    (str(stage["name"]), str(stage["stage_kind"])) for stage in DEEP_AGENT_PIPELINE
]
# Optional direct override example for explicit staged flow:
# DEEP_AGENT_PIPELINE = [
#     {"name": "preflight", "stage_kind": "preflight", "architecture": [("preflight_analyst", 1)], "use_worker_architecture": False},
#     {"name": "planner", "stage_kind": "planner", "architecture": [], "use_worker_architecture": False},
#     {"name": "workers", "stage_kind": "workers", "architecture": [("control_flow_analyst", 2), ("string_analyst", 1)], "use_worker_architecture": False},
#     {"name": "validators", "stage_kind": "validators", "architecture": [("evidence_validator", 2)], "use_worker_architecture": False},
#     {"name": "reporter", "stage_kind": "reporter", "architecture": [("reporting_analyst", 1)], "use_worker_architecture": False},
# ]


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


def _server_allows_result_cache(server_id: str) -> bool:
    sid = (server_id or "").lower()
    return bool(sid) and any(marker in sid for marker in TOOL_RESULT_CACHE_SERVER_MARKERS)


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

    async def _processor(ctx: Any, direct_call: Any, tool_name: str, tool_args: Dict[str, Any]) -> Any:
        if not cacheable:
            return await direct_call(tool_name, tool_args)

        state = _ACTIVE_PIPELINE_STATE.get()
        stage_name = _ACTIVE_PIPELINE_STAGE.get() or "pipeline"
        if state is None:
            return await direct_call(tool_name, tool_args)

        cache = state.setdefault("tool_result_cache", {})
        cache_key = _tool_result_cache_key(server_id, tool_name, tool_args)
        cached = cache.get(cache_key)
        if cached and cached.get("ok"):
            cached["hit_count"] = int(cached.get("hit_count", 0)) + 1
            _append_tool_cache_note(state, stage_name, "tool_cache_hit", server_id, tool_name, tool_args)
            return cached.get("result")

        owner = False
        with _TOOL_RESULT_CACHE_INFLIGHT_LOCK:
            task = _TOOL_RESULT_CACHE_INFLIGHT.get(cache_key)
            if task is None:
                task = asyncio.create_task(direct_call(tool_name, tool_args))
                _TOOL_RESULT_CACHE_INFLIGHT[cache_key] = task
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
                if _TOOL_RESULT_CACHE_INFLIGHT.get(cache_key) is task:
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

def _toolsets_for_domain(
    tool_domain: str,
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
) -> List[MCPServerStdio]:
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
        toolsets = _toolsets_for_domain(spec["tool_domain"], static_tools, dynamic_tools)
        if not toolsets:
            raise RuntimeError(
                f"Deep-agent architecture requested {archetype_name!r}, but no {spec['tool_domain']} MCP toolsets are configured."
            )

        for idx in range(quantity):
            instance_name = archetype_name if quantity == 1 else f"{archetype_name}_{idx + 1}"
            instructions = AGENT_ARCHETYPE_PROMPTS[archetype_name]
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
                    "toolsets": toolsets,
                    "preferred_mode": spec["preferred_mode"],
                    "typical_complexity": spec["typical_complexity"],
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
    return (
        f"{base}\n\n"
        "Current stage configuration:\n"
        f"- stage_name: {stage_name}\n"
        f"- stage_kind: {stage_kind}\n"
        f"- delegated roles: {delegated_roles}\n"
        "- Prefer normal synchronous delegation for stage work unless there is a strong reason to launch background tasks.\n"
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
    sections.extend(["", "Shared execution context:"])
    if validated_sample_path:
        sections.extend(
            [
                f"- validated_sample_path: {validated_sample_path}",
                f"- validated_sample_path_source: {validated_sample_path_source or 'unknown'}",
                "- Path rule: use this exact path verbatim in every tool call that requires the sample target.",
            ]
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
    architecture: List[Tuple[str, int]]
    subagent_names: List[str]
    agent: Agent
    deps: Any


@dataclass
class MultiAgentRuntime:
    pipeline_name: str
    stages: List[PipelineStageRuntime]


_RUNTIME: Optional[MultiAgentRuntime] = None
_LIVE_TOOL_LOG_STATE: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "live_tool_log_state",
    default=None,
)
_ACTIVE_PIPELINE_STATE: ContextVar[Optional[Dict[str, Any]]] = ContextVar(
    "active_pipeline_state",
    default=None,
)
_ACTIVE_PIPELINE_STAGE: ContextVar[Optional[str]] = ContextVar(
    "active_pipeline_stage",
    default=None,
)
_TOOL_RESULT_CACHE_INFLIGHT_LOCK = Lock()
_TOOL_RESULT_CACHE_INFLIGHT: Dict[str, asyncio.Task[Any]] = {}


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
            p = Path(path).expanduser().resolve()
            if p.exists() and p.is_dir():
                skill_directories.append(str(p))

        local_skills = (Path.cwd() / "skills").resolve()
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
            from pydantic_ai_backends import LocalBackend

            deep_root = Path(DEEP_BACKEND_ROOT).expanduser().resolve()
            deep_backend = LocalBackend(root_dir=str(deep_root), enable_execute=False)
        except Exception as e:
            print(f"[deep backend] persistent LocalBackend unavailable, using StateBackend: {e}")
            deep_backend = None
    return deep_backend


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
    subagents = (
        build_subagent_architecture(stage_name, architecture, static_tools, dynamic_tools)
        if architecture
        else []
    )
    planner_stage = stage_kind == "planner"
    stage_skill_directories = [] if planner_stage else list(skill_directories)
    memory_dir = str(Path(DEEP_MEMORY_DIR) / stage_name)
    if deep_backend is not None and memory_dir.startswith("/"):
        memory_dir = memory_dir.lstrip("/")

    try:
        stage_agent = create_deep_agent(
            model=OPENAI_MODEL_ID,
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
            context_manager_max_tokens=int(os.environ.get("DEEP_CONTEXT_MAX_TOKENS", "18000")),
            history_processors=_build_history_processors(),
            retries=DEEP_AGENT_RETRIES,
            cost_tracking=False,
            event_stream_handler=make_live_tool_event_handler(stage_name, f"{stage_name}.manager"),
        )
        stage_deps = create_default_deps(backend=deep_backend) if deep_backend is not None else create_default_deps()
        return PipelineStageRuntime(
            name=stage_name,
            stage_kind=stage_kind,
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
) -> List[PipelineStageRuntime]:
    skill_directories = _build_skill_directories()
    deep_backend = _build_deep_backend()
    return [
        build_stage_runtime(stage_definition, static_tools, dynamic_tools, skill_directories, deep_backend)
        for stage_definition in DEEP_AGENT_PIPELINE
    ]


def get_runtime_sync() -> MultiAgentRuntime:
    global _RUNTIME
    if _RUNTIME is not None:
        return _RUNTIME

    toolsets = load_mcp_servers("./MCPServers/servers.json")
    static_tools, dynamic_tools = partition_toolsets(toolsets)

    print("Loaded MCP servers:", [s.id for s in toolsets])
    print("Static tools:", [s.id for s in static_tools])
    print("Dynamic tools:", [s.id for s in dynamic_tools])

    stages = build_deep_runtime_components(static_tools, dynamic_tools)
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
            "backend_root": str(Path(DEEP_BACKEND_ROOT).expanduser().resolve()),
            "skills": DEEP_ENABLE_SKILLS,
            "skill_dirs": DEEP_SKILL_DIRS,
            "include_bundled_skills": DEEP_INCLUDE_BUNDLED_SKILLS,
            "deep_agent_retries": DEEP_AGENT_RETRIES,
        },
    )

    _RUNTIME = MultiAgentRuntime(
        pipeline_name=DEEP_AGENT_PIPELINE_NAME,
        stages=stages,
    )
    return _RUNTIME


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


def _append_tool_log_entries(
    state: Dict[str, Any],
    stage_name: str,
    entries: List[Dict[str, Any]],
) -> None:
    if not entries:
        return

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
    cleaned: List[str] = []
    for raw_line in (text or "").splitlines():
        stripped = raw_line.strip()
        lowered = stripped.lower()
        if lowered.startswith(PATH_HANDOFF_LINE_PREFIX.lower()):
            continue
        if "validated_sample_path:" in lowered:
            continue
        if "validated_sample_path_source:" in lowered:
            continue
        if "no validated sample path is currently available in shared context" in lowered:
            continue
        if lowered.startswith("- path rule:") or lowered.startswith("path rule:"):
            continue
        if lowered.startswith("- if you discover the real sample path"):
            continue
        cleaned.append(raw_line)

    output = "\n".join(cleaned)
    output = re.sub(r"\n{3,}", "\n\n", output).strip()
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
            validated = _extract_ghidra_executable_path(text)
            if not validated:
                continue
            shared = state.setdefault("shared_state", _new_shared_state())
            previous = shared.get("validated_sample_path")
            shared["validated_sample_path"] = validated
            shared["validated_sample_path_source"] = source
            if previous != validated:
                append_status(state, f"Validated sample path set from {source}: {validated}")
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
        "planned_work_items": [],
        "planned_work_items_parse_error": "",
        "pipeline_stage_outputs": [],
        "pipeline_stage_progress": [],
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
    return {
        "role_histories": {},
        "tool_log": "",
        "tool_log_sections": {},
        "_tool_log_seen_keys": {},
        "tool_result_cache": {},
        "status_log": "",
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
) -> None:
    with _UI_SNAPSHOT_LOCK:
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

def _stage_progress_from_pipeline_definition() -> List[Dict[str, Any]]:
    progress: List[Dict[str, Any]] = []
    for raw_stage in DEEP_AGENT_PIPELINE:
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

    box, tone, status_label = _planner_work_item_rollup(progress)
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
            f"<div style='font-size: 15px;'><span style='font-size: 18px; margin-right: 8px;'>{box}</span>"
            f"<strong>{item_id}</strong> <span style='color: #202124;'>{objective}</span></div>"
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
        if status == "failed" and item.get("error"):
            error_html = (
                f"<div style='margin-top: 4px; color: #a61b29;'>"
                f"{html.escape(str(item.get('error')))}</div>"
            )

        rows.append(
            "<div style='border: 1px solid #d5d8dd; border-radius: 10px; padding: 10px 12px; margin-top: 8px;'>"
            f"<div style='display: flex; justify-content: space-between; gap: 12px; align-items: center;'>"
            f"<div style='font-size: 15px;'><span style='font-size: 18px; margin-right: 8px;'>{box}</span>"
            f"<strong>{stage_name}</strong> <span style='color: #5f6368;'>({stage_kind})</span></div>"
            f"<div style='font-family: monospace; color: {tone};'>{_format_elapsed(elapsed)}</div>"
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

    state["shared_state"]["task_outputs"] = []
    state["shared_state"]["pipeline_stage_outputs"] = []
    state["shared_state"]["turn_task_runs"] = 0
    state["shared_state"]["last_user_request"] = user_text
    state["shared_state"]["execution_mode"] = "deep_pipeline"
    state["shared_state"]["deep_architecture_name"] = DEEP_AGENT_ARCHITECTURE_NAME
    state["shared_state"]["deep_architecture"] = list(DEEP_AGENT_ARCHITECTURE)
    state["shared_state"]["deep_subagents"] = expand_architecture_names(DEEP_AGENT_ARCHITECTURE)
    state["shared_state"]["deep_pipeline_name"] = runtime.pipeline_name
    state["shared_state"]["deep_pipeline"] = list(DEEP_AGENT_PIPELINE)
    state["shared_state"]["planned_work_items"] = []
    state["shared_state"]["planned_work_items_parse_error"] = ""
    _seed_pipeline_stage_progress(
        state,
        [(stage.name, stage.stage_kind, list(stage.subagent_names)) for stage in runtime.stages],
    )
    update_validated_sample_path(state, user_text, "user_request", explicit_only=False)

    prior_stage_outputs: Dict[str, str] = {}
    final_output = ""

    for stage in runtime.stages:
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

    state["shared_state"]["run_count"] = int(state["shared_state"].get("run_count", 0)) + 1
    state["shared_state"]["final_output"] = final_output
    append_status(state, f"Deep pipeline finished in {time.perf_counter() - t0:.1f}s")
    return final_output


# ----------------------------
# Gradio handlers
# ----------------------------
def _message_input(value: str = "", interactive: bool = True, visible: bool = True):
    return gr.update(value=value, interactive=interactive, visible=visible)


def _send_button(interactive: bool = True, visible: bool = True):
    return gr.update(interactive=interactive, visible=visible)


def _todo_board(state: Dict[str, Any], visible: bool):
    return gr.update(value=render_pipeline_todo_board(state), visible=visible)


def _planned_work_items_board(state: Dict[str, Any]):
    return gr.update(value=render_planned_work_items_panel(state), visible=True)


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
    planned_work_items_update: Any,
    send_update: Any,
    clear_update: Any,
    todo_update: Any,
) -> Tuple[Any, ...]:
    return (
        message_update,
        chat_history,
        state,
        planned_work_items_update,
        *_tool_log_updates(state),
        send_update,
        clear_update,
        todo_update,
    )


def _restore_snapshot_outputs(snapshot: Dict[str, Any]):
    state = snapshot.get("state") or _snapshot_state_default()
    chat_history = snapshot.get("chat_history") or []
    active = bool(snapshot.get("run_active"))
    composer_visible = bool(snapshot.get("composer_visible", True)) and not active
    send_visible = bool(snapshot.get("send_visible", True)) and not active
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
        _planned_work_items_board(state),
        _send_button(
            interactive=send_visible,
            visible=send_visible,
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
            *_tool_log_skip_updates(),
            gr.skip(),
            gr.skip(),
            gr.skip(),
        )
    return _restore_snapshot_outputs(snapshot)


def chat_turn(user_text: str, chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    user_text = (user_text or "").strip()
    if not user_text:
        state = state or {}
        yield _ui_updates(
            _message_input(value="", interactive=True, visible=True),
            chat_history,
            state,
            _planned_work_items_board(state),
            _send_button(interactive=True, visible=True),
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
    state.setdefault("shared_state", _new_shared_state())
    state["tool_log"] = ""
    state["tool_log_sections"] = {}
    state["_tool_log_seen_keys"] = {}
    state["shared_state"]["pipeline_stage_progress"] = _stage_progress_from_pipeline_definition()
    state["shared_state"]["planned_work_items"] = []
    state["shared_state"]["planned_work_items_parse_error"] = ""

    append_status(state, f"New query: {_shorten(user_text, max_chars=220)}")
    running_note = "[deep pipeline running... task board is live]"

    # Show user input immediately and begin streaming status/tool log updates.
    chat_box["history"] = chat_history + [
        {"role": "user", "content": user_text},
        {"role": "assistant", "content": running_note},
    ]
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
        _planned_work_items_board(state),
        _send_button(interactive=False, visible=False),
        _send_button(interactive=False, visible=False),
        _todo_board(state, visible=True),
    )

    def _run_deep_pipeline() -> Tuple[str, str]:
        runtime = get_runtime_sync()
        return run_deepagent_pipeline(runtime, user_text, state), "deep_pipeline"

    result_box: Dict[str, str] = {"assistant_text": running_note}
    done = Event()

    def _runner() -> None:
        try:
            assistant_text, mode = _run_deep_pipeline()
            append_status(state, f"Chat turn finished in {time.perf_counter() - turn_t0:.1f}s (mode={mode})")
            result_box["assistant_text"] = _sanitize_user_facing_output(assistant_text)
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
                    return
            append_status(state, f"Chat turn failed ({type(e).__name__}) in {time.perf_counter() - turn_t0:.1f}s")
            result_box["assistant_text"] = f"[multi-agent pipeline error] {type(e).__name__}: {e}"
        finally:
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
    while not done.wait(0.35):
        tool_now = state.get("tool_log", "")
        todo_now = render_pipeline_todo_board(state)
        planned_now = render_planned_work_items_panel(state)
        if tool_now != last_tool_log or todo_now != last_todo_html or planned_now != last_planned_html:
            last_tool_log = tool_now
            last_todo_html = todo_now
            last_planned_html = planned_now
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
                gr.update(value=planned_now, visible=True),
                _send_button(interactive=False, visible=False),
                _send_button(interactive=False, visible=False),
                gr.update(value=todo_now, visible=True),
            )

    worker.join(timeout=0.1)

    # Update UI chat
    chat_history = chat_box["history"]

    yield _ui_updates(
        _message_input(value="", interactive=True, visible=True),
        chat_history,
        state,
        _planned_work_items_board(state),
        _send_button(interactive=True, visible=True),
        _send_button(interactive=True, visible=True),
        _todo_board(state, visible=bool((state.get("shared_state") or {}).get("pipeline_stage_progress"))),
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
        _planned_work_items_board(fresh_state),
        _send_button(interactive=True, visible=True),
        _send_button(interactive=True, visible=True),
        _todo_board({"shared_state": fresh_shared_state}, visible=False),
    )


# ----------------------------
# UI
# ----------------------------
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
    snapshot_timer = gr.Timer(0.5, active=True, render=False)

    with gr.Row():
        with gr.Column(scale=3):
            chat = gr.Chatbot(label="Chat", height=330)
            todo_board = gr.HTML(visible=False)
            user = gr.Textbox(
                label="Message",
                lines=2,
                placeholder="Ask something. Example: analyze this sample for hashing, anti-debugging, and network behavior...",
            )
            with gr.Row():
                send = gr.Button("Send", variant="primary")
                clear = gr.Button("Reset")

        with gr.Column(scale=2):
            planned_work_items_panel = gr.HTML(value=render_planned_work_items_panel(initial_state))
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

    ui_outputs = [user, chat, state, planned_work_items_panel, *tool_log_boxes, send, clear, todo_board]
    send.click(chat_turn, inputs=[user, chat, state], outputs=ui_outputs)
    user.submit(chat_turn, inputs=[user, chat, state], outputs=ui_outputs)
    clear.click(reset, inputs=None, outputs=ui_outputs)
    demo.load(restore_last_ui, inputs=None, outputs=ui_outputs)
    snapshot_timer.tick(
        poll_active_ui_snapshot,
        inputs=None,
        outputs=ui_outputs,
        show_progress="hidden",
    )

demo.queue()
demo.launch()
