import os
import sys
import json
import time
import getpass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from dataclasses import dataclass
from threading import Event, Thread

import gradio as gr

from pydantic_ai import Agent, ModelMessage
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

from multi_agent_prompts import (
    AGENT_ARCHETYPE_PROMPTS,
    DEEP_ORCHESTRATOR_INSTRUCTIONS,
)

import pydantic_deep as pydantic_deep_pkg

from pydantic_deep import (
    create_deep_agent,
    create_default_deps,
    create_sliding_window_processor,
)


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

# Streamlined deep-agent architecture configuration. Edit the tuple list directly
# or set DEEP_AGENT_ARCHITECTURE_NAME to one of the named presets below.
DEEP_AGENT_ARCHITECTURE_PRESETS: Dict[str, List[Tuple[str, int]]] = {
    "minimal": [
        ("static_generalist", 1),
    ],
    "balanced": [
        ("triage_analyst", 1),
        ("control_flow_analyst", 1),
        ("obfuscation_analyst", 1),
        ("string_analyst", 1),
    ],
    "aws_collaboration": [
        ("triage_analyst", 1),
        ("control_flow_analyst", 1),
        ("string_analyst", 1),
        ("obfuscation_analyst", 1),
        ("capability_analyst", 1),
    ],
    "runtime_enriched": [
        ("triage_analyst", 1),
        ("control_flow_analyst", 1),
        ("string_analyst", 1),
        ("obfuscation_analyst", 1),
        ("capability_analyst", 1),
        ("runtime_behavior_analyst", 1),
    ],
    "static_swarm": [
        ("triage_analyst", 1),
        ("control_flow_analyst", 2),
        ("obfuscation_analyst", 1),
        ("string_analyst", 1),
        ("capability_analyst", 1),
    ],
}

DEEP_AGENT_ARCHITECTURE_NAME = (os.environ.get("DEEP_AGENT_ARCHITECTURE_NAME") or "aws_collaboration").strip()
if DEEP_AGENT_ARCHITECTURE_NAME not in DEEP_AGENT_ARCHITECTURE_PRESETS:
    raise RuntimeError(
        f"Unknown DEEP_AGENT_ARCHITECTURE_NAME={DEEP_AGENT_ARCHITECTURE_NAME!r}. "
        f"Available presets: {', '.join(sorted(DEEP_AGENT_ARCHITECTURE_PRESETS))}"
    )

DEEP_AGENT_ARCHITECTURE: List[Tuple[str, int]] = list(
    DEEP_AGENT_ARCHITECTURE_PRESETS[DEEP_AGENT_ARCHITECTURE_NAME]
)
# Optional direct override example:
# DEEP_AGENT_ARCHITECTURE = [
#     ("triage_analyst", 1),
#     ("control_flow_analyst", 2),
#     ("obfuscation_analyst", 1),
#     ("string_analyst", 1),
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

        server = MCPServerStdio(command, args=args, timeout=30, id=name)
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


AGENT_ARCHETYPE_SPECS: Dict[str, Dict[str, str]] = {
    "static_generalist": {
        "description": "General static reverse-engineering specialist.",
        "tool_domain": "static",
        "preferred_mode": "sync",
        "typical_complexity": "moderate",
    },
    "triage_analyst": {
        "description": "Static triage specialist that identifies the highest-value pivots for the sample.",
        "tool_domain": "static",
        "preferred_mode": "sync",
        "typical_complexity": "moderate",
    },
    "control_flow_analyst": {
        "description": "Static specialist focused on dispatcher logic, execution paths, and major branch pivots.",
        "tool_domain": "static",
        "preferred_mode": "sync",
        "typical_complexity": "complex",
    },
    "string_analyst": {
        "description": "Static specialist focused on recovered strings, stack strings, decoded values, and configuration material.",
        "tool_domain": "static",
        "preferred_mode": "sync",
        "typical_complexity": "moderate",
    },
    "obfuscation_analyst": {
        "description": "Static specialist focused on concrete obfuscation and anti-analysis mechanisms.",
        "tool_domain": "static",
        "preferred_mode": "sync",
        "typical_complexity": "complex",
    },
    "capability_analyst": {
        "description": "Static specialist focused on mapping concrete capabilities from code artifacts and capa evidence.",
        "tool_domain": "static",
        "preferred_mode": "sync",
        "typical_complexity": "moderate",
    },
    "dynamic_generalist": {
        "description": "General runtime behavior specialist.",
        "tool_domain": "dynamic",
        "preferred_mode": "auto",
        "typical_complexity": "complex",
    },
    "runtime_behavior_analyst": {
        "description": "Runtime specialist focused on behavioral correlation and execution-time artifacts.",
        "tool_domain": "dynamic",
        "preferred_mode": "auto",
        "typical_complexity": "complex",
    },
}


def _toolsets_for_domain(
    tool_domain: str,
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
) -> List[MCPServerStdio]:
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


# ----------------------------
# Runtime container
# ----------------------------
@dataclass
class MultiAgentRuntime:
    deep_orchestrator: Agent
    deep_deps: Any
    all_toolsets: List[MCPServerStdio]
    static_toolsets: List[MCPServerStdio]
    dynamic_toolsets: List[MCPServerStdio]


_RUNTIME: Optional[MultiAgentRuntime] = None


def build_deep_runtime_components(
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
) -> Tuple[Agent, Any]:
    subagents = build_subagent_architecture(DEEP_AGENT_ARCHITECTURE, static_tools, dynamic_tools)

    history_processors = [
        create_sliding_window_processor(
            trigger=("messages", 80),
            keep=("messages", 40),
        )
    ]

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

    deep_backend = None
    if DEEP_PERSIST_BACKEND:
        try:
            from pydantic_ai_backends import LocalBackend

            deep_root = Path(DEEP_BACKEND_ROOT).expanduser().resolve()
            deep_backend = LocalBackend(root_dir=str(deep_root), enable_execute=False)
        except Exception as e:
            print(f"[deep backend] persistent LocalBackend unavailable, using StateBackend: {e}")
            deep_backend = None

    memory_dir = DEEP_MEMORY_DIR
    if deep_backend is not None and memory_dir.startswith("/"):
        memory_dir = memory_dir.lstrip("/")

    try:
        deep_agent = create_deep_agent(
            model=OPENAI_MODEL_ID,
            instructions=DEEP_ORCHESTRATOR_INSTRUCTIONS,
            subagents=subagents,
            include_todo=True,
            include_filesystem=False,
            include_subagents=True,
            include_general_purpose_subagent=False,
            include_plan=False,
            include_skills=bool(skill_directories),
            skill_directories=skill_directories or None,
            include_memory=DEEP_ENABLE_MEMORY,
            memory_dir=memory_dir,
            include_history_archive=False,
            context_manager=True,
            context_manager_max_tokens=int(os.environ.get("DEEP_CONTEXT_MAX_TOKENS", "18000")),
            history_processors=history_processors,
            retries=DEEP_AGENT_RETRIES,
            cost_tracking=False,
        )
        deep_deps = create_default_deps(backend=deep_backend) if deep_backend is not None else create_default_deps()
        return deep_agent, deep_deps
    except Exception as e:
        raise RuntimeError(f"Deep-agent initialization failed: {type(e).__name__}: {e}") from e


def get_runtime_sync() -> MultiAgentRuntime:
    global _RUNTIME
    if _RUNTIME is not None:
        return _RUNTIME

    toolsets = load_mcp_servers("./MCPServers/servers.json")
    static_tools, dynamic_tools = partition_toolsets(toolsets)

    print("Loaded MCP servers:", [s.id for s in toolsets])
    print("Static tools:", [s.id for s in static_tools])
    print("Dynamic tools:", [s.id for s in dynamic_tools])

    deep_orchestrator, deep_deps = build_deep_runtime_components(static_tools, dynamic_tools)
    print("Deep-agent mode: required")
    print(
        "Deep config:",
        {
            "architecture_name": DEEP_AGENT_ARCHITECTURE_NAME,
            "architecture": DEEP_AGENT_ARCHITECTURE,
            "expanded_subagents": expand_architecture_names(DEEP_AGENT_ARCHITECTURE),
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
        deep_orchestrator=deep_orchestrator,
        deep_deps=deep_deps,
        all_toolsets=toolsets,
        static_toolsets=static_tools,
        dynamic_toolsets=dynamic_tools,
    )
    return _RUNTIME


# ----------------------------
# Tool log extraction (best-effort)
# ----------------------------
def extract_tool_log_from_messages(messages: List[ModelMessage]) -> str:
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
                        {
                            "kind": "tool_return",
                            "tool_name": part.tool_name,
                            "tool_call_id": part.tool_call_id,
                            "content": part.content,
                        }
                    )

        elif isinstance(m, ModelResponse):
            for part in getattr(m, "parts", []) or []:
                if isinstance(part, ToolCallPart):
                    out.append(
                        {
                            "kind": "tool_call",
                            "tool_name": part.tool_name,
                            "tool_call_id": part.tool_call_id,
                            "args": part.args,
                        }
                    )
                elif isinstance(part, ToolReturnPart):
                    out.append(
                        {
                            "kind": "tool_return",
                            "tool_name": part.tool_name,
                            "tool_call_id": part.tool_call_id,
                            "content": part.content,
                        }
                    )

    return json.dumps(out, indent=2, ensure_ascii=False) if out else ""


def append_tool_log_delta(
    state: Dict[str, Any],
    role_key: str,
    old_history: List[ModelMessage],
    new_history: List[ModelMessage],
) -> None:
    """
    Append only new tool logs (delta) to UI state to avoid duplicates.
    """
    old_len = len(old_history) if old_history else 0
    delta = new_history[old_len:]
    tool_blob = extract_tool_log_from_messages(delta)
    if not tool_blob:
        return

    prev = (state.get("tool_log") or "").strip()
    tagged = f"/* {role_key} */\n{tool_blob}"
    merged = (prev + "\n\n" + tagged).strip() if prev else tagged
    if len(merged) > MAX_TOOL_LOG_CHARS:
        merged = merged[-MAX_TOOL_LOG_CHARS:]
    state["tool_log"] = merged


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


def run_deepagent_orchestration(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> str:
    role_key = "deep_orchestrator"
    old_history = get_role_history(state, role_key)
    append_status(
        state,
        f"Deep orchestration started (architecture={DEEP_AGENT_ARCHITECTURE_NAME}, subagents={', '.join(expand_architecture_names(DEEP_AGENT_ARCHITECTURE))})",
    )
    t0 = time.perf_counter()

    if "shared_state" not in state:
        state["shared_state"] = {
            "artifacts": [],
            "findings": [],
            "task_outputs": [],
            "run_count": 0,
            "turn_task_runs": 0,
            "total_task_runs": 0,
        }

    state["shared_state"]["task_outputs"] = []
    state["shared_state"]["turn_task_runs"] = 0
    state["shared_state"]["last_user_request"] = user_text
    state["shared_state"]["orchestration_mode"] = "deep"
    state["shared_state"]["deep_architecture_name"] = DEEP_AGENT_ARCHITECTURE_NAME
    state["shared_state"]["deep_architecture"] = list(DEEP_AGENT_ARCHITECTURE)
    state["shared_state"]["deep_subagents"] = expand_architecture_names(DEEP_AGENT_ARCHITECTURE)

    try:
        result = runtime.deep_orchestrator.run_sync(
            user_text,
            message_history=old_history if old_history else None,
            deps=runtime.deep_deps,
        )
    except Exception as e:
        append_status(state, f"Deep orchestration failed after {time.perf_counter() - t0:.1f}s: {type(e).__name__}")
        raise
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)

    assistant_text = str(result.output)
    state["shared_state"]["task_outputs"].append(
        {
            "task_id": "deep_orchestrator",
            "worker": "deep",
            "objective": "Run deep-agent orchestration with delegated subagents",
            "status": "ok",
            "output_text": assistant_text,
        }
    )
    state["shared_state"]["run_count"] = int(state["shared_state"].get("run_count", 0)) + 1
    state["shared_state"]["turn_task_runs"] = int(state["shared_state"].get("turn_task_runs", 0)) + 1
    state["shared_state"]["total_task_runs"] = int(state["shared_state"].get("total_task_runs", 0)) + 1
    compact_shared_state(state)

    append_status(state, f"Deep orchestration finished in {time.perf_counter() - t0:.1f}s")
    return assistant_text


# ----------------------------
# Gradio handlers
# ----------------------------
def chat_turn(user_text: str, chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    user_text = (user_text or "").strip()
    if not user_text:
        state = state or {}
        yield "", chat_history, state, state.get("tool_log", ""), state.get("status_log", "")
        return

    chat_history = chat_history or []
    state = state or {}
    turn_t0 = time.perf_counter()

    # Make sure state keys exist
    state.setdefault("role_histories", {})
    state.setdefault("tool_log", "")
    state.setdefault("status_log", "")
    state.setdefault("shared_state", {
        "artifacts": [],
        "findings": [],
        "task_outputs": [],
        "run_count": 0,
        "turn_task_runs": 0,
        "total_task_runs": 0,
    })

    append_status(state, f"New query: {_shorten(user_text, max_chars=220)}")
    running_note = "[orchestration running... status timeline is live]"

    # Show user input immediately and begin streaming status/tool log updates.
    chat_history = chat_history + [
        {"role": "user", "content": user_text},
        {"role": "assistant", "content": running_note},
    ]
    yield "", chat_history, state, state.get("tool_log", ""), state.get("status_log", "")

    def _run_deep_orchestrator() -> Tuple[str, str]:
        runtime = get_runtime_sync()
        return run_deepagent_orchestration(runtime, user_text, state), "deep"

    result_box: Dict[str, str] = {"assistant_text": running_note}
    done = Event()

    def _runner() -> None:
        try:
            assistant_text, mode = _run_deep_orchestrator()
            append_status(state, f"Chat turn finished in {time.perf_counter() - turn_t0:.1f}s (mode={mode})")
            result_box["assistant_text"] = assistant_text
            return
        except Exception as e:
            err = str(e)
            if "messages with role 'tool' must be a response to a preceeding message with 'tool_calls'" in err:
                append_status(state, "Detected invalid tool history; clearing role histories and retrying once")
                state["role_histories"] = {}
                try:
                    assistant_text, mode = _run_deep_orchestrator()
                    append_status(
                        state,
                        f"Chat turn recovered after history reset in {time.perf_counter() - turn_t0:.1f}s (mode={mode})",
                    )
                    result_box["assistant_text"] = assistant_text
                    return
                except Exception as e2:
                    append_status(
                        state,
                        f"Chat turn failed after history-reset retry ({type(e2).__name__}) in {time.perf_counter() - turn_t0:.1f}s",
                    )
                    result_box["assistant_text"] = f"[multi-agent orchestration error] {type(e2).__name__}: {e2}"
                    return
            append_status(state, f"Chat turn failed ({type(e).__name__}) in {time.perf_counter() - turn_t0:.1f}s")
            result_box["assistant_text"] = f"[multi-agent orchestration error] {type(e).__name__}: {e}"
        finally:
            done.set()

    worker = Thread(target=_runner, daemon=True)
    worker.start()

    last_status = state.get("status_log", "")
    last_tool_log = state.get("tool_log", "")
    while not done.wait(0.35):
        status_now = state.get("status_log", "")
        tool_now = state.get("tool_log", "")
        if status_now != last_status or tool_now != last_tool_log:
            last_status = status_now
            last_tool_log = tool_now
            yield "", chat_history, state, tool_now, status_now

    worker.join(timeout=0.1)

    # Update UI chat
    chat_history[-1] = {"role": "assistant", "content": result_box["assistant_text"]}

    yield "", chat_history, state, state.get("tool_log", ""), state.get("status_log", "")


def reset():
    return [], {
        "role_histories": {},
        "tool_log": "",
        "status_log": "",
        "shared_state": {
            "artifacts": [],
            "findings": [],
            "task_outputs": [],
            "run_count": 0,
            "turn_task_runs": 0,
            "total_task_runs": 0,
        },
    }, "", ""


# ----------------------------
# UI
# ----------------------------
with gr.Blocks(title="MCP Deep-Agent Tool Bench (PydanticAI)") as demo:
    gr.Markdown("# MCP Deep-Agent Tool Bench (PydanticAI + MCPServerStdio)")
    gr.Markdown("Deep orchestrator -> delegated subagents")

    state = gr.State({
        "role_histories": {},
        "tool_log": "",
        "status_log": "",
        "shared_state": {
            "artifacts": [],
            "findings": [],
            "task_outputs": [],
            "run_count": 0,
            "turn_task_runs": 0,
            "total_task_runs": 0,
        },
    })

    with gr.Row():
        with gr.Column(scale=3):
            chat = gr.Chatbot(label="Chat", height=330)
            user = gr.Textbox(
                label="Message",
                lines=2,
                placeholder="Ask something. Example: analyze this sample for hashing, anti-debugging, and network behavior...",
            )
            with gr.Row():
                send = gr.Button("Send", variant="primary")
                clear = gr.Button("Reset")

        with gr.Column(scale=2):
            gr.Markdown("### Agent Status")
            status_log = gr.Textbox(label="Timeline", lines=16, max_lines=24, interactive=False)
            gr.Markdown("### Tool / MCP Log (best-effort)")
            tool_log = gr.Code(label="Log", language="json", lines=30)

    send.click(chat_turn, inputs=[user, chat, state], outputs=[user, chat, state, tool_log, status_log])
    user.submit(chat_turn, inputs=[user, chat, state], outputs=[user, chat, state, tool_log, status_log])
    clear.click(reset, inputs=None, outputs=[chat, state, tool_log, status_log])

demo.queue()
demo.launch()
