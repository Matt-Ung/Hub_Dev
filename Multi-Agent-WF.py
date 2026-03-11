import os
import sys
import json
import copy
import time
import getpass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Literal
from dataclasses import dataclass
from threading import Event, Lock, Thread
from concurrent.futures import ThreadPoolExecutor, Future

import gradio as gr
from pydantic import BaseModel, Field

from pydantic_ai import Agent, ModelMessage
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

try:
    import pydantic_deep as pydantic_deep_pkg

    from pydantic_deep import (
        create_deep_agent,
        create_default_deps,
        create_sliding_window_processor,
    )
except Exception:
    pydantic_deep_pkg = None
    create_deep_agent = None
    create_default_deps = None
    create_sliding_window_processor = None


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
USE_DEEP_AGENT = os.environ.get("USE_DEEP_AGENT", "0").strip().lower() in {"1", "true", "yes", "on"}


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
PLANNER_AGENT_RETRIES = int(os.environ.get("PLANNER_AGENT_RETRIES", "2"))
PLANNER_OUTPUT_RETRIES = int(os.environ.get("PLANNER_OUTPUT_RETRIES", "2"))
WORKER_AGENT_RETRIES = int(os.environ.get("WORKER_AGENT_RETRIES", "4"))
VERIFIER_AGENT_RETRIES = int(os.environ.get("VERIFIER_AGENT_RETRIES", "2"))
VERIFIER_OUTPUT_RETRIES = int(os.environ.get("VERIFIER_OUTPUT_RETRIES", "2"))
REPORTER_AGENT_RETRIES = int(os.environ.get("REPORTER_AGENT_RETRIES", "2"))
DEEP_AGENT_RETRIES = int(os.environ.get("DEEP_AGENT_RETRIES", str(WORKER_AGENT_RETRIES)))


# ----------------------------
# Role prompts
# ----------------------------
PLANNER_INSTRUCTIONS = """You are PlannerAgent for a malware analysis workflow.

Your job is to decompose the user's request into a minimal set of high-value worker tasks.

Rules:
- Do NOT perform the analysis yourself.
- Do NOT write the final answer.
- Assign each task to one worker role from the provided list.
- Prefer parallelizable tasks only when independent.
- Keep the plan compact and high value.
- Do NOT create tasks for generic PE primers (section lists, memory structure basics, standard compiler metadata)
  unless the user explicitly asked for them or they are directly relevant to a finding.
- If the user asks for control-flow understanding, include a task that reconstructs the primary execution path
  (entry to key branches/dispatchers/handlers) with concrete code artifacts.
- If the user asks for obfuscation, include tasks that demand concrete indicators from tools (FLOSS/capa/Ghidra),
  such as decoded strings, suspicious string construction routines, dynamic import resolution, indirect calls,
  dispatcher/flattening patterns, API hashing, or packer/decompression stubs.
- Task objectives should require specific evidence outputs (function names/addresses, API names, strings, capa rule names).
- Return only structured data matching the schema.
"""

STATIC_AGENT_INSTRUCTIONS = """You are StaticAnalysisAgent (reverse engineering specialist).

You may use ONLY static-analysis tools available through MCP (e.g., Ghidra, strings/FLOSS, HashDB, capa-static if present).

Rules:
- Produce evidence-grounded results only.
- Do not speculate beyond available evidence.
- Focus on analysis value, not textbook executable structure.
- Do NOT include generic memory/section breakdowns unless directly relevant to a finding or explicitly requested.
- For control flow, map the main path and key decision points (dispatcher, branch pivots, handlers) with concrete artifacts.
- For obfuscation, name the exact mechanism and provide concrete indicators from tool output.
  Weak claim example to avoid: "uses shared libraries."
  Strong claim pattern: "Technique -> evidence -> analyst interpretation."
- For each finding, include evidence pointers (tool name + function name/address/string/rule identifier).
- Return concise technical findings suitable for a verifier to review.
"""

DYNAMIC_AGENT_INSTRUCTIONS = """You are DynamicAnalysisAgent (sandbox/runtime specialist).

You may use ONLY dynamic-analysis tools available through MCP (e.g., VM tools, ProcMon, Wireshark, runtime execution tools).

Rules:
- Produce evidence-grounded runtime findings only.
- If a requested action cannot be completed, explain precisely what failed.
- Avoid generic malware boilerplate and focus on behavior actually observed.
- For each finding, cite concrete artifacts (process/API/network/file/registry evidence).
- Return concise technical findings suitable for a verifier to review.
"""

VERIFIER_INSTRUCTIONS = """You are VerifierAgent.

You review worker outputs for:
- unsupported claims
- missing evidence
- contradictions
- obvious gaps relative to the user request
- low-value boilerplate (especially generic PE memory/section explanations)
- high-level obfuscation claims without concrete indicators

Return a structured verdict:
- approved (bool)
- issues (list)
- retry_tasks (precise rework tasks only if needed)

Quality bar:
- Reject outputs that present generic executable structure as findings when not explicitly requested.
- Reject obfuscation claims unless each claimed technique has concrete evidence (e.g., function/address/API/string/capa rule).
- Prefer retry tasks that request exact missing evidence, not broad rewrites.

Do not write the final user-facing answer.
"""

REPORTER_INSTRUCTIONS = """You are ReporterAgent.

Write the final answer to the user using only the verified outputs from workers.

Style:
- technical, clear, concise
- separate confirmed findings vs unknowns when relevant
- do not invent tool results
- prioritize concrete evidence over generic malware language

Required report behavior:
- Do NOT include generic memory/section primers unless explicitly requested or directly relevant.
- Focus on:
  1) Program purpose hypothesis (evidence-based),
  2) Control-flow narrative (key path and decision points),
  3) Obfuscation techniques with specific indicators and why they matter.
- For obfuscation, each technique should include: exact mechanism, supporting evidence, and confidence.
- If evidence is insufficient, say so explicitly instead of filling with generic caveats.
"""

DEEP_ORCHESTRATOR_INSTRUCTIONS = """You are a malware-analysis orchestrator.

You have access to specialized subagents via tools. Use them deliberately:
- static_analyst: static reverse engineering and string/call-graph capability
- dynamic_analyst: runtime/VM/sandbox capability (when available)

Rules:
- Decompose the user request into minimal high-value tasks.
- Delegate independent tasks in parallel when possible.
- Keep each delegated task specific and evidence-oriented.
- Synthesize subagent outputs into one concise technical answer.
- Separate confirmed findings from unknowns.
- Never invent tool output.
- Avoid generic executable primers unless explicitly requested.
- For obfuscation claims, require concrete indicators from subagent/tool evidence.
"""


# ----------------------------
# Structured schemas (planner/verifier)
# ----------------------------
class PlanTask(BaseModel):
    id: str = Field(..., description="Unique task ID")
    worker: Literal["static", "dynamic"] = Field(..., description="Which worker role to run")
    objective: str = Field(..., description="Task objective")
    depends_on: List[str] = Field(default_factory=list)
    can_run_parallel: bool = False
    success_criteria: List[str] = Field(default_factory=list)


class ExecutionPlan(BaseModel):
    tasks: List[PlanTask] = Field(default_factory=list)
    final_output_style: str = "technical_markdown"


class VerificationIssue(BaseModel):
    task_id: str
    severity: Literal["low", "medium", "high"]
    problem: str
    required_fix: str


class RetryTask(BaseModel):
    task_id: str
    worker: Literal["static", "dynamic"]
    objective: str


class VerificationVerdict(BaseModel):
    approved: bool
    issues: List[VerificationIssue] = Field(default_factory=list)
    retry_tasks: List[RetryTask] = Field(default_factory=list)


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


# ----------------------------
# Runtime container
# ----------------------------
@dataclass
class MultiAgentRuntime:
    planner: Agent
    static_worker: Agent
    dynamic_worker: Agent
    verifier: Agent
    reporter: Agent
    deep_orchestrator: Optional[Agent]
    deep_deps: Any | None
    all_toolsets: List[MCPServerStdio]
    static_toolsets: List[MCPServerStdio]
    dynamic_toolsets: List[MCPServerStdio]


_RUNTIME: Optional[MultiAgentRuntime] = None


def build_deep_runtime_components(
    static_tools: List[MCPServerStdio],
    dynamic_tools: List[MCPServerStdio],
) -> Tuple[Optional[Agent], Any | None]:
    if create_deep_agent is None or create_default_deps is None:
        return None, None

    subagents: List[Dict[str, Any]] = []
    if static_tools:
        subagents.append(
            {
                "name": "static_analyst",
                "description": "Static reverse-engineering specialist for code, strings, call graphs, and capabilities.",
                "instructions": STATIC_AGENT_INSTRUCTIONS,
                "toolsets": static_tools,
                "preferred_mode": "sync",
                "typical_complexity": "moderate",
            }
        )
    if dynamic_tools:
        subagents.append(
            {
                "name": "dynamic_analyst",
                "description": "Dynamic sandbox/runtime specialist for process/network/runtime behavior.",
                "instructions": DYNAMIC_AGENT_INSTRUCTIONS,
                "toolsets": dynamic_tools,
                "preferred_mode": "auto",
                "typical_complexity": "complex",
            }
        )

    if not subagents:
        return None, None

    history_processors = None
    if create_sliding_window_processor is not None:
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

        if DEEP_INCLUDE_BUNDLED_SKILLS and pydantic_deep_pkg is not None:
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
        print(f"[deep-agent init disabled] {type(e).__name__}: {e}")
        return None, None


def get_runtime_sync() -> MultiAgentRuntime:
    global _RUNTIME
    if _RUNTIME is not None:
        return _RUNTIME

    toolsets = load_mcp_servers("./MCPServers/servers.json")
    static_tools, dynamic_tools = partition_toolsets(toolsets)

    print("Loaded MCP servers:", [s.id for s in toolsets])
    print("Static tools:", [s.id for s in static_tools])
    print("Dynamic tools:", [s.id for s in dynamic_tools])

    # Planner / verifier / reporter do not need MCP toolsets
    planner = Agent(
        OPENAI_MODEL_ID,
        instructions=PLANNER_INSTRUCTIONS,
        output_type=ExecutionPlan,
        retries=PLANNER_AGENT_RETRIES,
        output_retries=PLANNER_OUTPUT_RETRIES,
    )

    static_worker = Agent(
        OPENAI_MODEL_ID,
        instructions=STATIC_AGENT_INSTRUCTIONS,
        toolsets=static_tools,
        retries=WORKER_AGENT_RETRIES,
    )

    dynamic_worker = Agent(
        OPENAI_MODEL_ID,
        instructions=DYNAMIC_AGENT_INSTRUCTIONS,
        toolsets=dynamic_tools,
        retries=WORKER_AGENT_RETRIES,
    )

    verifier = Agent(
        OPENAI_MODEL_ID,
        instructions=VERIFIER_INSTRUCTIONS,
        output_type=VerificationVerdict,
        retries=VERIFIER_AGENT_RETRIES,
        output_retries=VERIFIER_OUTPUT_RETRIES,
    )

    reporter = Agent(
        OPENAI_MODEL_ID,
        instructions=REPORTER_INSTRUCTIONS,
        retries=REPORTER_AGENT_RETRIES,
    )

    deep_orchestrator: Optional[Agent] = None
    deep_deps: Any | None = None
    if USE_DEEP_AGENT:
        deep_orchestrator, deep_deps = build_deep_runtime_components(static_tools, dynamic_tools)
        if deep_orchestrator is not None:
            print("Deep-agent mode: enabled")
            print(
                "Deep config:",
                {
                    "memory": DEEP_ENABLE_MEMORY,
                    "memory_dir": DEEP_MEMORY_DIR,
                    "persist_backend": DEEP_PERSIST_BACKEND,
                    "backend_root": str(Path(DEEP_BACKEND_ROOT).expanduser().resolve()),
                    "skills": DEEP_ENABLE_SKILLS,
                    "skill_dirs": DEEP_SKILL_DIRS,
                    "include_bundled_skills": DEEP_INCLUDE_BUNDLED_SKILLS,
                    "worker_agent_retries": WORKER_AGENT_RETRIES,
                    "deep_agent_retries": DEEP_AGENT_RETRIES,
                },
            )
        else:
            print("Deep-agent mode: unavailable, falling back to classic orchestration")

    _RUNTIME = MultiAgentRuntime(
        planner=planner,
        static_worker=static_worker,
        dynamic_worker=dynamic_worker,
        verifier=verifier,
        reporter=reporter,
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


def append_status(state: Dict[str, Any], message: str, state_lock: Optional[Lock] = None) -> None:
    line = f"[{_status_ts()}] {message}"

    def _commit() -> None:
        lines = (state.get("status_log") or "").splitlines()
        lines.append(line)
        if len(lines) > MAX_STATUS_LOG_LINES:
            lines = lines[-MAX_STATUS_LOG_LINES:]
        state["status_log"] = "\n".join(lines)
        if STATUS_LOG_STDOUT:
            print(line, flush=True)

    if state_lock:
        with state_lock:
            _commit()
    else:
        _commit()


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


def validate_plan(plan: ExecutionPlan, has_dynamic_tools: bool) -> None:
    ids = set()
    for t in plan.tasks:
        if t.id in ids:
            raise ValueError(f"Duplicate task id: {t.id}")
        ids.add(t.id)

        if t.worker == "dynamic" and not has_dynamic_tools:
            raise ValueError("Planner requested dynamic task but no dynamic toolsets are configured.")

    for t in plan.tasks:
        for dep in t.depends_on:
            if dep not in ids:
                raise ValueError(f"Task {t.id} depends on unknown task {dep}")


def topological_batches(tasks: List[PlanTask]) -> List[List[PlanTask]]:
    """
    Small DAG scheduler returning executable batches.
    """
    remaining = {t.id: t for t in tasks}
    done = set()
    batches: List[List[PlanTask]] = []

    while remaining:
        ready = [t for t in remaining.values() if all(dep in done for dep in t.depends_on)]
        if not ready:
            raise ValueError("Cycle detected in plan dependencies")

        parallel = [t for t in ready if t.can_run_parallel]
        serial = [t for t in ready if not t.can_run_parallel]

        if parallel:
            batches.append(parallel)
            for t in parallel:
                done.add(t.id)
                del remaining[t.id]

        for t in serial:
            batches.append([t])
            done.add(t.id)
            del remaining[t.id]

    return batches


# ----------------------------
# Agent execution
# ----------------------------
def run_planner(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> ExecutionPlan:
    role_key = "planner"
    old_history = get_role_history(state, role_key)
    append_status(state, "Planner started")
    t0 = time.perf_counter()

    shared = state.get("shared_state") or {}
    available_workers = ["static"] + (["dynamic"] if runtime.dynamic_toolsets else [])

    planner_input = {
        "user_request": user_text,
        "available_workers": available_workers,
        "tool_inventory": {
            "static": [s.id for s in runtime.static_toolsets],
            "dynamic": [s.id for s in runtime.dynamic_toolsets],
        },
        "analysis_expectations": {
            "avoid_generic_pe_or_memory_primers": True,
            "require_specific_control_flow_artifacts": True,
            "require_specific_obfuscation_indicators": True,
        },
        "shared_state_summary": {
            "artifacts": shared.get("artifacts", []),
            "findings_count": len(shared.get("findings", [])),
            "previous_runs": shared.get("total_task_runs", 0),
        },
    }

    try:
        result = runtime.planner.run_sync(
            json.dumps(planner_input, indent=2),
            message_history=old_history if old_history else None,
        )
    except Exception as e:
        append_status(state, f"Planner failed after {time.perf_counter() - t0:.1f}s: {type(e).__name__}")
        raise
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)  # planner has no tools but harmless

    plan: ExecutionPlan = result.output
    validate_plan(plan, has_dynamic_tools=bool(runtime.dynamic_toolsets))
    append_status(state, f"Planner finished in {time.perf_counter() - t0:.1f}s with {len(plan.tasks)} task(s)")
    return plan


def run_worker_task(
    runtime: MultiAgentRuntime,
    task: PlanTask,
    state: Dict[str, Any],
    role_key_suffix: Optional[str] = None,
    shared_state_snapshot: Optional[Dict[str, Any]] = None,
    isolated_agent: bool = False,
    state_lock: Optional[Lock] = None,
) -> Dict[str, Any]:
    if task.worker == "static":
        role_key_base = "static_worker"
        agent = runtime.static_worker
        if isolated_agent:
            agent = Agent(
                OPENAI_MODEL_ID,
                instructions=STATIC_AGENT_INSTRUCTIONS,
                toolsets=runtime.static_toolsets,
                retries=WORKER_AGENT_RETRIES,
            )
    elif task.worker == "dynamic":
        role_key_base = "dynamic_worker"
        agent = runtime.dynamic_worker
        if isolated_agent:
            agent = Agent(
                OPENAI_MODEL_ID,
                instructions=DYNAMIC_AGENT_INSTRUCTIONS,
                toolsets=runtime.dynamic_toolsets,
                retries=WORKER_AGENT_RETRIES,
            )
    else:
        raise ValueError(f"Unknown worker type: {task.worker}")

    role_key = f"{role_key_base}:{role_key_suffix}" if role_key_suffix else role_key_base
    append_status(
        state,
        f"Worker {task.worker} started [{task.id}] - {_shorten(task.objective)}",
        state_lock=state_lock,
    )
    t0 = time.perf_counter()

    def _read_state() -> Tuple[List[ModelMessage], Dict[str, Any]]:
        old = get_role_history(state, role_key)
        shared = copy.deepcopy(shared_state_snapshot) if shared_state_snapshot is not None else copy.deepcopy(state.get("shared_state") or {})
        return old, shared

    if state_lock:
        with state_lock:
            old_history, shared = _read_state()
    else:
        old_history, shared = _read_state()

    worker_input = {
        "task": task.model_dump(),
        "shared_state": shared,
        "quality_requirements": {
            "no_generic_memory_structure_section": True,
            "obfuscation_claims_must_include_specific_indicators": True,
            "cite_artifacts_for_each_claim": True,
        },
    }

    try:
        result = agent.run_sync(
            json.dumps(worker_input, indent=2),
            message_history=old_history if old_history else None,
        )
    except Exception as e:
        append_status(
            state,
            f"Worker {task.worker} failed [{task.id}] after {time.perf_counter() - t0:.1f}s: {type(e).__name__}",
            state_lock=state_lock,
        )
        raise
    new_history = result.all_messages()

    worker_output_text = str(result.output)

    task_packet = {
        "task_id": task.id,
        "worker": task.worker,
        "objective": task.objective,
        "status": "ok",
        "output_text": worker_output_text,
    }

    def _commit_state() -> None:
        set_role_history(state, role_key, new_history)
        append_tool_log_delta(state, role_key, old_history, new_history)

        if "shared_state" not in state:
            state["shared_state"] = {
                "artifacts": [],
                "findings": [],
                "task_outputs": [],
                "run_count": 0,
                "turn_task_runs": 0,
                "total_task_runs": 0,
            }
        if "task_outputs" not in state["shared_state"]:
            state["shared_state"]["task_outputs"] = []

        state["shared_state"]["task_outputs"].append(task_packet)
        state["shared_state"]["run_count"] = int(state["shared_state"].get("run_count", 0)) + 1
        state["shared_state"]["turn_task_runs"] = int(state["shared_state"].get("turn_task_runs", 0)) + 1
        state["shared_state"]["total_task_runs"] = int(state["shared_state"].get("total_task_runs", 0)) + 1
        compact_shared_state(state)

    if state_lock:
        with state_lock:
            _commit_state()
    else:
        _commit_state()

    append_status(
        state,
        f"Worker {task.worker} finished [{task.id}] in {time.perf_counter() - t0:.1f}s",
        state_lock=state_lock,
    )
    return task_packet


def run_verifier(
    runtime: MultiAgentRuntime,
    user_text: str,
    plan: ExecutionPlan,
    state: Dict[str, Any],
    just_ran_task_ids: List[str],
) -> VerificationVerdict:
    role_key = "verifier"
    old_history = get_role_history(state, role_key)
    ids = ", ".join(just_ran_task_ids) if just_ran_task_ids else "<none>"
    append_status(state, f"Verifier started for task(s): {ids}")
    t0 = time.perf_counter()

    shared = state.get("shared_state") or {}
    verifier_input = {
        "user_request": user_text,
        "plan": plan.model_dump(),
        "just_ran_task_ids": just_ran_task_ids,
        "task_outputs": [
            t for t in shared.get("task_outputs", [])
            if t.get("task_id") in just_ran_task_ids
        ],
    }

    try:
        result = runtime.verifier.run_sync(
            json.dumps(verifier_input, indent=2),
            message_history=old_history if old_history else None,
        )
    except Exception as e:
        append_status(state, f"Verifier failed after {time.perf_counter() - t0:.1f}s: {type(e).__name__}")
        raise
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)

    verdict: VerificationVerdict = result.output
    append_status(
        state,
        (
            f"Verifier finished in {time.perf_counter() - t0:.1f}s "
            f"(approved={verdict.approved}, issues={len(verdict.issues)}, retries={len(verdict.retry_tasks)})"
        ),
    )
    return verdict


def run_reporter(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> str:
    role_key = "reporter"
    old_history = get_role_history(state, role_key)
    append_status(state, "Reporter started")
    t0 = time.perf_counter()

    shared = state.get("shared_state") or {}
    reporter_input = {
        "user_request": user_text,
        "task_outputs": shared.get("task_outputs", []),
        "notes": (
            "Write the final response for the user using only supported information from task outputs. "
            "Avoid generic PE/memory-structure primers unless explicitly requested or directly relevant. "
            "Prioritize specifics: control-flow path, key decision logic, and concrete obfuscation indicators "
            "(functions/APIs/decoded strings/capa rule names) with concise evidence-based interpretation."
        ),
    }

    try:
        result = runtime.reporter.run_sync(
            json.dumps(reporter_input, indent=2),
            message_history=old_history if old_history else None,
        )
    except Exception as e:
        append_status(state, f"Reporter failed after {time.perf_counter() - t0:.1f}s: {type(e).__name__}")
        raise
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)

    assistant_text = str(result.output)
    append_status(state, f"Reporter finished in {time.perf_counter() - t0:.1f}s")
    return assistant_text


def run_deepagent_orchestration(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> str:
    if runtime.deep_orchestrator is None or runtime.deep_deps is None:
        raise RuntimeError("Deep-agent runtime is not configured")

    role_key = "deep_orchestrator"
    old_history = get_role_history(state, role_key)
    append_status(state, "Deep orchestration started")
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


def run_multiagent_orchestration(user_text: str, state: Dict[str, Any]) -> str:
    runtime = get_runtime_sync()
    state_lock = Lock()
    t0 = time.perf_counter()
    append_status(state, "Classic orchestration started")

    cleared_histories = 0
    if "role_histories" in state:
        for key in list((state.get("role_histories") or {}).keys()):
            if key.startswith("static_worker:") or key.startswith("dynamic_worker:"):
                del state["role_histories"][key]
                cleared_histories += 1
    if cleared_histories:
        append_status(state, f"Cleared {cleared_histories} worker branch history entrie(s)")

    # Ensure shared state scaffold exists
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
    state["shared_state"]["orchestration_mode"] = "classic"

    # 1) Planner
    append_status(state, "Transition: init -> planner")
    plan = run_planner(runtime, user_text, state)
    append_status(state, f"Transition: planner -> workers ({len(plan.tasks)} planned task(s))")

    # 2) Execute plan (batch by dependencies)
    batches = topological_batches(plan.tasks)
    if not batches:
        append_status(state, "No worker tasks scheduled; moving directly to reporter")

    for idx, batch in enumerate(batches, start=1):
        batch_desc = ", ".join(f"{t.id}:{t.worker}" for t in batch)
        append_status(state, f"Batch {idx}/{len(batches)} started with {len(batch)} task(s): {batch_desc}")
        just_ran_ids: List[str] = []

        if len(batch) > 1:
            batch_shared_snapshot = copy.deepcopy(state.get("shared_state") or {})
            futures: Dict[str, Future] = {}
            with ThreadPoolExecutor(max_workers=len(batch)) as pool:
                for task in batch:
                    futures[task.id] = pool.submit(
                        run_worker_task,
                        runtime,
                        task,
                        state,
                        task.id,
                        batch_shared_snapshot,
                        True,
                        state_lock,
                    )
                for task in batch:
                    packet = futures[task.id].result()
                    just_ran_ids.append(packet["task_id"])
        else:
            task = batch[0]
            packet = run_worker_task(runtime, task, state, state_lock=state_lock)
            just_ran_ids.append(packet["task_id"])

        # 3) Verifier after each batch
        append_status(state, f"Transition: workers -> verifier for batch {idx}/{len(batches)}")
        verdict = run_verifier(runtime, user_text, plan, state, just_ran_ids)

        # Optional one-pass retry execution
        if verdict.retry_tasks:
            append_status(state, f"Verifier requested {len(verdict.retry_tasks)} retry task(s)")
            for r in verdict.retry_tasks:
                retry_task = PlanTask(
                    id=r.task_id,
                    worker=r.worker,
                    objective=r.objective,
                    depends_on=[],
                    can_run_parallel=False,
                    success_criteria=[],
                )
                append_status(
                    state,
                    f"Retrying task [{retry_task.id}] ({retry_task.worker}) - {_shorten(retry_task.objective)}",
                )
                run_worker_task(runtime, retry_task, state, state_lock=state_lock)
            append_status(state, f"Retry phase finished for batch {idx}/{len(batches)}")
        else:
            append_status(state, f"No retries requested for batch {idx}/{len(batches)}")

    # 4) Reporter
    append_status(state, "Transition: verifier -> reporter")
    final_answer = run_reporter(runtime, user_text, state)
    append_status(state, f"Classic orchestration finished in {time.perf_counter() - t0:.1f}s")
    return final_answer


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

    def _run_selected_orchestrator() -> Tuple[str, str]:
        runtime = get_runtime_sync()
        if USE_DEEP_AGENT and runtime.deep_orchestrator is not None:
            return run_deepagent_orchestration(runtime, user_text, state), "deep"
        return run_multiagent_orchestration(user_text, state), "classic"

    result_box: Dict[str, str] = {"assistant_text": running_note}
    done = Event()

    def _runner() -> None:
        try:
            assistant_text, mode = _run_selected_orchestrator()
            append_status(state, f"Chat turn finished in {time.perf_counter() - turn_t0:.1f}s (mode={mode})")
            result_box["assistant_text"] = assistant_text
            return
        except Exception as e:
            err = str(e)
            if "messages with role 'tool' must be a response to a preceeding message with 'tool_calls'" in err:
                append_status(state, "Detected invalid tool history; clearing role histories and retrying once")
                state["role_histories"] = {}
                try:
                    assistant_text, mode = _run_selected_orchestrator()
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
with gr.Blocks(title="MCP Multi-Agent Tool Bench (PydanticAI)") as demo:
    gr.Markdown("# MCP Multi-Agent Tool Bench (PydanticAI + MCPServerStdio)")
    gr.Markdown("Planner → Worker(s) → Verifier → Reporter")

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
