import os
import sys
import json
import getpass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional, Literal
from dataclasses import dataclass

import gradio as gr
from pydantic import BaseModel, Field

from pydantic_ai import Agent, ModelMessage
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart


# ----------------------------
# Config
# ----------------------------
if not os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter your OpenAI API Key: ")

OPENAI_MODEL_ID = os.environ.get("OPENAI_MODEL_ID", "openai:gpt-4o-mini")


# ----------------------------
# Role prompts
# ----------------------------
PLANNER_INSTRUCTIONS = """You are PlannerAgent for a malware analysis workflow.

Your job is to decompose the user's request into a minimal set of worker tasks.

Rules:
- Do NOT perform the analysis yourself.
- Do NOT write the final answer.
- Assign each task to one worker role from the provided list.
- Prefer parallelizable tasks only when independent.
- Keep the plan compact and high value.
- Return only structured data matching the schema.
"""

STATIC_AGENT_INSTRUCTIONS = """You are StaticAnalysisAgent (reverse engineering specialist).

You may use ONLY static-analysis tools available through MCP (e.g., Ghidra, strings/FLOSS, HashDB, capa-static if present).

Rules:
- Produce evidence-grounded results only.
- Do not speculate beyond available evidence.
- Return concise technical findings suitable for a verifier to review.
"""

DYNAMIC_AGENT_INSTRUCTIONS = """You are DynamicAnalysisAgent (sandbox/runtime specialist).

You may use ONLY dynamic-analysis tools available through MCP (e.g., VM tools, ProcMon, Wireshark, runtime execution tools).

Rules:
- Produce evidence-grounded runtime findings only.
- If a requested action cannot be completed, explain precisely what failed.
- Return concise technical findings suitable for a verifier to review.
"""

VERIFIER_INSTRUCTIONS = """You are VerifierAgent.

You review worker outputs for:
- unsupported claims
- missing evidence
- contradictions
- obvious gaps relative to the user request

Return a structured verdict:
- approved (bool)
- issues (list)
- retry_tasks (precise rework tasks only if needed)

Do not write the final user-facing answer.
"""

REPORTER_INSTRUCTIONS = """You are ReporterAgent.

Write the final answer to the user using only the verified outputs from workers.

Style:
- technical, clear, concise
- separate confirmed findings vs unknowns when relevant
- do not invent tool results
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
    all_toolsets: List[MCPServerStdio]
    static_toolsets: List[MCPServerStdio]
    dynamic_toolsets: List[MCPServerStdio]


_RUNTIME: Optional[MultiAgentRuntime] = None


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
        result_type=ExecutionPlan,
    )

    static_worker = Agent(
        OPENAI_MODEL_ID,
        instructions=STATIC_AGENT_INSTRUCTIONS,
        toolsets=static_tools,
    )

    dynamic_worker = Agent(
        OPENAI_MODEL_ID,
        instructions=DYNAMIC_AGENT_INSTRUCTIONS,
        toolsets=dynamic_tools,
    )

    verifier = Agent(
        OPENAI_MODEL_ID,
        instructions=VERIFIER_INSTRUCTIONS,
        result_type=VerificationVerdict,
    )

    reporter = Agent(
        OPENAI_MODEL_ID,
        instructions=REPORTER_INSTRUCTIONS,
    )

    _RUNTIME = MultiAgentRuntime(
        planner=planner,
        static_worker=static_worker,
        dynamic_worker=dynamic_worker,
        verifier=verifier,
        reporter=reporter,
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
    state["tool_log"] = (prev + "\n\n" + tagged).strip() if prev else tagged


# ----------------------------
# Multi-agent shared state helpers
# ----------------------------
def get_role_history(state: Dict[str, Any], role_key: str) -> List[ModelMessage]:
    return (state.get("role_histories") or {}).get(role_key, []) or []


def set_role_history(state: Dict[str, Any], role_key: str, history: List[ModelMessage]) -> None:
    if "role_histories" not in state:
        state["role_histories"] = {}
    state["role_histories"][role_key] = history


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

    shared = state.get("shared_state") or {}
    available_workers = ["static"] + (["dynamic"] if runtime.dynamic_toolsets else [])

    planner_input = {
        "user_request": user_text,
        "available_workers": available_workers,
        "tool_inventory": {
            "static": [s.id for s in runtime.static_toolsets],
            "dynamic": [s.id for s in runtime.dynamic_toolsets],
        },
        "shared_state_summary": {
            "artifacts": shared.get("artifacts", []),
            "findings_count": len(shared.get("findings", [])),
            "previous_runs": shared.get("run_count", 0),
        },
    }

    result = runtime.planner.run_sync(
        json.dumps(planner_input, indent=2),
        message_history=old_history if old_history else None,
    )
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)  # planner has no tools but harmless

    plan: ExecutionPlan = result.output
    validate_plan(plan, has_dynamic_tools=bool(runtime.dynamic_toolsets))
    return plan


def run_worker_task(
    runtime: MultiAgentRuntime,
    task: PlanTask,
    state: Dict[str, Any],
) -> Dict[str, Any]:
    if task.worker == "static":
        agent = runtime.static_worker
        role_key = "static_worker"
    elif task.worker == "dynamic":
        agent = runtime.dynamic_worker
        role_key = "dynamic_worker"
    else:
        raise ValueError(f"Unknown worker type: {task.worker}")

    old_history = get_role_history(state, role_key)

    shared = state.get("shared_state") or {}
    worker_input = {
        "task": task.model_dump(),
        "shared_state": shared,
    }

    result = agent.run_sync(
        json.dumps(worker_input, indent=2),
        message_history=old_history if old_history else None,
    )
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)

    worker_output_text = str(result.output)

    task_packet = {
        "task_id": task.id,
        "worker": task.worker,
        "objective": task.objective,
        "status": "ok",
        "output_text": worker_output_text,
    }

    # Store in shared state for verifier/reporter
    if "shared_state" not in state:
        state["shared_state"] = {"artifacts": [], "findings": [], "task_outputs": [], "run_count": 0}
    if "task_outputs" not in state["shared_state"]:
        state["shared_state"]["task_outputs"] = []

    state["shared_state"]["task_outputs"].append(task_packet)
    state["shared_state"]["run_count"] = int(state["shared_state"].get("run_count", 0)) + 1

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

    result = runtime.verifier.run_sync(
        json.dumps(verifier_input, indent=2),
        message_history=old_history if old_history else None,
    )
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)

    verdict: VerificationVerdict = result.output
    return verdict


def run_reporter(runtime: MultiAgentRuntime, user_text: str, state: Dict[str, Any]) -> str:
    role_key = "reporter"
    old_history = get_role_history(state, role_key)

    shared = state.get("shared_state") or {}
    reporter_input = {
        "user_request": user_text,
        "task_outputs": shared.get("task_outputs", []),
        "notes": "Write the final response for the user. Use only supported information from task outputs.",
    }

    result = runtime.reporter.run_sync(
        json.dumps(reporter_input, indent=2),
        message_history=old_history if old_history else None,
    )
    new_history = result.all_messages()
    set_role_history(state, role_key, new_history)
    append_tool_log_delta(state, role_key, old_history, new_history)

    return str(result.output)


def run_multiagent_orchestration(user_text: str, state: Dict[str, Any]) -> str:
    runtime = get_runtime_sync()

    # Ensure shared state scaffold exists
    if "shared_state" not in state:
        state["shared_state"] = {
            "artifacts": [],
            "findings": [],
            "task_outputs": [],
            "run_count": 0,
        }

    # 1) Planner
    plan = run_planner(runtime, user_text, state)

    # 2) Execute plan (batch by dependencies)
    batches = topological_batches(plan.tasks)

    for batch in batches:
        just_ran_ids: List[str] = []

        # If you want real concurrency later, this is where you'd parallelize.
        for task in batch:
            packet = run_worker_task(runtime, task, state)
            just_ran_ids.append(packet["task_id"])

        # 3) Verifier after each batch
        verdict = run_verifier(runtime, user_text, plan, state, just_ran_ids)

        # Optional one-pass retry execution
        if verdict.retry_tasks:
            for r in verdict.retry_tasks:
                retry_task = PlanTask(
                    id=r.task_id,
                    worker=r.worker,
                    objective=r.objective,
                    depends_on=[],
                    can_run_parallel=False,
                    success_criteria=[],
                )
                run_worker_task(runtime, retry_task, state)

    # 4) Reporter
    final_answer = run_reporter(runtime, user_text, state)
    return final_answer


# ----------------------------
# Gradio handlers
# ----------------------------
def chat_turn(user_text: str, chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    user_text = (user_text or "").strip()
    if not user_text:
        return "", chat_history, state, state.get("tool_log", "")

    chat_history = chat_history or []
    state = state or {}

    # Make sure state keys exist
    state.setdefault("role_histories", {})
    state.setdefault("tool_log", "")
    state.setdefault("shared_state", {
        "artifacts": [],
        "findings": [],
        "task_outputs": [],
        "run_count": 0,
    })

    try:
        assistant_text = run_multiagent_orchestration(user_text, state)
    except Exception as e:
        assistant_text = f"[multi-agent orchestration error] {type(e).__name__}: {e}"

    # Update UI chat
    chat_history = chat_history + [
        {"role": "user", "content": user_text},
        {"role": "assistant", "content": assistant_text},
    ]

    return "", chat_history, state, state.get("tool_log", "")


def reset():
    return [], {
        "role_histories": {},
        "tool_log": "",
        "shared_state": {
            "artifacts": [],
            "findings": [],
            "task_outputs": [],
            "run_count": 0,
        },
    }, ""


# ----------------------------
# UI
# ----------------------------
with gr.Blocks(title="MCP Multi-Agent Tool Bench (PydanticAI)") as demo:
    gr.Markdown("# MCP Multi-Agent Tool Bench (PydanticAI + MCPServerStdio)")
    gr.Markdown("Planner → Worker(s) → Verifier → Reporter")

    state = gr.State({
        "role_histories": {},
        "tool_log": "",
        "shared_state": {
            "artifacts": [],
            "findings": [],
            "task_outputs": [],
            "run_count": 0,
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
            gr.Markdown("### Tool / MCP Log (best-effort)")
            tool_log = gr.Code(label="Log", language="json", lines=30)

    send.click(chat_turn, inputs=[user, chat, state], outputs=[user, chat, state, tool_log])
    user.submit(chat_turn, inputs=[user, chat, state], outputs=[user, chat, state, tool_log])
    clear.click(reset, inputs=None, outputs=[chat, state, tool_log])

demo.queue()
demo.launch()