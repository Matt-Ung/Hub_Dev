import os
import sys
import json
import getpass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import gradio as gr

from pydantic_ai import Agent, ModelMessage
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart


# ----------------------------
# Config
# ----------------------------
if not os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter your OpenAI API Key: ")

# PydanticAI model IDs are provider-prefixed strings.
OPENAI_MODEL_ID = os.environ.get("OPENAI_MODEL_ID", "openai:gpt-5-nano")

INSTRUCTIONS = """You are a malware reverse engineer tasked with analyzing obfuscated malware.
Use your MCP tools to answer questions. 

You are analyzing a single binary currently loaded in Ghidra and accessible through the Ghidra MCP tool. You
also have a variety of static analysis tools at your disposal, such as FLOSS for string extraction, and more.
When asked a question, determine which tools to use and in what order. For example, you might first want to run FLOSS to extract strings, 
or run GhidraMCP functions to get decompiled code or call graphs for specific functions. 

You can also use the GhidraMCP tool to navigate the binary, e.g. "list all functions", "get decompilation for function X", "get call graph for function Y", etc.

Your manager will ask you a variety of questions about the malware, such as "what does the entry point do?", "what are the key functions of interest?", "are there any interesting strings?", "what does the call graph look like?", etc. 
Do NOT give an answer that purely explains a section of the assembly instructions line by line. 

If you use tools, include the relevant output from the tools in your answer, and explain how it informs your conclusions.
Return only the answer. 
"""


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

        # MCPServerStdio runs the subprocess and connects over stdio
        # timeout is how long it waits for startup/handshake.
        server = MCPServerStdio(command, args=args, timeout=30, id=name)
        servers.append(server)

    return servers


# ----------------------------
# Lazy init (cached agent)
# ----------------------------
_AGENT: Agent | None = None
_MCP_TOOLSETS: List[MCPServerStdio] | None = None


def get_agent_sync() -> Tuple[Agent, List[MCPServerStdio]]:
    global _AGENT, _MCP_TOOLSETS
    if _AGENT is not None and _MCP_TOOLSETS is not None:
        return _AGENT, _MCP_TOOLSETS

    toolsets = load_mcp_servers("./MCPServers/servers.json")
    print("Loaded MCP servers:", [s.id for s in toolsets])

    agent = Agent(
        OPENAI_MODEL_ID,
        instructions=INSTRUCTIONS,
        toolsets=toolsets,
    )

    _AGENT = agent
    _MCP_TOOLSETS = toolsets
    return agent, toolsets


# ----------------------------
# Tool log extraction (best-effort)
# ----------------------------
def extract_tool_log_from_messages(messages: List[ModelMessage]) -> str:
    """
    Walk the message stream and pull out tool calls + tool returns.
    This is meant for debugging / UI visibility, not as a stable format.
    """
    out: List[Dict[str, Any]] = []

    for m in messages:
        # ModelRequest: may contain tool returns (rare), but mostly user prompt + tool returns
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

        # ModelResponse: may contain tool calls and/or assistant text
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


# ----------------------------
# Gradio handlers
# ----------------------------
def chat_turn(user_text: str, chat_history: List[Dict[str, str]], state: Dict[str, Any]):
    user_text = (user_text or "").strip()
    if not user_text:
        return "", chat_history, state, state.get("tool_log", "")

    agent, _toolsets = get_agent_sync()

    chat_history = chat_history or []
    state = state or {}

    # Persist PydanticAI message history (stateful across turns)
    message_history: List[ModelMessage] = state.get("message_history") or []

    # Run one turn; store the updated full history for the next turn
    # PydanticAI supports passing prior messages via message_history to maintain continuity. :contentReference[oaicite:2]{index=2}
    result = agent.run_sync(user_text, message_history=message_history if message_history else None)

    assistant_text = result.output
    new_history = result.all_messages()

    # Update UI chat
    chat_history = chat_history + [
        {"role": "user", "content": user_text},
        {"role": "assistant", "content": assistant_text},
    ]

    # Update state
    state["message_history"] = new_history

    # Append tool log
    tool_blob = extract_tool_log_from_messages(new_history)
    if tool_blob:
        prev = (state.get("tool_log") or "").strip()
        state["tool_log"] = (prev + "\n\n" + tool_blob).strip() if prev else tool_blob

    return "", chat_history, state, state.get("tool_log", "")


def reset():
    return [], {"message_history": [], "tool_log": ""}, ""


# ----------------------------
# UI
# ----------------------------
with gr.Blocks(title="MCP Agent Tool Bench (PydanticAI)") as demo:
    gr.Markdown("# MCP Agent Tool Bench (PydanticAI + MCPServerStdio)")

    state = gr.State({"message_history": [], "tool_log": ""})

    with gr.Row():
        with gr.Column(scale=3):
            chat = gr.Chatbot(label="Chat", height=330)
            user = gr.Textbox(
                label="Message",
                lines=2,
                placeholder="Ask something. Example: build call graph from entry, summarize key functions...",
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