import os
import json
import asyncio
import getpass
import gradio as gr

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI

# ----------------------------
# Config
# ----------------------------
if not os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter your OpenAI API Key: ")

openai_model_id = "gpt-4o-mini"
# API_URL = None

system_prompt = """You are a malware reverse engineer.
Use your tools to answer questions. If you do not have a tool to
answer the question, say so.

Return only the answer. For example:
Human: What is 1 + 1?
AI: 2
"""

MCP_SERVERS = {
    "ghidramcp": {"transport": "sse", "url": "http://127.0.0.1:8081/sse"},
    "stringmcp": {"transport": "sse", "url": "http://127.0.0.1:8082/sse"},
    "flareflossmcp": {"transport": "sse", "url": "http://127.0.0.1:8083/sse"},
    "hashdbmcp": {"transport": "sse", "url": "http://127.0.0.1:8084/sse",},
    "virtualboxmcp": {"transport": "sse","url": "http://127.0.0.1:8090/sse"},
}

# ----------------------------
# Lazy init (cached agent)
# ----------------------------
_AGENT = None
_INIT_LOCK = asyncio.Lock()

async def get_agent():
    global _AGENT
    async with _INIT_LOCK:
        if _AGENT is not None:
            return _AGENT

        client = MultiServerMCPClient(connections=MCP_SERVERS)
        tools = await client.get_tools()

        llm = ChatOpenAI(
            model=openai_model_id,
            api_key=os.environ["OPENAI_API_KEY"],
            timeout=60,
            max_retries=2,
        )

        # Make tool use explicit/robust
        llm = llm.bind_tools(tools)

        _AGENT = create_agent(
            model=llm,
            tools=tools,
            system_prompt=system_prompt,
        )
        return _AGENT

# ----------------------------
# Helpers
# ----------------------------
def extract_assistant_text(resp) -> str:
    # your earlier pattern: resp["messages"][-1].content
    try:
        last = resp["messages"][-1]
        return getattr(last, "content", str(last))
    except Exception:
        return str(resp)

def extract_tool_log(resp) -> str:
    """
    Best-effort: dump non-user/assistant messages (tool/system) if present.
    Exact structure varies across LangChain versions.
    """
    try:
        msgs = resp.get("messages", [])
        out = []
        for m in msgs:
            role = getattr(m, "type", None) or getattr(m, "role", None) or getattr(m, "name", None)
            content = getattr(m, "content", None)
            if role in ("human", "user", "ai", "assistant"):
                continue
            entry = {"role": role, "content": content}

            ak = getattr(m, "additional_kwargs", None)
            if isinstance(ak, dict) and ak:
                entry["additional_kwargs"] = ak

            out.append(entry)

        return json.dumps(out, indent=2, ensure_ascii=False) if out else ""
    except Exception:
        return ""

# ----------------------------
# Gradio handlers
# ----------------------------
async def chat_turn(user_text, chat_history, state_tool_log):
    user_text = (user_text or "").strip()
    if not user_text:
        return "", chat_history, state_tool_log, state_tool_log

    agent = await get_agent()

    # chat_history is now a list[dict], e.g. {"role":"user","content":"..."}
    chat_history = chat_history or []

    # Build messages for the agent: system + prior chat + new user
    messages = [{"role": "system", "content": system_prompt}] + chat_history
    messages.append({"role": "user", "content": user_text})

    resp = await agent.ainvoke({"messages": messages})
    assistant_text = extract_assistant_text(resp)

    # Update the UI chat history in messages format
    chat_history = chat_history + [
        {"role": "user", "content": user_text},
        {"role": "assistant", "content": assistant_text},
    ]

    tool_blob = extract_tool_log(resp)
    if tool_blob:
        state_tool_log = (state_tool_log + "\n\n" + tool_blob).strip()

    return "", chat_history, state_tool_log, state_tool_log

def reset():
    return [], "", ""

# ----------------------------
# UI
# ----------------------------
with gr.Blocks(title="MCP Agent Tool Bench") as demo:
    gr.Markdown("# MCP Agent Tool Bench")

    # state_messages = gr.State([])   # canonical messages list
    state_tool_log = gr.State("")   # accumulated tool logs

    with gr.Row():
        with gr.Column(scale=3):
            chat = gr.Chatbot(label="Chat", height=330)
            user = gr.Textbox(
                label="Message",
                lines=2,
                placeholder="Ask something. Example: get hashes + executable path + floss strings...",
            )
            with gr.Row():
                send = gr.Button("Send", variant="primary")
                clear = gr.Button("Reset")

        with gr.Column(scale=2):
            gr.Markdown("### Tool / MCP Log (best-effort)")
            tool_log = gr.Code(label="Log", language="json", lines=30)

    send.click(chat_turn, inputs=[user, chat, state_tool_log],
                outputs=[user, chat, state_tool_log, tool_log])
    user.submit(chat_turn, inputs=[user, chat, state_tool_log],
                outputs=[user, chat, state_tool_log, tool_log])
    clear.click(reset, inputs=None, outputs=[chat, state_tool_log, tool_log])

demo.queue()
demo.launch()
