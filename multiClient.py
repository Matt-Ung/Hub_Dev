# multiClient.py
# Base implementation of a multi-client orchestrator that manages multiple specialized agents
# for different tasks, coordinating their actions to achieve a common goal.
# This will connect to implemented FASTMCP servers and route tasks accordingly.

import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
import os
import getpass

if ("OPENAI_API_KEY" not in os.environ) or (not os.environ["OPENAI_API_KEY"]):
    os.environ["OPENAI_API_KEY"] = getpass.getpass("Enter your OpenAI API Key: ")

openai_model_id = "gpt-4o-mini-2024-07-18"
imp_model_id = "gpt-5-mini"
openai_embmodel_id = "azure/text-embedding-3-small"
API_URL = "https://ai-gateway.andrew.cmu.edu/"

system_prompt = """You are a malware reverse engineer.
Use your tools to answer questions. If you do not have a tool to
answer the question, say so.

Return only the answer. For example:
Human: What is 1 + 1?
AI: 2
"""

# BASE_URL = "https://hashdb.openanalysis.net"
# HUNT_URL = f"{BASE_URL}/hunt"
# HASH_URL = f"{BASE_URL}/hash"


async def main():
    client = MultiServerMCPClient(
        {
            "ghidramcp": {
                "transport": "sse",
                "url": "http://127.0.0.1:8081/sse",
            },

            # Optional: add more MCP servers here
            # LangChain docs show HTTP/streamable-http as transport "http" with a /mcp URL. :contentReference[oaicite:3]{index=3}
            # "weather": {"transport": "http", "url": "http://localhost:8000/mcp"},
        },
        tool_name_prefix=True,  # avoids tool-name collisions across servers
    )

    tools = await client.get_tools()

    llm_OPENAI = ChatOpenAI(
        model=openai_model_id,
        api_key=os.environ["OPENAI_API_KEY"],
        base_url=API_URL
    )

    agent_openAI = create_agent(
        model=llm_OPENAI,
        tools=tools,
        system_prompt=system_prompt,
    )

    resp = await agent_openAI.ainvoke({
        "messages": [
            {"role": "user", "content": "Use ghidramcp tools to complete 3 tasks: 1) get file hashes (md5 and sha256) 2) get executable path, and 3) get the current function and decompile it, then summarize it."}
        ]
    })
    # print(resp)
    try:
        print(resp["messages"][-1].content)
    except Exception:
        print(resp)

asyncio.run(main())
