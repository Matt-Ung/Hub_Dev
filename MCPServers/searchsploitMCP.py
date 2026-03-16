#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: exploitation/searchsploit-mcp/server.py

This version is rewritten into the lightweight FastMCP wrapper style used by
the local MCPServers/ directory.
"""

import json
import logging
from typing import Any

from fastmcp import FastMCP

from _cli_mcp_common import (
    has_command,
    run_command,
    run_help_command,
    run_server,
    truncate_text,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "searchsploit_mcp",
    instructions="MCP server that exposes structured SearchSploit lookup tools.",
)


def _parse_searchsploit_json(output: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(output or "{}")
    except json.JSONDecodeError:
        return []

    exploits: list[dict[str, Any]] = []
    for item in payload.get("RESULTS_EXPLOIT", []) or []:
        if not isinstance(item, dict):
            continue
        exploits.append(
            {
                "title": item.get("Title"),
                "edb_id": item.get("EDB-ID"),
                "date": item.get("Date"),
                "author": item.get("Author"),
                "platform": item.get("Platform"),
                "type": item.get("Type"),
                "path": item.get("Path"),
            }
        )
    return exploits


@mcp.tool()
def searchsploitSearch(
    query: str,
    exact: bool = False,
    exclude: list[str] | None = None,
    timeout_sec: int = 60,
) -> dict[str, Any]:
    """Search Exploit-DB offline with SearchSploit."""
    if not query.strip():
        return {"ok": False, "error": "query cannot be empty"}
    if not has_command("searchsploit"):
        return {"ok": False, "error": "searchsploit not found on PATH"}

    try:
        cmd = ["searchsploit", "-j"]
        if exact:
            cmd.append("-e")
        for term in exclude or []:
            cmd.extend(["--exclude", term])
        cmd.append(query)

        result = run_command(cmd, timeout_sec=timeout_sec)
        exploits = _parse_searchsploit_json(result.stdout or "")

        by_platform: dict[str, int] = {}
        by_type: dict[str, int] = {}
        for exploit in exploits:
            if exploit.get("platform"):
                platform = str(exploit["platform"])
                by_platform[platform] = by_platform.get(platform, 0) + 1
            if exploit.get("type"):
                exp_type = str(exploit["type"])
                by_type[exp_type] = by_type.get(exp_type, 0) + 1

        return {
            "ok": result.returncode == 0,
            "rc": result.returncode,
            "command": cmd,
            "query": query,
            "exact": exact,
            "exclude": exclude or [],
            "stats": {
                "exploit_count": len(exploits),
                "by_platform": by_platform,
                "by_type": by_type,
            },
            "exploits": exploits[:100],
            "stdout": truncate_text(result.stdout or "", max_chars=16000),
            "stderr": truncate_text(result.stderr or "", max_chars=4000),
        }
    except Exception as e:
        logger.exception("searchsploitSearch failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def searchsploitExamine(edb_id: str, timeout_sec: int = 30, max_chars: int = 20000) -> dict[str, Any]:
    """Retrieve the content of a specific exploit by EDB-ID."""
    if not edb_id.strip():
        return {"ok": False, "error": "edb_id cannot be empty"}
    if not has_command("searchsploit"):
        return {"ok": False, "error": "searchsploit not found on PATH"}

    try:
        cmd = ["searchsploit", "-x", edb_id]
        result = run_command(cmd, timeout_sec=timeout_sec)
        return {
            "ok": result.returncode == 0,
            "rc": result.returncode,
            "command": cmd,
            "edb_id": edb_id,
            "content": truncate_text(result.stdout or "", max_chars=max_chars),
            "stderr": truncate_text(result.stderr or "", max_chars=4000),
        }
    except Exception as e:
        logger.exception("searchsploitExamine failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def searchsploitHelp(timeout_sec: int = 5) -> str:
    """Return `searchsploit --help` output."""
    return run_help_command("searchsploit", timeout_sec=timeout_sec)


def main() -> None:
    run_server(mcp, description="MCP server for SearchSploit", default_port=8094)


if __name__ == "__main__":
    main()
