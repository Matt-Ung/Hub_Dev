#!/usr/bin/env python3
"""
flareFlossMCP.py

FastMCP server that exposes FLOSS via:
- runFloss(command: str): execute a caller-supplied FLOSS command string (argv[0] must be floss)
- flossHelp(): returns `floss --help` output for flag discovery
"""

import argparse
import logging
import os
import shlex
import subprocess
import sys
from typing import List, Optional

from fastmcp import FastMCP

logger = logging.getLogger(__name__)
mcp = FastMCP(
    "flare_floss_mcp",
    instructions="MCP server that executes FLOSS (flare-floss) from a provided command string.",
)

# ----------------------------
# Command parsing + validation
# ----------------------------
def _split_command(command: str) -> List[str]:
    command = (command or "").strip()
    if not command:
        return []
    if os.name == "nt":
        return shlex.split(command, posix=False)
    return shlex.split(command, posix=True)


def _is_floss_argv0(argv0: str) -> bool:
    if not argv0:
        return False
    base = os.path.basename(argv0).lower()
    return base in ("floss", "floss.exe")


def _try_get_floss_help(timeout_sec: int = 3, max_chars: int = 1800) -> Optional[str]:
    """
    Best-effort: capture a *short* snippet of `floss --help` to embed into tool descriptions.
    If FLOSS isn't installed/accessible, return None.
    """
    try:
        r = subprocess.run(
            ["floss", "--help"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        text = (r.stdout or "") + ("\n" + (r.stderr or "") if (r.stderr or "").strip() else "")
        text = text.strip()
        if not text:
            return None
        if len(text) > max_chars:
            text = text[:max_chars] + "\n...[truncated]..."
        return text
    except Exception:
        return None


_HELP_SNIPPET = _try_get_floss_help()

RUN_FLOSS_DESCRIPTION = (
    "Execute FLOSS using a caller-supplied command string.\n\n"
    "Usage:\n"
    "  - Provide the FULL command as one string (e.g., `floss -j -n 6 -- sample.exe`).\n"
    "  - This server does not parse/validate flags beyond checking argv[0] is `floss`.\n"
    "  - For the full flag list, call the `flossHelp` tool (runs `floss --help`).\n\n"
    "Notes:\n"
    "  - Execution uses subprocess with shell=False (argv is parsed via shlex).\n"
    "  - Consider including `-j/--json` in your command if you want machine-readable output.\n"
)

if _HELP_SNIPPET:
    RUN_FLOSS_DESCRIPTION += "\nFLOSS --help (snippet):\n" + _HELP_SNIPPET


# ----------------------------
# MCP tools
# ----------------------------
@mcp.tool(description=RUN_FLOSS_DESCRIPTION)
def runFloss(command: str, timeout_sec: int = 300) -> str:
    """
    (Docstring is not used if description= is provided above.)
    """
    try:
        argv = _split_command(command)
        if not argv:
            return "Error: empty command string."

        if not _is_floss_argv0(argv[0]):
            return f"Error: first argument must be 'floss' (or 'floss.exe'). Got: {argv[0]!r}"

        r = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )

        return (
            "FLOSS execution complete.\n"
            f"rc={r.returncode}\n"
            "stdout:\n"
            f"{r.stdout or ''}\n"
            "stderr:\n"
            f"{r.stderr or ''}"
        )

    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        return (
            "Error: FLOSS execution timed out.\n"
            f"timeout_sec={timeout_sec}\n"
            "stdout:\n"
            f"{out}\n"
            "stderr:\n"
            f"{err}"
        )
    except Exception as e:
        logger.exception("runFloss failed")
        return f"Error: {e}"


@mcp.tool(description="Return FLOSS CLI help output (runs `floss --help`) so clients can discover flags.")
def flossHelp(timeout_sec: int = 5) -> str:
    try:
        r = subprocess.run(
            ["floss", "--help"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        return (
            "floss --help\n"
            f"rc={r.returncode}\n"
            "stdout:\n"
            f"{r.stdout or ''}\n"
            "stderr:\n"
            f"{r.stderr or ''}"
        )
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        return (
            "Error: `floss --help` timed out.\n"
            f"timeout_sec={timeout_sec}\n"
            "stdout:\n"
            f"{out}\n"
            "stderr:\n"
            f"{err}"
        )
    except FileNotFoundError:
        return "Error: `floss` not found on PATH. Install with `pip install flare-floss` (Python >= 3.10)."
    except Exception as e:
        logger.exception("flossHelp failed")
        return f"Error: {e}"


# ----------------------------
# CLI / main (server args only)
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="MCP server for FLOSS (flare-floss)")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8083,
                        help="Port to run MCP server on (only used for sse), default: 8083")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Logging level, default: INFO")
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level, logging.INFO)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    logger.info(f"sys.platform={sys.platform} transport={args.transport}")

    if args.transport == "sse":
        try:
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8083
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
