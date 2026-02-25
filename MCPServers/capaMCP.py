#!/usr/bin/env python3
"""
capaMCP_thesis.py

FastMCP server that exposes Mandiant capa via:
- runCapa(command: str, rules_dir: Optional[str] = None): execute a caller-supplied capa command string (argv[0] must be capa)
  - If rules_dir is not provided, the server will try:
      1) CAPA_RULES_DIR env var
      2) ./MCPServers/capa-rules (relative to CWD)
      3) MCPServers/capa-rules relative to this file (and one directory up)
  - If a rules directory is found and the command does NOT already include -r/--rules, the server injects -r <rules_dir>.
- capaHelp(): returns `capa --help` output for flag discovery

Notes:
- Uses subprocess with shell=False (argv is parsed via shlex).
- Intentionally lightweight and "run/help"-only, mirroring flareFlossMCP.py.
"""

import argparse
import logging
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "capa_mcp",
    instructions="MCP server that executes Mandiant capa from a provided command string (with optional rules dir injection).",
)

# ----------------------------
# Command parsing + validation
# ----------------------------

def _split_command(command: str) -> List[str]:
    command = (command or "").strip()
    if not command:
        return []
    
    return shlex.split(command, posix=True)


def _is_capa_argv0(argv0: str) -> bool:
    if not argv0:
        return False
    base = os.path.basename(argv0).lower()
    return base in ("capa", "capa.exe")


def _find_rules_dir(user_rules_dir: Optional[str]) -> Optional[str]:
    """
    Resolve rules directory (best-effort):
      - explicit tool arg wins
      - then CAPA_RULES_DIR env var
      - then ./MCPServers/capa-rules relative to CWD
      - then MCPServers/capa-rules relative to this file (and one directory up)
    Returns an absolute path string if found and looks like a directory; otherwise None.
    """
    candidates: List[Path] = []

    if user_rules_dir and str(user_rules_dir).strip():
        candidates.append(Path(os.path.expandvars(os.path.expanduser(str(user_rules_dir).strip()))))

    env = os.environ.get("CAPA_RULES_DIR")
    if env and env.strip():
        candidates.append(Path(os.path.expandvars(os.path.expanduser(env.strip()))))

    # Relative to CWD
    candidates.append(Path.cwd() / "MCPServers" / "capa-rules")

    # Relative to this file
    here = Path(__file__).resolve().parent
    candidates.append(here / "MCPServers" / "capa-rules")
    candidates.append(here.parent / "MCPServers" / "capa-rules")
    candidates.append(here / "capa-rules")
    candidates.append(here.parent / "capa-rules")

    for c in candidates:
        try:
            if c.exists() and c.is_dir():
                return str(c.resolve())
        except Exception:
            continue
    return None


def _argv_has_rules_flag(argv: List[str]) -> bool:
    # cheap check: handles "-r PATH" and "--rules PATH" and "-rPATH"
    for a in argv:
        if a == "-r" or a.startswith("-r"):
            return True
        if a == "--rules" or a.startswith("--rules="):
            return True
    return False


def _inject_rules(argv: List[str], rules_dir: Optional[str]) -> List[str]:
    """If rules_dir is available and argv does not already specify rules, inject "-r <rules_dir>"."""
    if not rules_dir:
        return argv
    if _argv_has_rules_flag(argv):
        return argv
    if len(argv) < 1:
        return argv
    return [argv[0], "-r", rules_dir] + argv[1:]


def _try_get_capa_help(timeout_sec: int = 3, max_chars: int = 1800) -> Optional[str]:
    """Best-effort: capture a short snippet of `capa --help` to embed into tool descriptions."""
    try:
        r = subprocess.run(
            ["capa", "--help"],
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


_HELP_SNIPPET = _try_get_capa_help()

RUN_CAPA_DESCRIPTION = (
    "Execute Mandiant capa using a caller-supplied command string.\n\n"
    "Usage:\n"
    "  - Provide the FULL command as one string (e.g., `capa -j -- sample.exe`).\n"
    "  - argv[0] must be `capa` (or `capa.exe`).\n"
    "  - If you pass rules_dir (or the server finds ./MCPServers/capa-rules), and your command does not include -r/--rules,\n"
    "    the server will inject `-r <rules_dir>` automatically.\n"
    "  - For the full flag list, call `capaHelp` (runs `capa --help`).\n\n"
    "Notes:\n"
    "  - Execution uses subprocess with shell=False (argv is parsed via shlex).\n"
)

if _HELP_SNIPPET:
    RUN_CAPA_DESCRIPTION += "\nCAPA --help (snippet):\n" + _HELP_SNIPPET


# ----------------------------
# MCP tools
# ----------------------------

@mcp.tool(description=RUN_CAPA_DESCRIPTION)
def runCapa(command: str, rules_dir: Optional[str] = None, timeout_sec: int = 300) -> str:
    """Execute capa and return a human-readable result summary."""
    try:
        argv = _split_command(command)
        if not argv:
            return "Error: empty command string."

        if not _is_capa_argv0(argv[0]):
            return f"Error: first argument must be 'capa' (or 'capa.exe'). Got: {argv[0]!r}"

        resolved_rules = _find_rules_dir(rules_dir)
        argv = _inject_rules(argv, resolved_rules)

        r = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        
        cmd_str = " ".join(shlex.quote(a) for a in argv)

        return (
            "capa execution complete.\n"
            f"rc={r.returncode}\n"
            f"rules_dir={'(none)' if not resolved_rules else resolved_rules}\n"
            f"command={cmd_str}\n"
            "stdout:\n"
            f"{r.stdout or ''}\n"
            "stderr:\n"
            f"{r.stderr or ''}"
        )

    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        return (
            "Error: capa execution timed out.\n"
            f"timeout_sec={timeout_sec}\n"
            "stdout:\n"
            f"{out}\n"
            "stderr:\n"
            f"{err}"
        )
    except FileNotFoundError:
        return "Error: `capa` not found on PATH. Install capa and ensure `capa` is on PATH."
    except Exception as e:
        logger.exception("runCapa failed")
        return f"Error: {e}"


@mcp.tool(description="Return capa CLI help output (runs `capa --help`) so clients can discover flags.")
def capaHelp(timeout_sec: int = 5) -> str:
    try:
        r = subprocess.run(
            ["capa", "--help"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        return (
            "capa --help\n"
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
            "Error: `capa --help` timed out.\n"
            f"timeout_sec={timeout_sec}\n"
            "stdout:\n"
            f"{out}\n"
            "stderr:\n"
            f"{err}"
        )
    except FileNotFoundError:
        return "Error: `capa` not found on PATH. Install capa and ensure `capa` is on PATH."
    except Exception as e:
        logger.exception("capaHelp failed")
        return f"Error: {e}"


# ----------------------------
# CLI / main (server args only)
# ----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for capa (thesis tool)")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8090,
        help="Port to run MCP server on (only used for sse), default: 8090",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol for MCP, default: stdio",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level, default: INFO",
    )
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level, logging.INFO)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    logger.info(f"sys.platform={sys.platform} transport={args.transport}")

    if args.transport == "sse":
        try:
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8090
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
