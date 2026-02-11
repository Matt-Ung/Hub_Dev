#!/usr/bin/env python3
"""
strings_mcp.py

FastMCP server that exposes a `callStrings(file_path)` tool.

Key features:
- Cross-platform detection (Windows/Linux/macOS)
- Path normalization (fixes `/C:/...` and `/mnt/c/...` cases)
- Uses native `strings` if available; on Windows can fall back to WSL `strings`
- Improved subprocess error reporting (stdout/stderr/return code)
- Preserves your existing argparse CLI:
    --transport {stdio,sse}
    --mcp-host
    --mcp-port
"""

import argparse
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("strings_mcp", instructions="MCP server that provides 'strings' functionality.")


# ----------------------------
# Platform + path normalization
# ----------------------------
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"

_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")          # "/C:/Users/..." (MSYS-style)
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")     # "/mnt/c/Users/..." (WSL-style)

def normalize_path_for_windows(p: str) -> str:
    """
    Convert common pseudo-posix paths into a Windows-friendly path string:
      - "/C:/Users/x" -> "C:/Users/x"
      - "/mnt/c/Users/x" -> "C:\\Users\\x"
    """
    p = (p or "").strip()
    if not p:
        return p

    m = _DRIVE_RE.match(p)
    if m:
        # "/C:/..." -> "C:/..."
        return p[1:]

    m = _MNT_RE.match(p)
    if m:
        drive = m.group(1).upper()
        rest = m.group(2).replace("/", "\\")
        return f"{drive}:\\{rest}"

    return p


def normalize_path_for_wsl(p: str) -> str:
    """
    Convert Windows path to WSL path:
      - "C:\\Users\\x" or "C:/Users/x" -> "/mnt/c/Users/x"
    If already looks posix, return as-is.
    """
    p = (p or "").strip()
    if not p:
        return p

    p2 = p.replace("\\", "/")
    if len(p2) >= 3 and p2[1] == ":" and p2[2] == "/":
        drive = p2[0].lower()
        rest = p2[3:]
        return f"/mnt/{drive}/{rest}"

    return p2

def has_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def can_run_wsl() -> bool:
    return IS_WINDOWS and has_cmd("wsl")


def file_exists(p: str) -> bool:
    try:
        return Path(p).exists()
    except Exception:
        return False

# ----------------------------
# strings invocation
# ----------------------------
def _run_subprocess(cmd: list) -> Tuple[int, str, str]:
    """
    Run a command and capture output, always returning (returncode, stdout, stderr).
    """
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
    )
    return r.returncode, r.stdout or "", r.stderr or ""


def run_strings(file_path: str, min_len: int = 4) -> str:
    """
    Try to run `strings` in a platform-aware way.
    Returns stdout on success; raises RuntimeError on failure (with details).
    """
    if not file_path or not str(file_path).strip():
        raise RuntimeError("empty file_path")

    fp_in = str(file_path).strip()

    if IS_WINDOWS:
        fp_win = normalize_path_for_windows(fp_in)

        if not file_exists(fp_win):
            fp_alt = fp_win.replace("\\", "/")
            if file_exists(fp_alt):
                fp_win = fp_alt
            else:
                raise RuntimeError(f"file not found: {fp_win}")

        if has_cmd("strings"):
            cmd1 = ["strings", "-n", str(min_len), fp_win]
            rc, out, err = _run_subprocess(cmd1)
            if rc == 0:
                return out

            cmd2 = ["strings", fp_win]
            rc2, out2, err2 = _run_subprocess(cmd2)
            if rc2 == 0:
                return out2

            last = (cmd2, rc2, err2[:500])
        else:
            last = (["strings", fp_win], -1, "strings not found on PATH")

        # 2) Fallback to WSL strings if available
        if can_run_wsl():
            fp_wsl = normalize_path_for_wsl(fp_win)
            cmd = ["wsl", "strings", "-n", str(min_len), fp_wsl]
            rc, out, err = _run_subprocess(cmd)
            if rc == 0:
                return out

            # fallback without -n
            cmd2 = ["wsl", "strings", fp_wsl]
            rc2, out2, err2 = _run_subprocess(cmd2)
            if rc2 == 0:
                return out2

            last = (cmd2, rc2, err2[:500])

        raise RuntimeError(f"strings failed. cmd={last[0]} rc={last[1]} stderr={last[2]}")

    # Linux/macOS
    fp = fp_in
    if not file_exists(fp):
        # Try resolving as a Path (handles ~, relative)
        fp2 = str(Path(fp).expanduser().resolve())
        if file_exists(fp2):
            fp = fp2
        else:
            raise RuntimeError(f"file not found: {fp}")

    if not has_cmd("strings"):
        raise RuntimeError("strings not found on PATH (install binutils or equivalent)")

    cmd = ["strings", "-n", str(min_len), fp]
    rc, out, err = _run_subprocess(cmd)
    if rc == 0:
        return out

    # fallback without -n
    cmd2 = ["strings", fp]
    rc2, out2, err2 = _run_subprocess(cmd2)
    if rc2 == 0:
        return out2

    raise RuntimeError(f"strings failed. cmd={cmd2} rc={rc2} stderr={err2[:500]}")


# ----------------------------
# MCP tool
# ----------------------------
@mcp.tool()
def callStrings(file_path: str, min_len: int = 4) -> str:
    """Call the 'strings' command on a given file and return the output.

    Args:
        file_path (str): Path to the file to extract strings from.
        min_len (int): Minimum string length (best-effort; depends on strings implementation).

    Returns:
        str: The extracted strings from the file, or an error message.
    """
    try:
        out = run_strings(file_path=file_path, min_len=min_len)
        out = out[:300]
        return out
    except Exception as e:
        logger.error(f"Error calling strings on {file_path}: {e}")
        return f"Error: {e}"


# ----------------------------
# CLI / main (your existing argparse preserved)
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="MCP server for Strings")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8082,
        help="Port to run MCP server on (only used for sse), default: 8082",
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

    # Logging setup
    log_level = getattr(logging, args.log_level, logging.INFO)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    logger.info(f"Platform: {platform.platform()} (sys.platform={sys.platform})")
    logger.info(f"Using transport: {args.transport}")

    if args.transport == "sse":
        try:
            # Configure MCP settings
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8082

            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        # stdio transport
        mcp.run()


if __name__ == "__main__":
    main()
