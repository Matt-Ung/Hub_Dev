#!/usr/bin/env python3
"""
Lightweight FastMCP wrapper for bounded UPX detection and unpacking.
"""

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")

mcp = FastMCP(
    "upx_mcp",
    instructions="MCP server that exposes bounded UPX help, test, and unpack tools.",
)


def truncate_text(text: str, max_chars: int = 12000) -> str:
    value = text or ""
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...[truncated]..."


def has_command(command: str) -> bool:
    return shutil.which(command) is not None


def normalize_user_path(path: str) -> str:
    value = (path or "").strip()
    if not value:
        return value

    if IS_WINDOWS:
        match = _DRIVE_RE.match(value)
        if match:
            return value[1:]

        match = _MNT_RE.match(value)
        if match:
            drive = match.group(1).upper()
            rest = match.group(2).replace("/", "\\")
            return f"{drive}:\\{rest}"

    return os.path.expandvars(os.path.expanduser(value))


def ensure_existing_path(path: str) -> str:
    candidate = Path(normalize_user_path(path))
    if not candidate.is_absolute():
        candidate = candidate.resolve()
    if not candidate.exists():
        raise FileNotFoundError(f"path not found: {candidate}")
    return str(candidate)


def ensure_parent_directory(path: str) -> str:
    candidate = Path(normalize_user_path(path))
    if not candidate.is_absolute():
        candidate = candidate.resolve()
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return str(candidate)


def run_command(argv: list[str], timeout_sec: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=max(1, int(timeout_sec)),
    )


def run_help_command(binary: str, timeout_sec: int = 5) -> str:
    if not has_command(binary):
        return f"Error: `{binary}` not found on PATH."
    result = run_command([binary, "--help"], timeout_sec=timeout_sec)
    return (
        f"{binary} --help\n"
        f"rc={result.returncode}\n"
        "stdout:\n"
        f"{truncate_text(result.stdout or '', max_chars=16000)}\n"
        "stderr:\n"
        f"{truncate_text(result.stderr or '', max_chars=4000)}"
    )


@mcp.tool()
def upxHelp(timeout_sec: int = 5) -> str:
    """Return `upx --help` output."""
    return run_help_command("upx", timeout_sec=timeout_sec)


@mcp.tool()
def upxTest(file_path: str, timeout_sec: int = 30) -> dict[str, Any]:
    """Run `upx -t` against a local file to test whether UPX recognizes it."""
    try:
        if not has_command("upx"):
            return {"ok": False, "error": "upx not found on PATH"}

        resolved_input = ensure_existing_path(file_path)
        result = run_command(["upx", "-t", resolved_input], timeout_sec=timeout_sec)
        stdout = truncate_text(result.stdout or "", max_chars=12000)
        stderr = truncate_text(result.stderr or "", max_chars=4000)
        combined = f"{stdout}\n{stderr}".lower()
        return {
            "ok": result.returncode == 0,
            "recognized": "not packed by upx" not in combined and "not packed" not in combined,
            "rc": result.returncode,
            "command": ["upx", "-t", resolved_input],
            "file_path": resolved_input,
            "stdout": stdout,
            "stderr": stderr,
        }
    except Exception as e:
        logger.exception("upxTest failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def upxUnpack(
    file_path: str,
    output_path: str,
    force: bool = False,
    timeout_sec: int = 120,
) -> dict[str, Any]:
    """Unpack a local file with `upx -d` into an explicit destination path."""
    try:
        if not has_command("upx"):
            return {"ok": False, "error": "upx not found on PATH"}

        resolved_input = ensure_existing_path(file_path)
        resolved_output = ensure_parent_directory(output_path)
        output_candidate = Path(resolved_output)
        if output_candidate.exists() and not force:
            return {
                "ok": False,
                "error": f"output already exists: {output_candidate}",
                "output_path": str(output_candidate),
            }

        cmd = ["upx", "-d", "-o", str(output_candidate), resolved_input]
        result = run_command(cmd, timeout_sec=timeout_sec)
        stdout = truncate_text(result.stdout or "", max_chars=12000)
        stderr = truncate_text(result.stderr or "", max_chars=4000)
        output_exists = output_candidate.exists()
        return {
            "ok": result.returncode == 0 and output_exists,
            "rc": result.returncode,
            "command": cmd,
            "file_path": resolved_input,
            "output_path": str(output_candidate),
            "output_exists": output_exists,
            "stdout": stdout,
            "stderr": stderr,
            "error": "" if (result.returncode == 0 and output_exists) else truncate_text(stderr or stdout, max_chars=2000),
        }
    except Exception as e:
        logger.exception("upxUnpack failed")
        return {"ok": False, "error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for UPX")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8093,
        help="Port to run MCP server on (only used for sse), default: 8093",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport to use (stdio or sse)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.transport == "stdio":
        mcp.run(show_banner=False)
    else:
        mcp.run(transport="sse", host=args.mcp_host, port=args.mcp_port, show_banner=False)


if __name__ == "__main__":
    main()
