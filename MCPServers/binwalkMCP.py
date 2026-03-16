#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: binary-analysis/binwalk-mcp/server.py

This version is rewritten into the lightweight FastMCP wrapper style used by
the local MCPServers/ directory.
"""

import logging
import os
import uuid
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from _cli_mcp_common import (
    ensure_directory,
    ensure_existing_path,
    has_command,
    run_command,
    run_help_command,
    run_server,
    truncate_text,
)

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = Path(os.environ.get("BINWALK_OUTPUT_DIR", str(Path.cwd() / "MCPServers" / "binwalk_output")))
mcp = FastMCP(
    "binwalk_mcp",
    instructions="MCP server that exposes structured binwalk scanning and extraction tools.",
)


def _parse_binwalk_signatures(output: str) -> list[dict[str, Any]]:
    signatures: list[dict[str, Any]] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("DECIMAL") or line.startswith("-"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            signatures.append(
                {
                    "offset": int(parts[0]),
                    "offset_hex": parts[1],
                    "description": parts[2],
                }
            )
        except ValueError:
            continue
    return signatures


def _list_files(root: Path, max_files: int = 200) -> list[str]:
    if not root.exists():
        return []
    out: list[str] = []
    for path in root.rglob("*"):
        if path.is_file():
            out.append(str(path.relative_to(root)))
            if len(out) >= max_files:
                break
    return out


@mcp.tool()
def binwalkScan(
    file_path: str,
    extract: bool = False,
    entropy: bool = False,
    hexdump: bool = False,
    matryoshka: bool = False,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """Run binwalk on a local file and return structured output."""
    try:
        if not has_command("binwalk"):
            return {"ok": False, "error": "binwalk not found on PATH"}

        resolved_file = ensure_existing_path(file_path)
        output_root = Path(ensure_directory(DEFAULT_OUTPUT_DIR))
        extraction_dir = output_root / f"extract_{uuid.uuid4().hex[:8]}"

        cmd = ["binwalk"]
        if extract:
            cmd.extend(["-e", "-C", str(extraction_dir)])
        if entropy:
            cmd.append("-E")
        if hexdump:
            cmd.append("-W")
        if matryoshka:
            cmd.append("-M")
        cmd.append(resolved_file)

        result = run_command(cmd, timeout_sec=timeout_sec)
        signatures = _parse_binwalk_signatures(result.stdout or "")
        extracted_files = _list_files(extraction_dir) if extract else []

        payload: dict[str, Any] = {
            "ok": result.returncode == 0,
            "rc": result.returncode,
            "command": cmd,
            "file_path": resolved_file,
            "extract": extract,
            "entropy": entropy,
            "hexdump": hexdump,
            "matryoshka": matryoshka,
            "signatures": signatures,
            "stats": {
                "signature_count": len(signatures),
                "extracted_file_count": len(extracted_files),
            },
            "stdout": truncate_text(result.stdout or "", max_chars=16000),
            "stderr": truncate_text(result.stderr or "", max_chars=4000),
        }
        if extract:
            payload["extraction_path"] = str(extraction_dir)
            payload["extracted_files"] = extracted_files
        return payload
    except FileNotFoundError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        logger.exception("binwalkScan failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def listBinwalkExtraction(extraction_path: str, max_files: int = 200) -> dict[str, Any]:
    """List files from a previous binwalk extraction directory."""
    try:
        resolved = Path(ensure_existing_path(extraction_path))
        if not resolved.is_dir():
            return {"ok": False, "error": f"not a directory: {resolved}"}
        return {
            "ok": True,
            "extraction_path": str(resolved),
            "files": _list_files(resolved, max_files=max_files),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


@mcp.tool()
def binwalkHelp(timeout_sec: int = 5) -> str:
    """Return `binwalk --help` output."""
    return run_help_command("binwalk", timeout_sec=timeout_sec)


def main() -> None:
    run_server(mcp, description="MCP server for binwalk", default_port=8091)


if __name__ == "__main__":
    main()
