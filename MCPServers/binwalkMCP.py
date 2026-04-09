#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: binary-analysis/binwalk-mcp/server.py

This version is rewritten into the lightweight FastMCP wrapper style used by
the local MCPServers/ directory.
"""

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from artifact_paths import describe_tool_output_root, get_tool_output_root

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")

mcp = FastMCP(
    "binwalk_mcp",
    instructions="MCP server that exposes structured binwalk scanning and extraction tools.",
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


def ensure_directory(path: str | Path) -> str:
    root = get_tool_output_root("binwalk")
    candidate = Path(normalize_user_path(str(path)))
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"binwalk output must stay under {root}; got {candidate}") from exc
    candidate.mkdir(parents=True, exist_ok=True)
    return str(candidate)


def run_command(argv: list[str], timeout_sec: int, *, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=max(1, int(timeout_sec)),
        cwd=cwd,
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


def _safe_component(value: str, default: str = "artifact") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    cleaned = cleaned.strip("._-")
    return cleaned or default


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
        output_root = Path(ensure_directory(get_tool_output_root("binwalk")))
        scan_work_dir = output_root / f"scan_{_safe_component(Path(resolved_file).stem, 'sample')}_{uuid.uuid4().hex[:8]}"
        scan_work_dir = Path(ensure_directory(scan_work_dir))
        extraction_dir = output_root / f"extract_{uuid.uuid4().hex[:8]}"
        entropy_plot_path = scan_work_dir / f"{Path(resolved_file).name}.png"

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

        result = run_command(cmd, timeout_sec=timeout_sec, cwd=str(scan_work_dir))
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
            "output_root": str(output_root),
            "scan_work_dir": str(scan_work_dir),
            "stdout": truncate_text(result.stdout or "", max_chars=16000),
            "stderr": truncate_text(result.stderr or "", max_chars=4000),
        }
        if extract:
            payload["extraction_path"] = str(extraction_dir)
            payload["extracted_files"] = extracted_files
        if entropy:
            payload["entropy_plot_path"] = str(entropy_plot_path)
            payload["entropy_plot_exists"] = entropy_plot_path.exists()
            payload["scan_work_files"] = _list_files(scan_work_dir)
        return payload
    except FileNotFoundError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        logger.warning("binwalkScan rejected request or failed to scan: %s", e)
        logger.exception("binwalkScan failed")
        return {"ok": False, "error": str(e), "allowed_output_root": describe_tool_output_root('binwalk')}


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
    return (
        run_help_command("binwalk", timeout_sec=timeout_sec)
        + "\n\n"
        + f"Allowed binwalk output root: {describe_tool_output_root('binwalk')}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for binwalk")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8091,
        help="Port to run MCP server on (only used for sse), default: 8091",
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

    if args.transport == "sse":
        try:
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8091
            mcp.run(transport="sse", show_banner=False)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
