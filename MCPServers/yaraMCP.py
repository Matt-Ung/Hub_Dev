#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: binary-analysis/yara-mcp/server.py

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
import tempfile
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")

DEFAULT_RULES_DIR = Path(os.environ.get("YARA_RULES_DIR", str(Path.cwd() / "MCPServers" / "yara_rules")))
mcp = FastMCP(
    "yara_mcp",
    instructions="MCP server that exposes structured YARA scanning tools.",
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


def run_server(mcp: FastMCP, description: str, default_port: int) -> None:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=default_port,
        help=f"Port to run MCP server on (only used for sse), default: {default_port}",
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
            mcp.settings.port = args.mcp_port or default_port
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


def _parse_yara_output(output: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) < 2:
            continue
        rule_name, rest = parts[0], parts[1].strip()
        if rule_name.startswith("0x"):
            continue
        matches.append({"rule": rule_name, "target": rest})
    return matches


def _resolve_rules_path(rules_path: Optional[str]) -> str:
    if rules_path:
        return ensure_existing_path(rules_path)

    if DEFAULT_RULES_DIR.is_dir():
        index_file = DEFAULT_RULES_DIR / "index.yar"
        if index_file.exists():
            return str(index_file)
        for suffix in ("*.yar", "*.yara"):
            first = next(DEFAULT_RULES_DIR.rglob(suffix), None)
            if first is not None:
                return str(first)

    raise FileNotFoundError(
        f"no YARA rules found. Provide rules_path or create rules under {DEFAULT_RULES_DIR}"
    )


def _run_yara_scan(
    target_path: str,
    rules_arg: str,
    recursive: bool,
    timeout_sec: int,
    show_strings: bool,
) -> dict[str, Any]:
    if not has_command("yara"):
        return {"ok": False, "error": "yara not found on PATH"}

    resolved_target = ensure_existing_path(target_path)
    target = Path(resolved_target)

    cmd = ["yara", "-w"]
    if recursive and target.is_dir():
        cmd.append("-r")
    if show_strings:
        cmd.append("-s")
    cmd.extend([rules_arg, resolved_target])

    result = run_command(cmd, timeout_sec=timeout_sec)
    matches = _parse_yara_output(result.stdout or "")
    unique_rules = sorted({m["rule"] for m in matches})
    unique_targets = sorted({m["target"] for m in matches})

    return {
        "ok": result.returncode == 0,
        "rc": result.returncode,
        "command": cmd,
        "rules_path": rules_arg,
        "target_path": resolved_target,
        "recursive": recursive,
        "show_strings": show_strings,
        "matches": matches,
        "stats": {
            "match_count": len(matches),
            "unique_rule_count": len(unique_rules),
            "unique_target_count": len(unique_targets),
            "rules": unique_rules,
        },
        "stdout": truncate_text(result.stdout or "", max_chars=16000),
        "stderr": truncate_text(result.stderr or "", max_chars=4000),
    }


@mcp.tool()
def yaraScan(
    target_path: str,
    rules_path: str = "",
    recursive: bool = True,
    show_strings: bool = False,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """Scan a file or directory with YARA rules."""
    try:
        rules_arg = _resolve_rules_path(rules_path.strip() or None)
        return _run_yara_scan(
            target_path=target_path,
            rules_arg=rules_arg,
            recursive=recursive,
            timeout_sec=timeout_sec,
            show_strings=show_strings,
        )
    except Exception as e:
        logger.exception("yaraScan failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def yaraScanInline(
    target_path: str,
    rule_text: str,
    recursive: bool = True,
    show_strings: bool = False,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """Scan a file or directory with inline YARA rule text."""
    if not rule_text.strip():
        return {"ok": False, "error": "rule_text cannot be empty"}

    temp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as handle:
            handle.write(rule_text)
            temp_path = handle.name
        return _run_yara_scan(
            target_path=target_path,
            rules_arg=temp_path,
            recursive=recursive,
            timeout_sec=timeout_sec,
            show_strings=show_strings,
        )
    except Exception as e:
        logger.exception("yaraScanInline failed")
        return {"ok": False, "error": str(e)}
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass


@mcp.tool()
def yaraListRules(max_rules: int = 200) -> dict[str, Any]:
    """List available rule files under the configured rules directory."""
    rules: list[str] = []
    if DEFAULT_RULES_DIR.is_dir():
        for pattern in ("*.yar", "*.yara"):
            for path in DEFAULT_RULES_DIR.rglob(pattern):
                rules.append(str(path.relative_to(DEFAULT_RULES_DIR)))
                if len(rules) >= max_rules:
                    break
            if len(rules) >= max_rules:
                break
    return {
        "ok": True,
        "rules_dir": str(DEFAULT_RULES_DIR),
        "rules": sorted(rules),
        "count": len(rules),
    }


@mcp.tool()
def yaraHelp(timeout_sec: int = 5) -> str:
    """Return `yara --help` output."""
    return run_help_command("yara", timeout_sec=timeout_sec)


def main() -> None:
    run_server(mcp, description="MCP server for YARA", default_port=8092)


if __name__ == "__main__":
    main()
