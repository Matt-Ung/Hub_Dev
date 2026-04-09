#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: secrets/gitleaks-mcp/server.py

This version is rewritten into the lightweight FastMCP wrapper style used by
the local MCPServers/ directory.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from artifact_paths import describe_tool_output_root, ensure_tool_output_root, get_tool_output_root  # noqa: E402

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")

mcp = FastMCP(
    "gitleaks_mcp",
    instructions="MCP server that exposes structured gitleaks scanning tools.",
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
    root = get_tool_output_root("gitleaks")
    candidate = Path(normalize_user_path(str(path)))
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"gitleaks output must stay under {root}; got {candidate}") from exc
    candidate.mkdir(parents=True, exist_ok=True)
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


def _mask_secret(secret: str, visible_chars: int = 4) -> str:
    if not secret:
        return ""
    if len(secret) <= visible_chars:
        return "*" * len(secret)
    return secret[:visible_chars] + ("*" * (len(secret) - visible_chars))


def _parse_findings(report_text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        payload = json.loads(report_text or "[]")
    except json.JSONDecodeError:
        return findings

    if not isinstance(payload, list):
        return findings

    for item in payload:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "rule_id": item.get("RuleID"),
                "description": item.get("Description"),
                "secret": _mask_secret(str(item.get("Secret", ""))),
                "file": item.get("File"),
                "line": item.get("StartLine"),
                "commit": item.get("Commit"),
                "author": item.get("Author"),
                "tags": item.get("Tags", []),
            }
        )
    return findings


def _run_gitleaks(target: str, no_git: bool, timeout_sec: int) -> dict[str, Any]:
    if not has_command("gitleaks"):
        return {"ok": False, "error": "gitleaks not found on PATH"}

    resolved_target = ensure_existing_path(target)
    output_dir = Path(ensure_directory(get_tool_output_root("gitleaks")))
    report_path = output_dir / f"gitleaks_{uuid.uuid4().hex[:8]}.json"

    cmd = [
        "gitleaks",
        "detect",
        "--source",
        resolved_target,
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--exit-code",
        "0",
    ]
    if no_git:
        cmd.append("--no-git")

    result = run_command(cmd, timeout_sec=timeout_sec)
    report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else "[]"
    findings = _parse_findings(report_text)

    rules_triggered: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("rule_id") or "unknown")
        rules_triggered[key] = rules_triggered.get(key, 0) + 1

    return {
        "ok": result.returncode == 0,
        "rc": result.returncode,
        "command": cmd,
        "target": resolved_target,
        "no_git": no_git,
        "findings": findings,
        "stats": {
            "finding_count": len(findings),
            "rule_count": len(rules_triggered),
            "rules_triggered": rules_triggered,
        },
        "stdout": truncate_text(result.stdout or "", max_chars=8000),
        "stderr": truncate_text(result.stderr or "", max_chars=4000),
        "allowed_output_root": describe_tool_output_root("gitleaks"),
    }


@mcp.tool()
def gitleaksScan(target_path: str, no_git: bool = False, timeout_sec: int = 300) -> dict[str, Any]:
    """Scan a repository or directory with gitleaks."""
    try:
        return _run_gitleaks(target_path, no_git=no_git, timeout_sec=timeout_sec)
    except Exception as e:
        logger.warning("gitleaksScan rejected request or failed to scan: %s", e)
        logger.exception("gitleaksScan failed")
        return {"ok": False, "error": str(e), "allowed_output_root": describe_tool_output_root("gitleaks")}


@mcp.tool()
def gitleaksScanContent(content: str, timeout_sec: int = 120) -> dict[str, Any]:
    """Scan inline content by writing it to a temporary file and running gitleaks."""
    if not content:
        return {"ok": False, "error": "content cannot be empty"}

    temp_path: str | None = None
    try:
        temp_root = ensure_tool_output_root("gitleaks")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, dir=str(temp_root)) as handle:
            handle.write(content)
            temp_path = handle.name
        return _run_gitleaks(temp_path, no_git=True, timeout_sec=timeout_sec)
    except Exception as e:
        logger.warning("gitleaksScanContent rejected request or failed to scan: %s", e)
        logger.exception("gitleaksScanContent failed")
        return {"ok": False, "error": str(e), "allowed_output_root": describe_tool_output_root("gitleaks")}
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass


@mcp.tool()
def gitleaksHelp(timeout_sec: int = 5) -> str:
    """Return `gitleaks --help` output."""
    return (
        run_help_command("gitleaks", timeout_sec=timeout_sec)
        + "\n\n"
        + f"Allowed report output root: {describe_tool_output_root('gitleaks')}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for gitleaks")
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
            mcp.settings.port = args.mcp_port or 8093
            mcp.run(transport="sse", show_banner=False)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
