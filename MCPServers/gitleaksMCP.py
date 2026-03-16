#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: secrets/gitleaks-mcp/server.py

This version is rewritten into the lightweight FastMCP wrapper style used by
the local MCPServers/ directory.
"""

import json
import logging
import os
import tempfile
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

DEFAULT_OUTPUT_DIR = Path(os.environ.get("GITLEAKS_OUTPUT_DIR", str(Path.cwd() / "MCPServers" / "gitleaks_output")))
mcp = FastMCP(
    "gitleaks_mcp",
    instructions="MCP server that exposes structured gitleaks scanning tools.",
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
    output_dir = Path(ensure_directory(DEFAULT_OUTPUT_DIR))
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
    }


@mcp.tool()
def gitleaksScan(target_path: str, no_git: bool = False, timeout_sec: int = 300) -> dict[str, Any]:
    """Scan a repository or directory with gitleaks."""
    try:
        return _run_gitleaks(target_path, no_git=no_git, timeout_sec=timeout_sec)
    except Exception as e:
        logger.exception("gitleaksScan failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def gitleaksScanContent(content: str, timeout_sec: int = 120) -> dict[str, Any]:
    """Scan inline content by writing it to a temporary file and running gitleaks."""
    if not content:
        return {"ok": False, "error": "content cannot be empty"}

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as handle:
            handle.write(content)
            temp_path = handle.name
        return _run_gitleaks(temp_path, no_git=True, timeout_sec=timeout_sec)
    except Exception as e:
        logger.exception("gitleaksScanContent failed")
        return {"ok": False, "error": str(e)}
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass


@mcp.tool()
def gitleaksHelp(timeout_sec: int = 5) -> str:
    """Return `gitleaks --help` output."""
    return run_help_command("gitleaks", timeout_sec=timeout_sec)


def main() -> None:
    run_server(mcp, description="MCP server for gitleaks", default_port=8093)


if __name__ == "__main__":
    main()
