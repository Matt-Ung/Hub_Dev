#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: cloud-security/trivy-mcp/server.py

This version is rewritten into the lightweight FastMCP wrapper style used by
the local MCPServers/ directory.
"""

import json
import logging
from typing import Any, Literal

from fastmcp import FastMCP

from _cli_mcp_common import (
    ensure_existing_path,
    has_command,
    run_command,
    run_help_command,
    run_server,
    truncate_text,
)

logger = logging.getLogger(__name__)

VALID_SCAN_TYPES = {"image", "filesystem", "repo", "config", "sbom"}
mcp = FastMCP(
    "trivy_mcp",
    instructions="MCP server that exposes structured Trivy scanning tools.",
)


def _parse_trivy_compact(output: str) -> dict[str, Any]:
    try:
        payload = json.loads(output or "{}")
    except json.JSONDecodeError:
        return {"results": [], "summary": {"vulnerability_count": 0, "misconfiguration_count": 0}}

    rows: list[dict[str, Any]] = []
    vuln_count = 0
    misconfig_count = 0

    for result in payload.get("Results", []) or []:
        target = result.get("Target")
        class_name = result.get("Class")
        vulns = result.get("Vulnerabilities", []) or []
        misconfigs = result.get("Misconfigurations", []) or []
        vuln_count += len(vulns)
        misconfig_count += len(misconfigs)
        rows.append(
            {
                "target": target,
                "class": class_name,
                "vulnerability_count": len(vulns),
                "misconfiguration_count": len(misconfigs),
                "top_vulnerabilities": [
                    {
                        "id": vuln.get("VulnerabilityID"),
                        "pkg": vuln.get("PkgName"),
                        "severity": vuln.get("Severity"),
                    }
                    for vuln in vulns[:10]
                ],
                "top_misconfigurations": [
                    {
                        "id": misconfig.get("ID"),
                        "title": misconfig.get("Title"),
                        "severity": misconfig.get("Severity"),
                    }
                    for misconfig in misconfigs[:10]
                ],
            }
        )

    return {
        "results": rows,
        "summary": {
            "vulnerability_count": vuln_count,
            "misconfiguration_count": misconfig_count,
            "result_count": len(rows),
        },
    }


@mcp.tool()
def trivyScan(
    target: str,
    scan_type: Literal["image", "filesystem", "repo", "config", "sbom"] = "filesystem",
    severity: list[str] | None = None,
    ignore_unfixed: bool = False,
    timeout_sec: int = 600,
    output_mode: Literal["json_compact", "json_full", "text"] = "json_compact",
) -> dict[str, Any] | str:
    """Run Trivy against an image or local path."""
    if scan_type not in VALID_SCAN_TYPES:
        return {"ok": False, "error": f"invalid scan_type={scan_type!r}"}
    if not has_command("trivy"):
        return {"ok": False, "error": "trivy not found on PATH"}

    try:
        resolved_target = target
        if scan_type != "image":
            resolved_target = ensure_existing_path(target)

        cmd = ["trivy", scan_type, resolved_target]
        if severity:
            cmd.extend(["--severity", ",".join(severity)])
        if ignore_unfixed:
            cmd.append("--ignore-unfixed")

        mode = (output_mode or "json_compact").strip().lower()
        if mode == "text":
            result = run_command(cmd, timeout_sec=timeout_sec)
            return {
                "ok": result.returncode == 0,
                "rc": result.returncode,
                "command": cmd,
                "scan_type": scan_type,
                "target": resolved_target,
                "stdout": truncate_text(result.stdout or "", max_chars=16000),
                "stderr": truncate_text(result.stderr or "", max_chars=4000),
            }

        cmd.extend(["--format", "json"])
        result = run_command(cmd, timeout_sec=timeout_sec)
        compact = _parse_trivy_compact(result.stdout or "")
        envelope: dict[str, Any] = {
            "ok": result.returncode == 0,
            "rc": result.returncode,
            "command": cmd,
            "scan_type": scan_type,
            "target": resolved_target,
            "stderr": truncate_text(result.stderr or "", max_chars=4000),
        }
        if mode == "json_full":
            try:
                envelope["result"] = json.loads(result.stdout or "{}")
            except json.JSONDecodeError:
                envelope["ok"] = False
                envelope["error"] = "failed to parse Trivy JSON output"
                envelope["stdout"] = truncate_text(result.stdout or "", max_chars=12000)
        else:
            envelope["result"] = compact
        return envelope
    except Exception as e:
        logger.exception("trivyScan failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def trivyHelp(timeout_sec: int = 5) -> str:
    """Return `trivy --help` output."""
    return run_help_command("trivy", timeout_sec=timeout_sec)


def main() -> None:
    run_server(mcp, description="MCP server for Trivy", default_port=8095)


if __name__ == "__main__":
    main()
