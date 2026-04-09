#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: cloud-security/trivy-mcp/server.py

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
from pathlib import Path
from typing import Any, Literal

from fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from artifact_paths import describe_tool_output_root, ensure_tool_output_root  # noqa: E402

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")

VALID_SCAN_TYPES = {"image", "filesystem", "repo", "config", "sbom"}
mcp = FastMCP(
    "trivy_mcp",
    instructions="MCP server that exposes structured Trivy scanning tools.",
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


def run_command(argv: list[str], timeout_sec: int, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=max(1, int(timeout_sec)),
        env=env,
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
        cache_dir = ensure_tool_output_root("trivy")
        command_env = os.environ.copy()
        command_env["TRIVY_CACHE_DIR"] = str(cache_dir)

        cmd = ["trivy", scan_type, resolved_target]
        if severity:
            cmd.extend(["--severity", ",".join(severity)])
        if ignore_unfixed:
            cmd.append("--ignore-unfixed")

        mode = (output_mode or "json_compact").strip().lower()
        if mode == "text":
            result = run_command(cmd, timeout_sec=timeout_sec, env=command_env)
            return {
                "ok": result.returncode == 0,
                "rc": result.returncode,
                "command": cmd,
                "scan_type": scan_type,
                "target": resolved_target,
                "cache_dir": str(cache_dir),
                "stdout": truncate_text(result.stdout or "", max_chars=16000),
                "stderr": truncate_text(result.stderr or "", max_chars=4000),
            }

        cmd.extend(["--format", "json"])
        result = run_command(cmd, timeout_sec=timeout_sec, env=command_env)
        compact = _parse_trivy_compact(result.stdout or "")
        envelope: dict[str, Any] = {
            "ok": result.returncode == 0,
            "rc": result.returncode,
            "command": cmd,
            "scan_type": scan_type,
            "target": resolved_target,
            "cache_dir": str(cache_dir),
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
        logger.warning("trivyScan rejected request or failed to scan: %s", e)
        logger.exception("trivyScan failed")
        return {"ok": False, "error": str(e), "cache_dir": describe_tool_output_root("trivy")}


@mcp.tool()
def trivyHelp(timeout_sec: int = 5) -> str:
    """Return `trivy --help` output."""
    return (
        run_help_command("trivy", timeout_sec=timeout_sec)
        + "\n\n"
        + f"Configured Trivy cache dir: {describe_tool_output_root('trivy')}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for Trivy")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8095,
        help="Port to run MCP server on (only used for sse), default: 8095",
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
            mcp.settings.port = args.mcp_port or 8095
            mcp.run(transport="sse", show_banner=False)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
