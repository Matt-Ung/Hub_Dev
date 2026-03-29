#!/usr/bin/env python3
"""
Centralized writer for reusable agent-generated artifacts such as YARA-adjacent
helpers, Python deobfuscation utilities, Java helpers, reports, and Ghidra
supporting scripts.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from artifact_paths import (  # noqa: E402
    ARTIFACT_TYPE_DEFAULTS,
    get_agent_artifact_dir,
    list_agent_artifact_dirs,
    resolve_agent_artifact_path,
)

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "agent_artifacts_mcp",
    instructions=(
        "MCP server for writing reusable agent-generated artifacts into a standardized, "
        "configurable directory layout."
    ),
)


def _write_text_file(
    *,
    artifact_type: str,
    content: str,
    filename: str,
    overwrite: bool,
    default_stem: str,
    default_extension: str | None,
    subdir: str = "",
    description: str = "",
) -> dict[str, Any]:
    text = str(content or "")
    if not text.strip():
        return {"ok": False, "error": "content cannot be empty"}

    try:
        output_path = resolve_agent_artifact_path(
            artifact_type,
            filename=filename,
            default_stem=default_stem,
            default_extension=default_extension,
            subdir=subdir,
        )
        existed = output_path.exists()
        if existed and not overwrite:
            return {
                "ok": False,
                "error": f"artifact already exists: {output_path}",
                "artifact_path": str(output_path),
            }
        output_path.write_text(text.rstrip() + "\n", encoding="utf-8")
        return {
            "ok": True,
            "artifact_type": artifact_type,
            "artifact_path": str(output_path),
            "artifact_filename": output_path.name,
            "artifact_dir": str(output_path.parent),
            "description": str(description or "").strip(),
            "overwrote_existing": existed and overwrite,
            "artifact_dirs": list_agent_artifact_dirs(),
        }
    except Exception as exc:
        logger.exception("write_text_file failed")
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def agentArtifactPaths() -> dict[str, Any]:
    """Return the configured root and typed subdirectories for generated agent artifacts."""
    return {"ok": True, "artifact_dirs": list_agent_artifact_dirs()}


@mcp.tool()
def writeTextArtifact(
    artifact_type: str,
    content: str,
    filename: str = "",
    overwrite: bool = False,
    subdir: str = "",
    description: str = "",
) -> dict[str, Any]:
    """Write a generic text artifact into a standardized typed artifact directory."""
    normalized_type = str(artifact_type or "").strip().lower()
    if normalized_type not in ARTIFACT_TYPE_DEFAULTS:
        allowed = ", ".join(sorted(ARTIFACT_TYPE_DEFAULTS))
        return {"ok": False, "error": f"unsupported artifact_type {artifact_type!r}; expected one of: {allowed}"}
    return _write_text_file(
        artifact_type=normalized_type,
        content=content,
        filename=filename,
        overwrite=overwrite,
        default_stem=f"generated_{normalized_type}_artifact",
        default_extension=None,
        subdir=subdir,
        description=description,
    )


@mcp.tool()
def writePythonArtifact(
    content: str,
    filename: str = "",
    overwrite: bool = False,
    subdir: str = "",
    description: str = "",
    ghidra_script: bool = False,
) -> dict[str, Any]:
    """Write a Python helper or Python-based Ghidra support script into the standardized artifact tree."""
    artifact_type = "ghidra" if ghidra_script else "python"
    default_stem = "ghidra_python_helper" if ghidra_script else "python_helper"
    return _write_text_file(
        artifact_type=artifact_type,
        content=content,
        filename=filename,
        overwrite=overwrite,
        default_stem=default_stem,
        default_extension=".py",
        subdir=subdir,
        description=description,
    )


@mcp.tool()
def writeJavaArtifact(
    content: str,
    filename: str = "",
    overwrite: bool = False,
    subdir: str = "",
    description: str = "",
    ghidra_script: bool = False,
) -> dict[str, Any]:
    """Write a Java helper or Java-based Ghidra support script into the standardized artifact tree."""
    artifact_type = "ghidra" if ghidra_script else "java"
    default_stem = "ghidra_java_helper" if ghidra_script else "java_helper"
    return _write_text_file(
        artifact_type=artifact_type,
        content=content,
        filename=filename,
        overwrite=overwrite,
        default_stem=default_stem,
        default_extension=".java",
        subdir=subdir,
        description=description,
    )


@mcp.tool()
def listAgentArtifacts(artifact_type: str = "", max_results: int = 200) -> dict[str, Any]:
    """List generated artifacts under one typed directory or across all configured artifact directories."""
    entries: list[dict[str, str]] = []
    choices = [str(artifact_type or "").strip().lower()] if str(artifact_type or "").strip() else sorted(ARTIFACT_TYPE_DEFAULTS)
    for item_type in choices:
        if item_type not in ARTIFACT_TYPE_DEFAULTS:
            return {"ok": False, "error": f"unsupported artifact_type {artifact_type!r}"}
        directory = get_agent_artifact_dir(item_type)
        if not directory.is_dir():
            continue
        for path in sorted(p for p in directory.rglob("*") if p.is_file()):
            entries.append(
                {
                    "artifact_type": item_type,
                    "absolute_path": str(path),
                    "relative_path": str(path.relative_to(directory)),
                }
            )
            if len(entries) >= max_results:
                break
        if len(entries) >= max_results:
            break
    return {"ok": True, "entries": entries, "count": len(entries), "artifact_dirs": list_agent_artifact_dirs()}


@mcp.tool()
def agentArtifactHelp() -> dict[str, Any]:
    """Describe the standardized artifact layout and the available write tools."""
    return {
        "ok": True,
        "artifact_dirs": list_agent_artifact_dirs(),
        "artifact_types": sorted(ARTIFACT_TYPE_DEFAULTS),
        "tools": [
            "agentArtifactPaths()",
            "writeTextArtifact(artifact_type, content, filename='', overwrite=False, subdir='', description='')",
            "writePythonArtifact(content, filename='', overwrite=False, subdir='', description='', ghidra_script=False)",
            "writeJavaArtifact(content, filename='', overwrite=False, subdir='', description='', ghidra_script=False)",
            "listAgentArtifacts(artifact_type='', max_results=200)",
        ],
        "notes": [
            "Use the YARA MCP server for YARA rules so the rule text can still be validated and indexed before writing.",
            "Use this server for reusable Python/Java helpers, deobfuscation utilities, reports, and Ghidra-supporting scripts.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for standardized agent artifact writes")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"])
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8096)
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level, logging.INFO))
    logging.getLogger().setLevel(getattr(logging, args.log_level, logging.INFO))

    if args.transport == "sse":
        mcp.settings.log_level = args.log_level
        mcp.settings.host = args.mcp_host or "127.0.0.1"
        mcp.settings.port = args.mcp_port or 8096
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
