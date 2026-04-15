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
from MCPServers.server_helper_scripts.malware_reporting import (  # noqa: E402
    DEFAULT_TEMPLATE_PATH,
    example_report_payload,
    parse_report_payload,
    render_markdown,
    render_pdf,
    report_slug,
    schema_for_mcp,
    write_normalized_json,
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


def _report_bundle_subdir(subdir: str, slug: str) -> str:
    base = str(subdir or "").strip().replace("\\", "/").strip("/")
    if base:
        return f"{base}/malware_reports/{slug}"
    return f"malware_reports/{slug}"


def _ensure_report_paths(slug: str, *, subdir: str) -> dict[str, Path]:
    bundle_subdir = _report_bundle_subdir(subdir, slug)
    return {
        "json": resolve_agent_artifact_path(
            "reports",
            filename="report.json",
            default_stem="report",
            default_extension=".json",
            subdir=bundle_subdir,
        ),
        "markdown": resolve_agent_artifact_path(
            "reports",
            filename="report.md",
            default_stem="report",
            default_extension=".md",
            subdir=bundle_subdir,
        ),
        "pdf": resolve_agent_artifact_path(
            "reports",
            filename="report.pdf",
            default_stem="report",
            default_extension=".pdf",
            subdir=bundle_subdir,
        ),
    }


@mcp.tool()
def agentArtifactPaths() -> dict[str, Any]:
    """Return the configured root and typed subdirectories for generated agent artifacts."""
    try:
        return {"ok": True, "artifact_dirs": list_agent_artifact_dirs()}
    except Exception as exc:
        logger.warning("agentArtifactPaths rejected invalid artifact configuration: %s", exc)
        return {"ok": False, "error": str(exc)}


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
    try:
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
    except Exception as exc:
        logger.warning("listAgentArtifacts rejected invalid artifact configuration: %s", exc)
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def agentArtifactHelp() -> dict[str, Any]:
    """Describe the standardized artifact layout and the available write tools."""
    try:
        return {
            "ok": True,
            "artifact_dirs": list_agent_artifact_dirs(),
            "artifact_types": sorted(ARTIFACT_TYPE_DEFAULTS),
            "tools": [
                "agentArtifactPaths()",
                "writeTextArtifact(artifact_type, content, filename='', overwrite=False, subdir='', description='')",
                "writePythonArtifact(content, filename='', overwrite=False, subdir='', description='', ghidra_script=False)",
                "writeJavaArtifact(content, filename='', overwrite=False, subdir='', description='', ghidra_script=False)",
                "malwareReportSchema()",
                "generateMalwareReport(report, filename='', overwrite=False, subdir='', emit_json=True, emit_markdown=True, emit_pdf=True)",
                "listAgentArtifacts(artifact_type='', max_results=200)",
            ],
            "notes": [
                "Use the YARA MCP server for YARA rules so the rule text can still be validated and indexed before writing.",
                "Use this server for reusable Python/Java helpers, deobfuscation utilities, structured malware reports, and Ghidra-supporting scripts.",
                "Server-side path enforcement keeps per-type directories and artifact writes under the configured AGENT_ARTIFACT_DIR root.",
                f"Malware report Markdown rendering uses the template at {DEFAULT_TEMPLATE_PATH}.",
            ],
        }
    except Exception as exc:
        logger.warning("agentArtifactHelp rejected invalid artifact configuration: %s", exc)
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def malwareReportSchema() -> dict[str, Any]:
    """Return the structured schema, template path, and example payload for malware report generation."""
    try:
        return {
            "ok": True,
            "schema": schema_for_mcp(),
            "template_path": str(DEFAULT_TEMPLATE_PATH),
            "example_report": example_report_payload(),
            "notes": [
                "Pass the report payload as one structured object to generateMalwareReport(...).",
                "List-like fields accept either a single string or a list of strings.",
                "Missing sections are omitted from the rendered Markdown and PDF output.",
            ],
        }
    except Exception as exc:
        logger.exception("malwareReportSchema failed")
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def generateMalwareReport(
    report: dict[str, Any],
    filename: str = "",
    overwrite: bool = False,
    subdir: str = "",
    emit_json: bool = True,
    emit_markdown: bool = True,
    emit_pdf: bool = True,
) -> dict[str, Any]:
    """
    Generate a structured malware analysis report bundle under the standardized reports artifact directory.

    The tool validates the input payload, writes a normalized JSON payload, renders
    a Markdown report from the malware-report template, and optionally renders a PDF.
    """
    if not any((emit_json, emit_markdown, emit_pdf)):
        return {"ok": False, "error": "at least one of emit_json, emit_markdown, or emit_pdf must be true"}

    try:
        parsed = parse_report_payload(report or {})
        slug = report_slug(parsed, filename=filename)
        paths = _ensure_report_paths(slug, subdir=subdir)
        existing = [str(path) for key, path in paths.items() if {"json": emit_json, "markdown": emit_markdown, "pdf": emit_pdf}[key] and path.exists()]
        if existing and not overwrite:
            return {
                "ok": False,
                "error": "one or more report artifacts already exist; set overwrite=True to replace them",
                "existing_paths": existing,
            }

        outputs: dict[str, str] = {}
        if emit_json:
            write_normalized_json(paths["json"], parsed)
            outputs["json"] = str(paths["json"])
        if emit_markdown:
            markdown_text = render_markdown(parsed)
            paths["markdown"].write_text(markdown_text, encoding="utf-8")
            outputs["markdown"] = str(paths["markdown"])
        if emit_pdf:
            render_pdf(parsed, paths["pdf"])
            outputs["pdf"] = str(paths["pdf"])

        included_sections: list[str] = []
        if parsed.executive_summary:
            included_sections.append("executive_summary")
        if parsed.introduction:
            included_sections.append("introduction")
        if any(str(value or "").strip() for value in parsed.file_details.model_dump().values()):
            included_sections.append("file_details")
        if parsed.methods_of_distribution:
            included_sections.append("methods_of_distribution")
        if parsed.installation:
            included_sections.append("installation")
        if parsed.stage_descriptions:
            included_sections.append("stage_descriptions")
        if any(parsed.host_artifacts.model_dump().values()):
            included_sections.append("host_artifacts")
        if any(parsed.functionality_overview.model_dump().values()):
            included_sections.append("functionality_overview")
        if any(parsed.command_and_control.model_dump().values()):
            included_sections.append("command_and_control")
        if parsed.conclusion:
            included_sections.append("conclusion")
        if any(parsed.appendix_content.model_dump().values()):
            included_sections.append("appendix_content")

        return {
            "ok": True,
            "artifact_type": "reports",
            "report_title": parsed.title,
            "report_slug": slug,
            "sample_name": parsed.sample_name,
            "artifact_dir": str(paths["markdown"].parent if emit_markdown else next(iter(paths.values())).parent),
            "outputs": outputs,
            "included_sections": included_sections,
            "artifact_dirs": list_agent_artifact_dirs(),
            "template_path": str(DEFAULT_TEMPLATE_PATH),
            "example_call_hint": {
                "tool": "generateMalwareReport",
                "arguments": {
                    "report": example_report_payload(),
                    "filename": "sample_report",
                    "subdir": "engagement_alpha",
                    "overwrite": False,
                },
            },
        }
    except Exception as exc:
        logger.exception("generateMalwareReport failed")
        return {"ok": False, "error": str(exc)}


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
        mcp.run(transport="sse", show_banner=False)
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
