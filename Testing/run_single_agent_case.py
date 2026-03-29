#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict


def _build_initial_state(shared_state_factory):
    return {
        "role_histories": {},
        "tool_log": "",
        "tool_log_sections": {},
        "_tool_log_seen_keys": {},
        "tool_result_cache": {},
        "status_log": "",
        "active_run_id": "",
        "cancel_requested": False,
        "allow_parent_input": False,
        "shell_execution_mode": "none",
        "validator_review_level": "default",
        "shared_state": shared_state_factory(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one agent pipeline case against an artifact-backed Ghidra bundle")
    parser.add_argument("--bundle-dir", required=True, help="Path to a prepared experimental sample bundle")
    parser.add_argument("--query", default="", help="Query to run. If omitted, automation payload / manifest defaults are used")
    parser.add_argument("--pipeline", default="auto_triage", help="Pipeline preset to run")
    parser.add_argument("--architecture", default="balanced", help="Architecture preset to run")
    parser.add_argument("--output-json", required=True, help="Path to write the run result JSON")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    bundle_dir = Path(args.bundle_dir).resolve()
    output_json = Path(args.output_json).resolve()
    automation_payload_path = bundle_dir / "automation_payload.json"
    manifest_path = bundle_dir / "bundle_manifest.json"

    with tempfile.TemporaryDirectory(prefix="artifact_mcp_manifest_") as temp_dir:
        manifest_output = Path(temp_dir) / "servers.json"

        from experimental_batch_utils import build_artifact_servers_manifest, read_json, summarize_tool_usage, parse_tool_log_sections

        build_artifact_servers_manifest(bundle_dir, manifest_output)
        os.environ["MCP_SERVER_MANIFEST_PATH"] = str(manifest_output)

        from multi_agent_wf.pipeline import run_deepagent_pipeline
        from multi_agent_wf.runtime import get_runtime_sync, shutdown_runtime_sync
        from multi_agent_wf.shared_state import _new_shared_state, apply_automation_payload_to_state

        state = _build_initial_state(_new_shared_state)
        manifest = read_json(manifest_path) if manifest_path.exists() else {}
        automation_payload = read_json(automation_payload_path) if automation_payload_path.exists() else {}
        if automation_payload:
            apply_automation_payload_to_state(state, automation_payload)

        query = str(args.query or "").strip()
        if not query:
            query = (
                (((manifest.get("manifest") or {}).get("default_query")) if isinstance(manifest.get("manifest"), dict) else "")
                or "Analyze this executable at the program level and summarize the most relevant behaviors."
            )

        result: Dict[str, Any] = {
            "bundle_dir": str(bundle_dir),
            "pipeline": args.pipeline,
            "architecture": args.architecture,
            "query": query,
            "manifest_path": str(manifest_output),
            "ok": False,
        }
        try:
            runtime = get_runtime_sync(args.pipeline, architecture_name=args.architecture)
            report = run_deepagent_pipeline(runtime, query, state)
            shared = state.get("shared_state") or {}
            parsed_tool_entries = parse_tool_log_sections(state.get("tool_log_sections") or {})
            result.update(
                {
                    "ok": True,
                    "final_report": report,
                    "automation_status": str(shared.get("automation_status") or ""),
                    "auto_triage_status": str(shared.get("auto_triage_status") or ""),
                    "auto_triage_context_summary": str(shared.get("auto_triage_context_summary") or ""),
                    "planned_work_items": list(shared.get("planned_work_items") or []),
                    "ghidra_change_proposals": list(shared.get("ghidra_change_proposals") or []),
                    "generated_yara_rules": list(shared.get("generated_yara_rules") or []),
                    "tool_usage": summarize_tool_usage(parsed_tool_entries),
                    "tool_log_sections": state.get("tool_log_sections") or {},
                    "status_log": str(state.get("status_log") or ""),
                }
            )
        except Exception as exc:
            result.update(
                {
                    "ok": False,
                    "error": "%s: %s" % (type(exc).__name__, exc),
                    "traceback": traceback.format_exc(),
                    "status_log": str(state.get("status_log") or ""),
                }
            )
        finally:
            try:
                shutdown_runtime_sync()
            except Exception:
                pass

        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
