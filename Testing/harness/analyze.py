from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict

from .artifacts import build_artifact_servers_manifest, inspect_bundle_dir, parse_tool_log_sections, summarize_tool_usage
from .costing import estimate_event_costs
from .paths import REPO_ROOT, read_json, write_json


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


def _validation_summary(shared: Dict[str, Any]) -> Dict[str, Any]:
    history = list(shared.get("validation_history") or [])
    retry_count = int(shared.get("validation_retry_count") or 0)
    max_retries = int(shared.get("validation_max_retries") or 0)
    last_decision = str(shared.get("validation_last_decision") or "").strip().lower()
    feedback = str(shared.get("validation_replan_feedback") or "").strip()
    latest = history[-1] if history else {}
    blocked = bool(history) and last_decision == "reject" and retry_count >= max_retries and max_retries >= 0
    rejection_reasons = list(latest.get("rejection_reasons") or []) if isinstance(latest, dict) else []
    return {
        "history": history,
        "retry_count": retry_count,
        "max_retries": max_retries,
        "last_decision": last_decision,
        "feedback": feedback,
        "latest": latest if isinstance(latest, dict) else {},
        "blocked": blocked,
        "rejection_reasons": rejection_reasons,
    }


def _derive_result_status(shared: Dict[str, Any], final_report: str, *, error: str = "") -> Dict[str, Any]:
    validation = _validation_summary(shared)
    report_text = str(final_report or "").strip()
    if error:
        return {
            "status": "analysis_error",
            "produced_result": False,
            "accepted_final_output": False,
            "failure_reason": error,
            "validation": validation,
        }
    if validation["blocked"]:
        latest = validation.get("latest") or {}
        reasons = list(validation.get("rejection_reasons") or [])
        failure_reason = "; ".join(reasons) or str(validation.get("feedback") or "Validation gate rejected after max replans.")
        return {
            "status": "validator_blocked",
            "produced_result": False,
            "accepted_final_output": False,
            "failure_reason": failure_reason,
            "validation": validation,
            "validator_summary": {
                "attempts": int(validation.get("retry_count") or 0),
                "max_retries": int(validation.get("max_retries") or 0),
                "last_decision": str(validation.get("last_decision") or ""),
                "rejection_reasons": reasons,
                "planner_fixes": list(latest.get("planner_fixes") or []) if isinstance(latest, dict) else [],
                "out_of_scope_work_items": list(latest.get("out_of_scope_work_items") or []) if isinstance(latest, dict) else [],
            },
        }
    if report_text:
        return {
            "status": "completed",
            "produced_result": True,
            "accepted_final_output": True,
            "failure_reason": "",
            "validation": validation,
        }
    return {
        "status": "no_result",
        "produced_result": False,
        "accepted_final_output": False,
        "failure_reason": "Pipeline completed without a non-empty final report.",
        "validation": validation,
    }


def run_agent_case(
    bundle_dir: Path,
    *,
    query: str,
    pipeline: str,
    architecture: str,
    validator_review_level: str = "default",
    tool_profile: str = "full",
    output_json: Path | None = None,
) -> Dict[str, Any]:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    bundle_dir = bundle_dir.resolve()
    bundle_readiness = inspect_bundle_dir(bundle_dir)
    if not bool(bundle_readiness.get("ready_for_analysis")):
        missing_required = list(bundle_readiness.get("missing_required") or [])
        result = {
            "bundle_dir": str(bundle_dir),
            "pipeline": pipeline,
            "architecture": architecture,
            "query": str(query or "").strip(),
            "manifest_path": "",
            "ok": False,
            "status": "analysis_error",
            "produced_result": False,
            "accepted_final_output": False,
            "failure_reason": (
                "Prepared analysis bundle is missing required files: "
                + ", ".join(missing_required)
                + ". Run the bundle-preparation step without --skip-prepare and ensure analyzeHeadless is installed."
            ),
            "bundle_readiness": bundle_readiness,
            "validator_review_level": str(validator_review_level or "default").strip() or "default",
            "validator_summary": {},
            "validation": {},
            "tool_profile": str(tool_profile or "full").strip() or "full",
            "model_usage": {"totals": {}, "by_stage": {}, "events": []},
            "cost_estimate": {},
            "duration_sec": 0.0,
            "status_log": "",
        }
        if output_json is not None:
            write_json(output_json, result)
        return result

    automation_payload_path = bundle_dir / "automation_payload.json"
    manifest_path = bundle_dir / "bundle_manifest.json"

    with tempfile.TemporaryDirectory(prefix="artifact_mcp_manifest_") as temp_dir:
        manifest_output = Path(temp_dir) / "servers.json"
        build_artifact_servers_manifest(bundle_dir, manifest_output, tool_profile=str(tool_profile or "full").strip() or "full")
        os.environ["MCP_SERVER_MANIFEST_PATH"] = str(manifest_output)

        from multi_agent_wf.pipeline import run_deepagent_pipeline
        from multi_agent_wf.runtime import get_runtime_sync, shutdown_runtime_sync
        from multi_agent_wf.shared_state import _new_shared_state, apply_automation_payload_to_state

        state = _build_initial_state(_new_shared_state)
        state["validator_review_level"] = str(validator_review_level or "default").strip() or "default"
        if isinstance(state.get("shared_state"), dict):
            state["shared_state"]["validator_review_level"] = state["validator_review_level"]
        manifest = read_json(manifest_path) if manifest_path.exists() else {}
        automation_payload = read_json(automation_payload_path) if automation_payload_path.exists() else {}
        if automation_payload:
            apply_automation_payload_to_state(state, automation_payload)

        effective_query = str(query or "").strip()
        if not effective_query:
            effective_query = (
                (((manifest.get("manifest") or {}).get("default_query")) if isinstance(manifest.get("manifest"), dict) else "")
                or "Analyze this executable at the program level and summarize the most relevant behaviors."
            )

        result: Dict[str, Any] = {
            "bundle_dir": str(bundle_dir),
            "bundle_readiness": bundle_readiness,
            "pipeline": pipeline,
            "architecture": architecture,
            "query": effective_query,
            "manifest_path": str(manifest_output),
            "tool_profile": str(tool_profile or "full").strip() or "full",
            "ok": False,
        }
        try:
            runtime = get_runtime_sync(pipeline, architecture_name=architecture)
            report = run_deepagent_pipeline(runtime, effective_query, state)
            shared = state.get("shared_state") or {}
            parsed_tool_entries = parse_tool_log_sections(state.get("tool_log_sections") or {})
            model_usage_events = list(shared.get("model_usage_events") or [])
            status_info = _derive_result_status(shared, report)
            result.update(
                {
                    "ok": True,
                    "final_report": report,
                    "status": status_info["status"],
                    "produced_result": bool(status_info["produced_result"]),
                    "accepted_final_output": bool(status_info["accepted_final_output"]),
                    "failure_reason": str(status_info.get("failure_reason") or ""),
                    "validator_review_level": str(shared.get("validator_review_level") or state.get("validator_review_level") or "default"),
                    "validator_summary": dict(status_info.get("validator_summary") or {}),
                    "validation": dict(status_info.get("validation") or {}),
                    "automation_status": str(shared.get("automation_status") or ""),
                    "auto_triage_status": str(shared.get("auto_triage_status") or ""),
                    "auto_triage_context_summary": str(shared.get("auto_triage_context_summary") or ""),
                    "planned_work_items": list(shared.get("planned_work_items") or []),
                    "ghidra_change_proposals": list(shared.get("ghidra_change_proposals") or []),
                    "generated_yara_rules": list(shared.get("generated_yara_rules") or []),
                    "tool_usage": summarize_tool_usage(parsed_tool_entries),
                    "model_usage": {
                        "totals": dict(shared.get("model_usage_totals") or {}),
                        "by_stage": dict(shared.get("model_usage_by_stage") or {}),
                        "events": model_usage_events,
                    },
                    "cost_estimate": estimate_event_costs(model_usage_events),
                    "duration_sec": float(shared.get("pipeline_duration_sec") or 0.0),
                    "tool_log_sections": state.get("tool_log_sections") or {},
                    "status_log": str(state.get("status_log") or ""),
                }
            )
        except Exception as exc:
            shared = state.get("shared_state") or {}
            model_usage_events = list(shared.get("model_usage_events") or [])
            status_info = _derive_result_status(shared, "", error="%s: %s" % (type(exc).__name__, exc))
            result.update(
                {
                    "ok": False,
                    "status": status_info["status"],
                    "produced_result": False,
                    "accepted_final_output": False,
                    "failure_reason": str(status_info.get("failure_reason") or ""),
                    "validator_review_level": str(shared.get("validator_review_level") or state.get("validator_review_level") or "default"),
                    "validator_summary": dict(status_info.get("validator_summary") or {}),
                    "validation": dict(status_info.get("validation") or {}),
                    "error": "%s: %s" % (type(exc).__name__, exc),
                    "traceback": traceback.format_exc(),
                    "model_usage": {
                        "totals": dict(shared.get("model_usage_totals") or {}),
                        "by_stage": dict(shared.get("model_usage_by_stage") or {}),
                        "events": model_usage_events,
                    },
                    "cost_estimate": estimate_event_costs(model_usage_events),
                    "duration_sec": float(shared.get("pipeline_duration_sec") or 0.0),
                    "status_log": str(state.get("status_log") or ""),
                }
            )
        finally:
            try:
                shutdown_runtime_sync()
            except Exception:
                pass

    if output_json is not None:
        write_json(output_json, result)
    return result
