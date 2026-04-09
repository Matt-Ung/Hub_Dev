"""
File: analyze.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Execute one artifact-backed agent analysis case inside the testing harness.

Summary:
  This module adapts a prepared bundle into the runtime under test, captures
  agent outputs, summarizes validation and worker-assignment outcomes, and
  writes the canonical `agent_result.json` payload used by judging and later
  analysis. It sits at the boundary between prepared test artifacts and the
  multi-agent workflow runtime.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict

from .artifacts import (
    build_artifact_servers_manifest,
    inspect_bundle_dir,
    parse_tool_log_sections,
    resolve_analysis_bundle,
    summarize_tool_usage,
)
from .costing import estimate_event_costs
from .paths import REPO_ROOT, read_json, write_json
from .tool_redundancy import normalize_tool_call_entries, summarize_tool_call_redundancy


@contextlib.contextmanager
def _fresh_harness_runtime(manifest_path: Path):
    """
    Function: _fresh_harness_runtime
    Inputs:
      - manifest_path: path to the harness-generated MCP manifest for this case.
    Description:
      Force the runtime under test to reload with harness-specific isolation
      settings so each evaluation case starts from a fresh module state and
      does not inherit persisted deep-agent memory from prior runs.
    Outputs:
      Yields a dictionary of freshly imported runtime callables.
    Side Effects:
      Mutates process env/config state for the duration of the context, reloads
      runtime modules, and clears those modules again on exit.
    """
    runtime_module_names = (
        "multi_agent_wf.shared_state",
        "multi_agent_wf.runtime",
        "multi_agent_wf.pipeline",
    )
    env_overrides = {
        "MCP_SERVER_MANIFEST_PATH": str(manifest_path),
        "DEEP_ENABLE_MEMORY": "0",
        "DEEP_PERSIST_BACKEND": "0",
        "AUTO_TRIAGE_INCLUDE_PRESWEEP_STRING_PREVIEWS": "0",
    }
    original_env = {key: os.environ.get(key) for key in env_overrides}

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    config_mod = importlib.import_module("multi_agent_wf.config")
    original_config = {
        "MCP_SERVER_MANIFEST_PATH": getattr(config_mod, "MCP_SERVER_MANIFEST_PATH", ""),
        "DEEP_ENABLE_MEMORY": getattr(config_mod, "DEEP_ENABLE_MEMORY", True),
        "DEEP_PERSIST_BACKEND": getattr(config_mod, "DEEP_PERSIST_BACKEND", True),
        "AUTO_TRIAGE_INCLUDE_PRESWEEP_STRING_PREVIEWS": getattr(
            config_mod,
            "AUTO_TRIAGE_INCLUDE_PRESWEEP_STRING_PREVIEWS",
            True,
        ),
    }

    imported: Dict[str, Any] = {}
    for key, value in env_overrides.items():
        os.environ[key] = value
        setattr(config_mod, key, value if key == "MCP_SERVER_MANIFEST_PATH" else value == "1")

    for module_name in runtime_module_names:
        sys.modules.pop(module_name, None)

    try:
        pipeline_mod = importlib.import_module("multi_agent_wf.pipeline")
        runtime_mod = importlib.import_module("multi_agent_wf.runtime")
        shared_state_mod = importlib.import_module("multi_agent_wf.shared_state")
        imported = {
            "run_deepagent_pipeline": pipeline_mod.run_deepagent_pipeline,
            "get_runtime_sync": runtime_mod.get_runtime_sync,
            "shutdown_runtime_sync": runtime_mod.shutdown_runtime_sync,
            "_new_shared_state": shared_state_mod._new_shared_state,
            "apply_automation_payload_to_state": shared_state_mod.apply_automation_payload_to_state,
        }
        yield imported
    finally:
        shutdown_runtime_sync = imported.get("shutdown_runtime_sync")
        if callable(shutdown_runtime_sync):
            try:
                shutdown_runtime_sync()
            except Exception:
                pass
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        for key, value in original_config.items():
            setattr(config_mod, key, value)
        for module_name in runtime_module_names:
            sys.modules.pop(module_name, None)


def _build_initial_state(shared_state_factory):
    """
    Function: _build_initial_state
    Inputs:
      - shared_state_factory: callable that creates the runtime shared-state
        structure.
    Description:
      Build the baseline state dictionary expected by the runtime before any
      pipeline execution begins.
    Outputs:
      Returns a new mutable state dictionary seeded with the fields the runtime
      and harness read during one analysis case.
    Side Effects:
      None.
    """
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
    """
    Function: _validation_summary
    Inputs:
      - shared: runtime shared-state dictionary accumulated during execution.
    Description:
      Collapse raw validator history fields into a smaller summary used by the
      harness when classifying the outcome of a run.
    Outputs:
      Returns a normalized summary dictionary containing retry counts, the last
      decision, latest rejection reasons, and whether validation blocked the run.
    Side Effects:
      None.
    """
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


def _worker_assignment_summary(shared: Dict[str, Any]) -> Dict[str, Any]:
    """
    Function: _worker_assignment_summary
    Inputs:
      - shared: runtime shared-state dictionary containing planned work-item
        status entries.
    Description:
      Summarize host-managed worker assignment outcomes so reporting can
      distinguish successful worker execution from blocked or failed items.
    Outputs:
      Returns counts for total, completed, and failed assignments plus a compact
      list of failed work items.
    Side Effects:
      None.
    """
    status_map = shared.get("planned_work_item_status") if isinstance(shared.get("planned_work_item_status"), dict) else {}
    failed_items = []
    completed = 0
    for work_item_id, raw_entry in status_map.items():
        entry = raw_entry if isinstance(raw_entry, dict) else {}
        status = str(entry.get("status") or "").strip().lower()
        if status == "completed":
            completed += 1
            continue
        if status in {"blocked", "failed"}:
            failed_items.append(
                {
                    "work_item_id": str(work_item_id or ""),
                    "slot_name": str(entry.get("slot_name") or ""),
                    "error": str(entry.get("error") or ""),
                    "status": status,
                    "duration_sec": entry.get("duration_sec"),
                }
            )
    return {
        "total_assignments": len(status_map),
        "completed_assignments": completed,
        "failed_assignments": len(failed_items),
        "failed_items": failed_items,
    }


def _classify_failure_reason(error: str, shared: Dict[str, Any] | None = None) -> Dict[str, Any]:
    shared = shared or {}
    pipeline_error = shared.get("last_pipeline_error") if isinstance(shared.get("last_pipeline_error"), dict) else {}
    text = str(error or pipeline_error.get("error_text") or "").strip()
    lowered = text.lower()

    category = "unknown"
    retryable = False
    source = "analysis"

    if "bundle is missing required files" in lowered:
        category = "bundle_missing_required"
        source = "bundle"
    elif "failed to resolve the effective analysis bundle" in lowered:
        category = "analysis_bundle_resolution_failed"
        source = "bundle"
    elif "wait_tasks" in lowered and "exceeded max retries count" in lowered:
        category = "async_task_tool_misuse"
        source = "pipeline"
    elif "pipeline canceled by user" in lowered or "cancelled by user" in lowered or "canceled by user" in lowered:
        category = "cancelled"
        source = "pipeline"
    elif "usagelimitexceeded" in lowered or "request_limit of 50" in lowered:
        category = "usage_limit_exceeded"
        source = "pipeline"
    elif "context_length_exceeded" in lowered or "input tokens exceed the configured limit" in lowered:
        category = "context_length_exceeded"
        source = "pipeline"
    elif "invalid_request_error" in lowered or "status_code: 400" in lowered:
        source = "pipeline"
        if "could not parse the json body" in lowered:
            category = "invalid_request_payload"
        else:
            category = "invalid_request"
    elif any(marker in lowered for marker in ("429", "rate limit", "too many requests", "ratelimit")):
        category = "rate_limit"
        retryable = True
        source = "pipeline"
    elif any(marker in lowered for marker in ("connecttimeout", "readtimeout", "timed out", "timeout")):
        category = "timeout"
        retryable = True
        source = "pipeline"
    elif any(
        marker in lowered
        for marker in (
            "remoteprotocolerror",
            "readerror",
            "peer closed connection",
            "incomplete chunked read",
            "server disconnected",
            "connection reset",
            "connection aborted",
            "apiconnectionerror",
            "service unavailable",
            "bad gateway",
            "internalservererror",
            "status_code: 500",
            "status_code: 502",
            "status_code: 503",
            "status_code: 504",
        )
    ):
        category = "transient_transport"
        retryable = True
        source = "pipeline"

    stage_name = str(pipeline_error.get("stage_name") or "").strip()
    if stage_name:
        source = "pipeline"

    return {
        "failure_category": category,
        "failure_retryable": retryable,
        "failure_source": source,
        "failure_stage": stage_name,
    }


def _derive_result_status(shared: Dict[str, Any], final_report: str, *, error: str = "") -> Dict[str, Any]:
    """
    Function: _derive_result_status
    Inputs:
      - shared: runtime shared-state dictionary after pipeline execution.
      - final_report: final report text returned by the pipeline, if any.
      - error: optional top-level runtime error string from the analysis call.
    Description:
      Convert raw runtime outcomes into the harness's normalized analysis status
      categories, including worker failures and validator blocks.
    Outputs:
      Returns a small status payload merged into `agent_result.json`.
    Side Effects:
      None.
    """
    validation = _validation_summary(shared)
    worker_summary = _worker_assignment_summary(shared)
    report_text = str(final_report or "").strip()
    if error:
        failure_details = _classify_failure_reason(error, shared)
        return {
            "status": "analysis_error",
            "produced_result": False,
            "accepted_final_output": False,
            "failure_reason": error,
            "validation": validation,
            "worker_assignment_summary": worker_summary,
            **failure_details,
        }
    if int(worker_summary.get("failed_assignments") or 0) > 0:
        failed_items = list(worker_summary.get("failed_items") or [])
        failure_reason = "; ".join(
            (
                f"{item.get('work_item_id') or 'work_item'} -> "
                f"{item.get('slot_name') or 'worker'} ({item.get('error') or item.get('status') or 'failed'})"
            )
            for item in failed_items
        ) or "One or more host-parallel worker assignments failed."
        failure_details = _classify_failure_reason(
            failure_reason,
            {
                "last_pipeline_error": {
                    "stage_name": "workers",
                    "error_text": failure_reason,
                }
            },
        )
        failure_category = str(failure_details.get("failure_category") or "").strip() or "worker_assignment_failed"
        return {
            "status": "worker_assignment_failed",
            "produced_result": False,
            "accepted_final_output": False,
            "failure_reason": failure_reason,
            "validation": validation,
            "worker_assignment_summary": worker_summary,
            "failure_category": failure_category,
            "failure_retryable": bool(failure_details.get("failure_retryable")),
            "failure_source": str(failure_details.get("failure_source") or "worker_assignments"),
            "failure_stage": str(failure_details.get("failure_stage") or "workers"),
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
            "worker_assignment_summary": worker_summary,
            "validator_summary": {
                "attempts": int(validation.get("retry_count") or 0),
                "max_retries": int(validation.get("max_retries") or 0),
                "last_decision": str(validation.get("last_decision") or ""),
                "rejection_reasons": reasons,
                "planner_fixes": list(latest.get("planner_fixes") or []) if isinstance(latest, dict) else [],
                "out_of_scope_work_items": list(latest.get("out_of_scope_work_items") or []) if isinstance(latest, dict) else [],
            },
            "failure_category": "validator_blocked",
            "failure_retryable": False,
            "failure_source": "validator",
            "failure_stage": "",
        }
    if report_text:
        return {
            "status": "completed",
            "produced_result": True,
            "accepted_final_output": True,
            "failure_reason": "",
            "validation": validation,
            "worker_assignment_summary": worker_summary,
            "failure_category": "",
            "failure_retryable": False,
            "failure_source": "",
            "failure_stage": "",
        }
    return {
        "status": "no_result",
        "produced_result": False,
        "accepted_final_output": False,
        "failure_reason": "Pipeline completed without a non-empty final report.",
        "validation": validation,
        "worker_assignment_summary": worker_summary,
        "failure_category": "no_result",
        "failure_retryable": False,
        "failure_source": "pipeline",
        "failure_stage": "",
    }

"""
Function: run_agent_case
Inputs:
  - bundle_dir: prepared bundle directory for one sample binary.
  - query: evaluation-task prompt to send into the runtime.
  - pipeline: pipeline preset name for the agent runtime.
  - architecture: worker architecture preset name for the runtime.
  - validator_review_level: validator strictness label for validated pipelines.
  - tool_profile: named tool-availability profile already reflected in the
    artifact MCP manifest.
  - output_json: optional path where the canonical agent result should be
    written.
Description:
  Run one artifact-backed analysis case against the multi-agent workflow
  runtime, capture the resulting report, tool usage, validation history,
  and failure state, and normalize the result for judging/reporting.
Outputs:
  Returns the canonical `agent_result.json` dictionary for this sample-task
  case. When `output_json` is provided, the same payload is written to disk.
Side Effects:
  Sets `MCP_SERVER_MANIFEST_PATH` for the duration of the run, imports the
  runtime modules lazily, may execute the full analysis pipeline, and may
  write the result artifact.
"""
def run_agent_case(
    bundle_dir: Path,
    *,
    query: str,
    pipeline: str,
    architecture: str,
    validator_review_level: str = "default",
    tool_profile: str = "full",
    prefer_upx_unpacked: bool = False,
    timeout_sec: int | None = None,
    ghidra_install_dir: str = "",
    ghidra_headless: str = "",
    skip_cli_tools: bool = False,
    keep_project: bool = False,
    output_json: Path | None = None,
) -> Dict[str, Any]:
    # Normalize the bundle path once so every downstream artifact reference is
    # stable and absolute in logs and result payloads.
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
            "failure_category": "bundle_missing_required",
            "failure_retryable": False,
            "failure_source": "bundle",
            "failure_stage": "",
        }
        if output_json is not None:
            write_json(output_json, result)
        return result

    bundle_resolution = resolve_analysis_bundle(
        bundle_dir,
        prefer_upx_unpacked=prefer_upx_unpacked,
        timeout_sec=timeout_sec,
        ghidra_install_dir=ghidra_install_dir,
        ghidra_headless=ghidra_headless,
        skip_cli_tools=skip_cli_tools,
        keep_project=keep_project,
    )
    effective_bundle_dir = Path(str(bundle_resolution.get("bundle_dir") or bundle_dir)).resolve()
    effective_bundle_readiness = inspect_bundle_dir(effective_bundle_dir)
    if not bool(effective_bundle_readiness.get("ready_for_analysis")):
        missing_required = list(effective_bundle_readiness.get("missing_required") or [])
        result = {
            "bundle_dir": str(bundle_dir),
            "analysis_bundle_dir": str(effective_bundle_dir),
            "source_bundle_dir": str(bundle_dir),
            "pipeline": pipeline,
            "architecture": architecture,
            "query": str(query or "").strip(),
            "manifest_path": "",
            "ok": False,
            "status": "analysis_error",
            "produced_result": False,
            "accepted_final_output": False,
            "failure_reason": (
                "Effective analysis bundle is missing required files: "
                + ", ".join(missing_required)
                + "."
            ),
            "bundle_readiness": effective_bundle_readiness,
            "source_bundle_readiness": bundle_readiness,
            "analysis_target": dict(bundle_resolution.get("analysis_target") or {}),
            "validator_review_level": str(validator_review_level or "default").strip() or "default",
            "validator_summary": {},
            "validation": {},
            "tool_profile": str(tool_profile or "full").strip() or "full",
            "model_usage": {"totals": {}, "by_stage": {}, "events": []},
            "cost_estimate": {},
            "duration_sec": 0.0,
            "status_log": "",
            "failure_category": "bundle_missing_required",
            "failure_retryable": False,
            "failure_source": "bundle",
            "failure_stage": "",
        }
        if output_json is not None:
            write_json(output_json, result)
        return result

    automation_payload_path = effective_bundle_dir / "automation_payload.json"
    manifest_path = effective_bundle_dir / "bundle_manifest.json"

    with tempfile.TemporaryDirectory(prefix="artifact_mcp_manifest_") as temp_dir:
        manifest_output = Path(temp_dir) / "servers.json"
        build_artifact_servers_manifest(
            effective_bundle_dir,
            manifest_output,
            tool_profile=str(tool_profile or "full").strip() or "full",
            analysis_target_kind=str(((bundle_resolution.get("analysis_target") or {}) if isinstance(bundle_resolution.get("analysis_target"), dict) else {}).get("kind") or ""),
        )
        with _fresh_harness_runtime(manifest_output) as runtime_parts:
            run_deepagent_pipeline = runtime_parts["run_deepagent_pipeline"]
            get_runtime_sync = runtime_parts["get_runtime_sync"]
            _new_shared_state = runtime_parts["_new_shared_state"]
            apply_automation_payload_to_state = runtime_parts["apply_automation_payload_to_state"]

            # Seed the runtime with the same shared-state layout the interactive
            # workflow expects, then inject any automation payload bundled for the
            # sample before executing the pipeline.
            state = _build_initial_state(_new_shared_state)
            run_label = (
                f"pid-{os.getpid()}:{output_json.parent.name}"
                if output_json is not None and output_json.parent.name
                else f"pid-{os.getpid()}:analysis"
            )
            state["active_run_id"] = run_label
            state["validator_review_level"] = str(validator_review_level or "default").strip() or "default"
            if isinstance(state.get("shared_state"), dict):
                state["shared_state"]["validator_review_level"] = state["validator_review_level"]
            manifest = (
                dict(bundle_resolution.get("bundle_manifest") or {})
                if isinstance(bundle_resolution.get("bundle_manifest"), dict)
                else {}
            )
            if not manifest:
                manifest = read_json(manifest_path) if manifest_path.exists() else {}
            automation_payload = (
                dict(bundle_resolution.get("automation_payload") or {})
                if isinstance(bundle_resolution.get("automation_payload"), dict)
                else {}
            )
            if not automation_payload:
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
                "bundle_dir": str(effective_bundle_dir),
                "analysis_bundle_dir": str(effective_bundle_dir),
                "source_bundle_dir": str(bundle_dir),
                "bundle_readiness": effective_bundle_readiness,
                "source_bundle_readiness": bundle_readiness,
                "pipeline": pipeline,
                "architecture": architecture,
                "query": effective_query,
                "manifest_path": str(manifest_output),
                "analysis_bundle_manifest_path": str(manifest_path),
                "analysis_target": dict(bundle_resolution.get("analysis_target") or {}),
                "tool_profile": str(tool_profile or "full").strip() or "full",
                "ok": False,
            }
            try:
                runtime = get_runtime_sync(pipeline, architecture_name=architecture)
                report = run_deepagent_pipeline(runtime, effective_query, state)
                shared = state.get("shared_state") or {}
                parsed_tool_entries = parse_tool_log_sections(state.get("tool_log_sections") or {})
                normalized_tool_calls = normalize_tool_call_entries(parsed_tool_entries)
                tool_redundancy = summarize_tool_call_redundancy(
                    parsed_tool_entries,
                    normalized_calls=normalized_tool_calls,
                )
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
                        "worker_assignment_summary": dict(status_info.get("worker_assignment_summary") or {}),
                        "failure_category": str(status_info.get("failure_category") or ""),
                        "failure_retryable": bool(status_info.get("failure_retryable")),
                        "failure_source": str(status_info.get("failure_source") or ""),
                        "failure_stage": str(status_info.get("failure_stage") or ""),
                        "automation_status": str(shared.get("automation_status") or ""),
                        "auto_triage_status": str(shared.get("auto_triage_status") or ""),
                        "auto_triage_context_summary": str(shared.get("auto_triage_context_summary") or ""),
                        "planned_work_items": list(shared.get("planned_work_items") or []),
                        "ghidra_change_proposals": list(shared.get("ghidra_change_proposals") or []),
                        "generated_yara_rules": list(shared.get("generated_yara_rules") or []),
                        "tool_usage": summarize_tool_usage(parsed_tool_entries),
                        "normalized_tool_calls": normalized_tool_calls,
                        "tool_redundancy": tool_redundancy,
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
                        "worker_assignment_summary": dict(status_info.get("worker_assignment_summary") or {}),
                        "failure_category": str(status_info.get("failure_category") or ""),
                        "failure_retryable": bool(status_info.get("failure_retryable")),
                        "failure_source": str(status_info.get("failure_source") or ""),
                        "failure_stage": str(status_info.get("failure_stage") or ""),
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

    if output_json is not None:
        write_json(output_json, result)
    return result
