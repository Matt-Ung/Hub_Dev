"""
File: runner.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Execute one complete testing-harness run for a single configuration.

Summary:
  This module implements the canonical single-run path for the maintained
  binary benchmark. It resolves the requested sample-task scope, performs
  preflight and optional preparation steps, runs agent analysis and judging,
  writes canonical artifacts, and updates the live-status state used by the
  sweep monitor and experiment orchestration layers.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

from .analyze import run_agent_case
from .artifacts import inspect_corpus_bundles, prepare_corpus_bundles
from .budgeting import (
    evaluate_budget_status,
    evaluate_projected_experiment_budget,
    project_experiment_budget,
    resolve_budget_config,
    summarize_record_budget,
)
from .building import build_corpus
from .lineage import compute_lineage_id, normalize_run_lineage_payload, refresh_lineage_index_for_run
from .paths import BUNDLE_ROOT, RESULTS_ROOT, RUNS_ROOT, build_run_id, ensure_dir, read_json, write_json
from .preflight import validate_run_configuration
from .query_variants import apply_query_variant
from .result_layout import build_run_output_layout
from .reporting import aggregate_records, build_sample_record, write_markdown_report, write_summary_csv
from .samples import build_evaluation_tasks, get_corpus_config, list_sample_binaries, load_sample_manifest, resolve_sample_metadata, sample_slug


def _parse_metadata(values: List[str]) -> Dict[str, str]:
    """
    Function: _parse_metadata
    Inputs:
      - values: CLI metadata fragments in `key=value` form.
    Description:
      Normalize optional run metadata flags into the dictionary stored in the
      run manifest and lineage records.
    Outputs:
      Returns a dictionary of parsed metadata entries. Malformed fragments are
      ignored instead of aborting the run.
    Side Effects:
      None.
    """
    parsed: Dict[str, str] = {}
    for item in values:
        if "=" not in str(item):
            continue
        key, value = str(item).split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            parsed[key] = value
    return parsed


def _emit_progress(message: str) -> None:
    """
    Function: _emit_progress
    Inputs:
      - message: human-readable progress message for the current run.
    Description:
      Emit a standardized progress line for interactive monitoring.
    Outputs:
      Returns nothing.
    Side Effects:
      Writes one line to stderr.
    """
    print(f"[eval] {message}", file=sys.stderr, flush=True)


def _write_live_status(run_dir: Path, payload: Dict[str, Any]) -> None:
    """
    Function: _write_live_status
    Inputs:
      - run_dir: root output directory for the active run.
      - payload: current live-status snapshot to persist.
    Description:
      Write the latest live-status snapshot used by the polling monitor.
    Outputs:
      Returns nothing.
    Side Effects:
      Overwrites `live_status.json` inside the run directory.
    """
    write_json(run_dir / "live_status.json", payload)


def _build_terminal_live_status(
    *,
    run_budget_status: Dict[str, Any],
    completed_task_count: int,
    expected_task_count: int,
) -> Dict[str, str]:
    """
    Function: _build_terminal_live_status
    Inputs:
      - run_budget_status: final cumulative budget evaluation for the run.
      - completed_task_count: number of finished sample-task records.
      - expected_task_count: total number of planned sample-task records.
    Description:
      Convert the final run-budget outcome into a user-facing terminal live
      status that distinguishes normal completion from a completed result that
      merely crossed budget on the last task, and from a true early stop.
    Outputs:
      Returns a compact live-status fragment with terminal status fields.
    Side Effects:
      None.
    """
    budget_exceeded = not bool(run_budget_status.get("ok", True))
    aborted_early = bool(run_budget_status.get("aborted_early"))
    if budget_exceeded and aborted_early and completed_task_count < expected_task_count:
        return {
            "status": "budget_exceeded",
            "stage": "budget_exceeded",
            "current_phase": "budget_exceeded",
            "last_message": (
                f"Run stopped after {completed_task_count} completed task(s) because the cumulative run budget was exceeded."
            ),
        }
    if budget_exceeded:
        return {
            "status": "completed_budget_exceeded",
            "stage": "completed",
            "current_phase": "completed",
            "last_message": (
                "Run complete; the final completed task pushed the cumulative run budget over its configured limit."
            ),
        }
    return {
        "status": "completed",
        "stage": "completed",
        "current_phase": "completed",
        "last_message": "Run complete.",
    }


@contextlib.contextmanager
def _heartbeat(message: str, interval_sec: int = 30):
    """
    Function: _heartbeat
    Inputs:
      - message: status text to repeat while a long-running step is active.
      - interval_sec: heartbeat interval in seconds.
    Description:
      Context manager that spawns a lightweight background ticker so long
      analysis steps still show terminal progress.
    Outputs:
      Yields control back to the wrapped code block.
    Side Effects:
      Starts and stops a daemon thread that emits progress messages.
    """
    stop = threading.Event()
    start = time.monotonic()

    def _worker() -> None:
        while not stop.wait(max(1, int(interval_sec))):
            elapsed = int(time.monotonic() - start)
            _emit_progress(f"{message} still running ({elapsed}s elapsed)")

    thread = threading.Thread(target=_worker, name="eval-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1)


def main(argv: List[str] | None = None) -> None:
    """
    Function: main
    Inputs:
      - argv: optional explicit argument list. When omitted, arguments are read
        from the process command line.
    Description:
      Execute the canonical single-run harness workflow: resolve scope, perform
      preflight, run analysis and judging, aggregate records, and write the run
      outputs used by later experiment comparison.
    Outputs:
      Returns nothing. Exits with an error if required inputs are invalid or if
      the run cannot be completed.
    Side Effects:
      May build binaries, prepare bundles, invoke the runtime and judge models,
      write run artifacts, and update live-progress state.
    """
    parser = argparse.ArgumentParser(description="Unified testing workflow: build -> prepare bundles -> run agent -> judge -> aggregate")
    parser.add_argument("--corpus", choices=["prototype", "experimental"], default="experimental")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample filename(s) to restrict to")
    parser.add_argument("--task", action="append", default=[], help="Optional task id(s) to restrict to when the sample manifest defines multiple evaluation tasks")
    parser.add_argument("--difficulty-filter", action="append", default=[], help="Optional difficulty label(s) to restrict to, e.g. --difficulty-filter medium --difficulty-filter hard")
    parser.add_argument("--pipeline", default="", help="Pipeline preset override")
    parser.add_argument("--architecture", default="", help="Architecture preset override")
    parser.add_argument("--query", default="", help="Optional fixed query override for all samples")
    parser.add_argument("--query-variant", default="default", help="Prompt/query detail variant name")
    parser.add_argument("--subagent-profile", default="default", help="Worker subagent breadth profile override")
    parser.add_argument("--worker-persona-profile", default="default", help="Worker-stage persona prompt overlay profile")
    parser.add_argument("--validator-review-level", default="default", help="Validator review strictness: easy, default, intermediate, or strict")
    parser.add_argument("--tool-profile", default="full", help="Named MCP tool-availability profile for analysis ablations")
    parser.add_argument("--model-profile", default="", help="Experiment model profile label for reporting (for example: repo_default, budget, premium)")
    parser.add_argument("--force-model", default="", help="Optional model ID to force across the run")
    parser.add_argument("--label", default="", help="Optional short label for this run")
    parser.add_argument("--run-id", default="", help="Optional explicit run id override. Used by sweep live-view mode to create a predictable run directory.")
    parser.add_argument("--experiment-id", default="", help="Optional experiment sweep identifier")
    parser.add_argument("--variant-name", default="", help="Optional experiment variant name")
    parser.add_argument("--changed-variable", default="", help="Optional changed variable label for sweep runs")
    parser.add_argument("--comparison-baseline-id", default="", help="Optional baseline variant id this run should be compared against")
    parser.add_argument("--comparison-baseline-label", default="", help="Optional human-readable comparison baseline label")
    parser.add_argument("--replicate-index", type=int, default=1, help="1-based replicate index for repeated sweep runs")
    parser.add_argument("--replicate-count", type=int, default=1, help="Planned replicate count for this configuration")
    parser.add_argument("--meta", action="append", default=[], help="Extra experiment metadata in key=value form")
    parser.add_argument("--skip-build", action="store_true", help="Reuse existing binaries in Testing/build")
    parser.add_argument("--clean-build", action="store_true", help="Run make clean before rebuilding")
    parser.add_argument("--skip-prepare", action="store_true", help="Reuse existing analysis bundles")
    parser.add_argument("--skip-cli-tools", action="store_true", help="Skip optional CLI tool collection while preparing bundles")
    parser.add_argument("--keep-project", action="store_true", help="Preserve temporary Ghidra headless projects")
    parser.add_argument("--ghidra-install-dir", default="", help="Optional GHIDRA_INSTALL_DIR override")
    parser.add_argument("--ghidra-headless", default="", help="Optional analyzeHeadless override")
    parser.add_argument("--judge-mode", choices=["agent", "disabled"], default="agent")
    parser.add_argument("--judge-model", default="", help="Optional judge model override")
    parser.add_argument("--max-run-input-tokens", type=int, default=None, help="Abort the run after the current task if cumulative agent+judge input tokens exceed this ceiling")
    parser.add_argument("--max-run-output-tokens", type=int, default=None, help="Abort the run after the current task if cumulative agent+judge output tokens exceed this ceiling")
    parser.add_argument("--max-run-total-tokens", type=int, default=None, help="Abort the run after the current task if cumulative agent+judge input+output tokens exceed this ceiling")
    parser.add_argument("--max-run-relative-cost-index", type=float, default=None, help="Abort the run after the current task if the cumulative relative cost index exceeds this ceiling")
    parser.add_argument("--max-run-estimated-cost-usd", type=float, default=None, help="Advisory warning threshold for cumulative estimated USD cost. This is surfaced in preflight and budget_status.json but does not abort the run by itself.")
    parser.add_argument("--hard-max-run-estimated-cost-usd", type=float, default=None, help="Optional explicit hard-stop ceiling for cumulative estimated USD cost.")
    parser.add_argument("--timeout-sec", type=int, default=0, help="Optional subprocess timeout in seconds for build, bundle prep, and external child tools; 0 disables it")
    parser.add_argument("--preflight-only", action="store_true", help="Validate rubric/config/build/bundle readiness and exit without running agents")
    args = parser.parse_args(argv)

    config = get_corpus_config(args.corpus)
    manifest = load_sample_manifest(args.corpus)
    run_id = str(args.run_id or "").strip() or build_run_id("eval", args.corpus, args.label)
    run_dir = ensure_dir(RUNS_ROOT / run_id)
    sample_root = ensure_dir(run_dir / "samples")

    # Tutorial 5.3 in multi_agent_wf/extension_tutorial.md: mirror any new
    # env-driven workflow knob here so single runs and sweep child runs use the
    # same runtime configuration path.
    os.environ["DEEP_WORKER_SUBAGENT_PROFILE"] = str(args.subagent_profile or "default").strip() or "default"
    os.environ["DEEP_WORKER_PERSONA_PROFILE"] = str(args.worker_persona_profile or "default").strip() or "default"
    if str(args.force_model or "").strip():
        os.environ["DEEP_FORCE_MODEL_ID"] = str(args.force_model).strip()
    else:
        os.environ.pop("DEEP_FORCE_MODEL_ID", None)

    # This manifest becomes the source-of-truth for the run configuration, so
    # later records, lineage state, and experiment summaries can all trace back
    # to the exact same normalized knob set.
    run_metadata: Dict[str, Any] = {
        "run_id": run_id,
        "corpus": args.corpus,
        "pipeline": args.pipeline or config.default_pipeline,
        "architecture": args.architecture or config.default_architecture,
        "query_override": str(args.query or "").strip(),
        "query_variant": str(args.query_variant or "default").strip() or "default",
        "subagent_profile": str(args.subagent_profile or "default").strip() or "default",
        "worker_persona_profile": str(args.worker_persona_profile or "default").strip() or "default",
        "validator_review_level": str(args.validator_review_level or "default").strip() or "default",
        "tool_profile": str(args.tool_profile or "full").strip() or "full",
        "model_profile": str(args.model_profile or "").strip(),
        "force_model": str(args.force_model or "").strip(),
        "judge_mode": args.judge_mode,
        "judge_model": str(args.judge_model or os.environ.get("EVAL_JUDGE_MODEL") or "").strip(),
        "label": args.label,
        "experiment_id": str(args.experiment_id or "").strip(),
        "variant_name": str(args.variant_name or "").strip(),
        "changed_variable": str(args.changed_variable or "").strip(),
        "comparison_baseline_id": str(args.comparison_baseline_id or "").strip(),
        "comparison_baseline_label": str(args.comparison_baseline_label or "").strip(),
        "replicate_index": max(1, int(args.replicate_index or 1)),
        "replicate_count": max(1, int(args.replicate_count or 1)),
        "metadata": _parse_metadata(args.meta),
        "selected_samples": args.sample,
        "selected_tasks": args.task,
        "selected_difficulties": args.difficulty_filter,
    }
    run_metadata["config_lineage_id"] = compute_lineage_id(run_metadata)
    run_metadata["config_lineage_key"] = normalize_run_lineage_payload(run_metadata)
    budget_config = resolve_budget_config(
        max_run_input_tokens=args.max_run_input_tokens,
        max_run_output_tokens=args.max_run_output_tokens,
        max_run_total_tokens=args.max_run_total_tokens,
        max_run_relative_cost_index=args.max_run_relative_cost_index,
        max_run_estimated_cost_usd=args.max_run_estimated_cost_usd,
        hard_max_run_estimated_cost_usd=args.hard_max_run_estimated_cost_usd,
    )
    run_metadata["budget_config"] = budget_config
    write_json(run_dir / "run_manifest.json", run_metadata)

    live_status: Dict[str, Any] = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "status": "running",
        "stage": "initializing",
        "current_task_index": 0,
        "completed_task_count": 0,
        "expected_task_count": 0,
        "current_sample": "",
        "current_task_id": "",
        "current_phase": "",
        "last_message": "Run initialized.",
        "started_at_epoch": time.time(),
        "updated_at_epoch": time.time(),
        "tasks": [],
        "preflight_ok": None,
    }
    _write_live_status(run_dir, live_status)

    build_record: Dict[str, Any] = {"skipped": True}
    live_status.update(
        {
            "stage": "build",
            "current_phase": "build",
            "last_message": "Building binaries." if not args.skip_build else "Skipping build step.",
            "updated_at_epoch": time.time(),
        }
    )
    _write_live_status(run_dir, live_status)
    if not args.skip_build:
        build_record = build_corpus(
            args.corpus,
            clean_first=args.clean_build,
            include_gcc=True,
            timeout_sec=args.timeout_sec,
        )
    write_json(run_dir / "build_record.json", build_record)

    sample_paths = list_sample_binaries(args.corpus, selected=args.sample, difficulty_filters=args.difficulty_filter, manifest=manifest)
    if not sample_paths:
        raise SystemExit(f"No built sample binaries found for corpus={args.corpus} under {config.build_root}")
    evaluation_tasks = build_evaluation_tasks(
        args.corpus,
        sample_paths,
        manifest=manifest,
        selected_task_ids=args.task,
        selected_difficulties=args.difficulty_filter,
    )
    if not evaluation_tasks:
        raise SystemExit(f"No evaluation tasks resolved for corpus={args.corpus}; check the sample manifest task definitions.")
    run_metadata["expected_task_count"] = len(evaluation_tasks)
    write_json(run_dir / "run_manifest.json", run_metadata)
    live_status["expected_task_count"] = len(evaluation_tasks)
    live_status["tasks"] = [
        {
            "sample": task.sample_name,
            "task_id": task.task_id,
            "task_name": task.task_name,
            "sample_task_id": f"{task.sample_name}::{task.task_id}",
            "status": "pending",
            "judge_status": "",
            "score": None,
        }
        for task in evaluation_tasks
    ]
    live_status["updated_at_epoch"] = time.time()
    _write_live_status(run_dir, live_status)

    bundle_root = ensure_dir(BUNDLE_ROOT / args.corpus)
    prepare_record: Dict[str, Any] = {"skipped": True}
    live_status.update(
        {
            "stage": "prepare",
            "current_phase": "prepare",
            "last_message": "Preparing bundles." if not args.skip_prepare else "Skipping bundle preparation.",
            "updated_at_epoch": time.time(),
        }
    )
    _write_live_status(run_dir, live_status)
    if not args.skip_prepare:
        prepare_record = prepare_corpus_bundles(
            args.corpus,
            sample_paths,
            manifest.get("samples") or {},
            output_root=bundle_root,
            timeout_sec=args.timeout_sec,
            ghidra_install_dir=args.ghidra_install_dir,
            ghidra_headless=args.ghidra_headless,
            skip_cli_tools=args.skip_cli_tools,
            keep_project=args.keep_project,
        )
    write_json(run_dir / "prepare_record.json", prepare_record)
    bundle_readiness = inspect_corpus_bundles(args.corpus, sample_paths, output_root=bundle_root)
    write_json(run_dir / "bundle_readiness.json", bundle_readiness)
    preflight = validate_run_configuration(
        corpus_name=args.corpus,
        sample_paths=sample_paths,
        manifest=manifest,
        selected_samples=args.sample,
        selected_task_ids=args.task,
        selected_difficulties=args.difficulty_filter,
        pipeline=run_metadata["pipeline"],
        architecture=run_metadata["architecture"],
        query_variant=run_metadata["query_variant"],
        worker_persona_profile=run_metadata["worker_persona_profile"],
        validator_review_level=run_metadata["validator_review_level"],
        tool_profile=run_metadata["tool_profile"],
        judge_mode=args.judge_mode,
        explicit_judge_model=str(args.judge_model or "").strip(),
        forced_model=run_metadata["force_model"],
        python_executable=sys.executable,
        bundle_root=bundle_root,
        require_ready_bundles=True,
    )
    run_budget_projection = project_experiment_budget(
        child_runs=1,
        tasks_per_child_run=len(evaluation_tasks),
        config=budget_config,
    )
    run_budget_projection_status = evaluate_projected_experiment_budget(run_budget_projection, {
        **budget_config,
        "max_experiment_relative_cost_index": budget_config.get("max_run_relative_cost_index"),
        "max_experiment_estimated_cost_usd": budget_config.get("max_run_estimated_cost_usd"),
        "hard_max_experiment_estimated_cost_usd": budget_config.get("hard_max_run_estimated_cost_usd"),
    })
    preflight["budget_projection"] = run_budget_projection
    preflight["budget_projection_status"] = run_budget_projection_status
    if run_budget_projection_status.get("warnings"):
        preflight.setdefault("warnings", []).extend(
            [f"budget_projection: {item}" for item in (run_budget_projection_status.get("warnings") or [])]
        )
    if not run_budget_projection_status.get("ok"):
        preflight["ok"] = False
        preflight.setdefault("errors", []).extend(
            [f"budget_projection: {item}" for item in (run_budget_projection_status.get("exceeded") or [])]
        )
    write_json(run_dir / "preflight.json", preflight)
    live_status.update(
        {
            "stage": "preflight",
            "current_phase": "preflight",
            "preflight_ok": bool(preflight.get("ok")),
            "last_message": "Preflight validation completed.",
            "updated_at_epoch": time.time(),
        }
    )
    _write_live_status(run_dir, live_status)
    if args.preflight_only:
        live_status.update(
            {
                "status": "completed" if bool(preflight.get("ok")) else "failed",
                "stage": "preflight_only",
                "current_phase": "preflight_only",
                "last_message": "Preflight-only run finished.",
                "updated_at_epoch": time.time(),
            }
        )
        _write_live_status(run_dir, live_status)
        print(json.dumps({"run_id": run_id, "run_dir": str(run_dir), "preflight_ok": bool(preflight.get("ok"))}, indent=2))
        if not preflight.get("ok"):
            raise SystemExit("Preflight validation failed; see preflight.json for details.")
        return
    if not preflight.get("ok"):
        live_status.update(
            {
                "status": "failed",
                "stage": "preflight_failed",
                "current_phase": "preflight",
                "last_message": "Preflight validation failed.",
                "updated_at_epoch": time.time(),
            }
        )
        _write_live_status(run_dir, live_status)
        raise SystemExit("Preflight validation failed; see preflight.json for details before spending on agent runs.")

    _emit_progress(
        f"Starting run {run_id}: {len(evaluation_tasks)} task(s), pipeline={run_metadata['pipeline']}, "
        f"architecture={run_metadata['architecture']}, query_variant={run_metadata['query_variant']}"
    )
    records: List[Dict[str, Any]] = []
    run_budget_status: Dict[str, Any] = {
        "scope": "run",
        "ok": True,
        "exceeded": [],
        "warnings": [],
        "observed": {},
        "limits": budget_config,
        "aborted_early": False,
    }
    run_budget_triggered = False
    for task_index, task in enumerate(evaluation_tasks, start=1):
        sample_path = task.sample_path
        slug = sample_slug(sample_path)
        task_slug = f"{slug}__{task.task_id}"
        sample_dir = ensure_dir(sample_root / task_slug)
        sample_meta = resolve_sample_metadata(args.corpus, sample_path.name, manifest=manifest)
        bundle_dir = bundle_root / slug
        bundle_manifest = read_json(bundle_dir / "bundle_manifest.json") if (bundle_dir / "bundle_manifest.json").exists() else {}

        base_query = str(args.query or "").strip() or str(task.query or "").strip()
        effective_query = apply_query_variant(base_query, sample_meta, run_metadata["query_variant"])
        live_status.update(
            {
                "stage": "analysis",
                "current_task_index": task_index,
                "current_sample": sample_path.name,
                "current_task_id": task.task_id,
                "current_phase": "analysis",
                "last_message": f"Starting analysis for {sample_path.name} :: {task.task_id}",
                "updated_at_epoch": time.time(),
            }
        )
        live_status["tasks"][task_index - 1]["status"] = "running"
        _write_live_status(run_dir, live_status)
        _emit_progress(
            f"[{task_index}/{len(evaluation_tasks)}] Starting analysis for {sample_path.name} :: {task.task_id}"
        )
        task_started = time.monotonic()
        task_started_epoch = time.time()
        with _heartbeat(f"Analysis for {sample_path.name} :: {task.task_id}"):
            agent_result = run_agent_case(
                bundle_dir,
                query=effective_query,
                pipeline=run_metadata["pipeline"],
                architecture=run_metadata["architecture"],
                validator_review_level=run_metadata["validator_review_level"],
                tool_profile=run_metadata["tool_profile"],
                output_json=sample_dir / "agent_result.json",
            )
        _emit_progress(
            f"[{task_index}/{len(evaluation_tasks)}] Analysis finished for {sample_path.name} :: {task.task_id} "
            f"status={agent_result.get('status', 'unknown')} elapsed={int(time.monotonic() - task_started)}s"
        )
        live_status.update(
            {
                "stage": "judge" if args.judge_mode == "agent" else "analysis",
                "current_phase": "judge" if args.judge_mode == "agent" else "analysis_complete",
                "last_message": (
                    f"Analysis finished for {sample_path.name} :: {task.task_id} "
                    f"status={agent_result.get('status', 'unknown')}"
                ),
                "updated_at_epoch": time.time(),
            }
        )
        live_status["tasks"][task_index - 1]["status"] = str(agent_result.get("status") or "completed")
        _write_live_status(run_dir, live_status)

        judge_result = None
        if args.judge_mode == "agent":
            from .judge import judge_agent_result

            live_status.update(
                {
                    "stage": "judge",
                    "current_phase": "judge",
                    "last_message": f"Starting judge for {sample_path.name} :: {task.task_id}",
                    "updated_at_epoch": time.time(),
                }
            )
            _write_live_status(run_dir, live_status)
            _emit_progress(f"[{task_index}/{len(evaluation_tasks)}] Starting judge for {sample_path.name} :: {task.task_id}")
            judge_started = time.monotonic()
            with _heartbeat(f"Judge for {sample_path.name} :: {task.task_id}"):
                judge_result = judge_agent_result(
                    sample_path.name,
                    sample_meta,
                    {
                        "task_id": task.task_id,
                        "task_name": task.task_name,
                        "query": effective_query,
                        "target_tools": list(task.target_tools),
                        "expected_evidence": list(task.expected_evidence),
                        "acceptance_targets": list(task.acceptance_targets),
                        "tags": list(task.tags),
                    },
                    bundle_manifest,
                    agent_result,
                    judge_model=args.judge_model,
                    output_json=sample_dir / "judge_result.json",
                )
            _emit_progress(
                f"[{task_index}/{len(evaluation_tasks)}] Judge finished for {sample_path.name} :: {task.task_id} "
                f"status={judge_result.get('status', 'unknown') if isinstance(judge_result, dict) else 'n/a'} "
                f"elapsed={int(time.monotonic() - judge_started)}s"
            )
            live_status.update(
                {
                    "last_message": (
                        f"Judge finished for {sample_path.name} :: {task.task_id} "
                        f"status={judge_result.get('status', 'unknown') if isinstance(judge_result, dict) else 'n/a'}"
                    ),
                    "updated_at_epoch": time.time(),
                }
            )
            live_status["tasks"][task_index - 1]["judge_status"] = str(judge_result.get("status") or "") if isinstance(judge_result, dict) else ""
            _write_live_status(run_dir, live_status)

        record = build_sample_record(
            sample_path.name,
            sample_meta,
            {
                "task_id": task.task_id,
                "task_name": task.task_name,
                "query": effective_query,
                "target_tools": list(task.target_tools),
                "expected_evidence": list(task.expected_evidence),
                "acceptance_targets": list(task.acceptance_targets),
                "tags": list(task.tags),
            },
            bundle_manifest,
            agent_result,
            judge_result,
            {
                "started_at_epoch": task_started_epoch,
                "finished_at_epoch": time.time(),
                "wall_clock_duration_sec": round(time.monotonic() - task_started, 6),
            },
        )
        write_json(sample_dir / "record.json", record)
        records.append(record)
        live_status["completed_task_count"] = len(records)
        live_status["tasks"][task_index - 1]["status"] = str((record.get("metrics") or {}).get("analysis_status") or live_status["tasks"][task_index - 1]["status"] or "completed")
        live_status["tasks"][task_index - 1]["judge_status"] = str((record.get("metrics") or {}).get("judge_status") or live_status["tasks"][task_index - 1].get("judge_status") or "")
        live_status["tasks"][task_index - 1]["score"] = (record.get("metrics") or {}).get("overall_score_0_to_100")
        live_status["last_message"] = f"Recorded result for {sample_path.name} :: {task.task_id}"
        live_status["updated_at_epoch"] = time.time()
        _write_live_status(run_dir, live_status)
        _emit_progress(
            f"[{task_index}/{len(evaluation_tasks)}] Recorded result for {sample_path.name} :: {task.task_id} "
            f"analysis_status={(record.get('metrics') or {}).get('analysis_status')} "
            f"score={(record.get('metrics') or {}).get('overall_score_0_to_100')}"
        )
        budget_summary = summarize_record_budget(records)
        run_budget_status = evaluate_budget_status(budget_summary, budget_config, scope="run")
        run_budget_status["aborted_early"] = False
        write_json(run_dir / "budget_status.json", run_budget_status)
        if not run_budget_status.get("ok") and bool(budget_config.get("abort_on_run_budget_exceeded", True)):
            run_budget_triggered = True
            budget_exceeded_before_remaining_tasks = task_index < len(evaluation_tasks)
            run_budget_status["aborted_early"] = budget_exceeded_before_remaining_tasks
            write_json(run_dir / "budget_status.json", run_budget_status)
            if budget_exceeded_before_remaining_tasks:
                for remaining_index in range(task_index, len(evaluation_tasks)):
                    if live_status["tasks"][remaining_index]["status"] == "pending":
                        live_status["tasks"][remaining_index]["status"] = "not_run_budget_exceeded"
                last_message = f"Run budget exceeded after {task_index} completed task(s); remaining tasks will not run."
                progress_message = f"Run budget exceeded; stopping before remaining task(s) after {task_index} completed task(s)"
            else:
                last_message = "Run budget exceeded after the final completed task; aggregating completed results."
                progress_message = "Run budget exceeded after the final completed task; aggregating completed results"
            live_status.update(
                {
                    "stage": "budget_limit_reached",
                    "current_phase": "budget_limit_reached",
                    "last_message": last_message,
                    "updated_at_epoch": time.time(),
                }
            )
            _write_live_status(run_dir, live_status)
            _emit_progress(progress_message)
            break

    live_status.update(
        {
            "stage": "aggregate",
            "current_phase": "aggregate",
            "last_message": "Aggregating run results.",
            "updated_at_epoch": time.time(),
        }
    )
    _write_live_status(run_dir, live_status)
    aggregate = aggregate_records(run_metadata, records)
    aggregate["run_budget_status"] = run_budget_status
    terminal_live_status = _build_terminal_live_status(
        run_budget_status=run_budget_status,
        completed_task_count=len(records),
        expected_task_count=len(evaluation_tasks),
    )
    aggregate["terminal_status"] = terminal_live_status["status"]
    aggregate["budget_limit_reached"] = run_budget_triggered or not bool(run_budget_status.get("ok", True))
    aggregate["budget_warning_triggered"] = bool(run_budget_status.get("warnings"))
    write_json(run_dir / "aggregate.json", aggregate)
    lineage_payload = refresh_lineage_index_for_run(
        run_dir=run_dir,
        run_manifest=run_metadata,
        aggregate=aggregate,
    )
    aggregate["config_lineage_id"] = run_metadata.get("config_lineage_id")
    aggregate["config_lineage_path"] = str((RESULTS_ROOT / "lineages" / f"{run_metadata.get('config_lineage_id')}.json").resolve())
    aggregate["config_lineage_run_count"] = lineage_payload.get("run_count")
    write_json(run_dir / "aggregate.json", aggregate)
    write_summary_csv(run_dir / "summary.csv", records, run_metadata)
    write_markdown_report(run_dir / "report.md", aggregate)
    layout_payload = build_run_output_layout(
        run_dir=run_dir,
        run_manifest=run_metadata,
        aggregate=aggregate,
    )
    write_json(run_dir / "result_layout.json", layout_payload)
    _emit_progress(
        f"Run complete: {len(records)} record(s), mean_score={aggregate.get('overall_score_mean')}, "
        f"task_success_rate={aggregate.get('task_success_rate')}"
    )
    live_status.update(
        {
            **terminal_live_status,
            "current_sample": "",
            "current_task_id": "",
            "updated_at_epoch": time.time(),
        }
    )
    _write_live_status(run_dir, live_status)

    completion_payload = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "sample_count": len(records),
        "status": terminal_live_status["status"],
        "budget_limit_reached": aggregate["budget_limit_reached"],
    }
    print(json.dumps(completion_payload, indent=2))
    print("EVAL_RUN_RESULT_JSON::" + json.dumps(completion_payload, ensure_ascii=False, sort_keys=True))
