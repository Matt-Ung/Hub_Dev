from __future__ import annotations

"""
Single-configuration evaluation entry point.

This script is the canonical path for one run configuration:
build -> bundle prep -> per-sample-task analysis -> judging -> aggregation.

If you need to add a new run-level knob, wire it through:
- CLI args here
- env passthrough here when the runtime reads it from process env
- `run_metadata`
- preflight validation
- reporting fields if the knob should appear in outputs
"""

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
    print(f"[eval] {message}", file=sys.stderr, flush=True)


@contextlib.contextmanager
def _heartbeat(message: str, interval_sec: int = 30):
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
    parser.add_argument("--max-run-estimated-cost-usd", type=float, default=None, help="Abort the run after the current task if the cumulative estimated USD cost exceeds this ceiling")
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument("--preflight-only", action="store_true", help="Validate rubric/config/build/bundle readiness and exit without running agents")
    args = parser.parse_args(argv)

    config = get_corpus_config(args.corpus)
    manifest = load_sample_manifest(args.corpus)
    run_id = build_run_id("eval", args.corpus, args.label)
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
    )
    run_metadata["budget_config"] = budget_config
    write_json(run_dir / "run_manifest.json", run_metadata)

    build_record: Dict[str, Any] = {"skipped": True}
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

    bundle_root = ensure_dir(BUNDLE_ROOT / args.corpus)
    prepare_record: Dict[str, Any] = {"skipped": True}
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
    })
    preflight["budget_projection"] = run_budget_projection
    preflight["budget_projection_status"] = run_budget_projection_status
    if not run_budget_projection_status.get("ok"):
        preflight["ok"] = False
        preflight.setdefault("errors", []).extend(
            [f"budget_projection: {item}" for item in (run_budget_projection_status.get("exceeded") or [])]
        )
    write_json(run_dir / "preflight.json", preflight)
    if args.preflight_only:
        print(json.dumps({"run_id": run_id, "run_dir": str(run_dir), "preflight_ok": bool(preflight.get("ok"))}, indent=2))
        if not preflight.get("ok"):
            raise SystemExit("Preflight validation failed; see preflight.json for details.")
        return
    if not preflight.get("ok"):
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
        "observed": {},
        "limits": budget_config,
        "aborted_early": False,
    }
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

        judge_result = None
        if args.judge_mode == "agent":
            from .judge import judge_agent_result

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
            run_budget_status["aborted_early"] = True
            write_json(run_dir / "budget_status.json", run_budget_status)
            _emit_progress(f"Run budget exceeded; aborting after {task_index} completed task(s)")
            break

    aggregate = aggregate_records(run_metadata, records)
    aggregate["run_budget_status"] = run_budget_status
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

    completion_payload = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "sample_count": len(records),
    }
    print(json.dumps(completion_payload, indent=2))
    print("EVAL_RUN_RESULT_JSON::" + json.dumps(completion_payload, ensure_ascii=False, sort_keys=True))
