#!/usr/bin/env python3
"""
File: run_recover_failed_tasks.py
Author: Matt-Ung
Last Updated: 2026-04-02
Purpose:
  Inspect an existing run or sweep directory and relaunch only failed tasks.

Summary:
  This command-line wrapper uses the harness recovery module to classify task
  outcomes from canonical run artifacts, print a retry plan, and optionally
  launch exact-task recovery runs without mutating the original results.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, Iterable

from _bootstrap import TESTING_ROOT  # noqa: F401
from harness.recovery import RETRYABLE_POLICIES, execute_recovery_plan


def _format_counts(counts: Dict[str, Any]) -> str:
    parts = [f"{key}={counts[key]}" for key in sorted(counts) if counts.get(key)]
    return ", ".join(parts) if parts else "none"


def _iter_retryable_tasks(inspection: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    return list(inspection.get("retryable_tasks") or [])


def _print_plan(plan: Dict[str, Any]) -> None:
    print(f"Recovery target: {plan.get('target_path')}")
    print(f"Scope: {plan.get('scope_type')} | retry_policy={plan.get('retry_policy')}")
    print(
        "Runs examined: {runs_examined} | runs with retryable tasks: {runs_with_retryable_tasks} | retryable tasks: {retryable_task_count}".format(
            runs_examined=int(plan.get("runs_examined") or 0),
            runs_with_retryable_tasks=int(plan.get("runs_with_retryable_tasks") or 0),
            retryable_task_count=int(plan.get("retryable_task_count") or 0),
        )
    )
    if plan.get("session_dir"):
        print(f"Recovery session: {plan.get('session_dir')}")

    inspections = list(plan.get("inspections") or [])
    if not inspections:
        print("No retryable tasks detected.")
        return

    for inspection in inspections:
        run_label = str(inspection.get("display_label") or inspection.get("run_id") or "run")
        run_id = str(inspection.get("run_id") or "")
        print("")
        print(f"Run: {run_label} [{run_id}]")
        print(f"Source: {inspection.get('run_dir')}")
        print(f"Original status: {inspection.get('run_status') or 'unknown'}")
        print(f"Task classifications: {_format_counts(dict(inspection.get('task_counts') or {}))}")
        retryable_tasks = list(_iter_retryable_tasks(inspection))
        print(f"Retrying {len(retryable_tasks)} task(s):")
        for task in retryable_tasks:
            sample_task_id = str(task.get("sample_task_id") or "<full-run-scope>")
            classification = str(task.get("classification") or "unknown")
            reason = str(task.get("reason") or "").strip()
            detail = f" [{classification}]"
            if reason:
                detail += f" {reason}"
            print(f"- {sample_task_id}{detail}")

        recovery_command = inspection.get("recovery_command") if isinstance(inspection.get("recovery_command"), dict) else {}
        if recovery_command:
            print(f"Recovery run id: {recovery_command.get('recovery_run_id')}")
        recovery_result = inspection.get("recovery_result") if isinstance(inspection.get("recovery_result"), dict) else {}
        if recovery_result:
            status_text = "ok" if recovery_result.get("ok") else "failed"
            print(f"Recovery result: {status_text}")
            if recovery_result.get("recovery_run_dir"):
                print(f"Recovery run dir: {recovery_result.get('recovery_run_dir')}")
            if recovery_result.get("log_path"):
                print(f"Log: {recovery_result.get('log_path')}")
            if recovery_result.get("error"):
                print(f"Error: {recovery_result.get('error')}")

    summary = dict(plan.get("summary") or {})
    if summary:
        print("")
        print(
            "Summary: launched={launched_recovery_runs} completed={completed_recovery_runs} failed={failed_recovery_runs}".format(
                launched_recovery_runs=int(summary.get("launched_recovery_runs") or 0),
                completed_recovery_runs=int(summary.get("completed_recovery_runs") or 0),
                failed_recovery_runs=int(summary.get("failed_recovery_runs") or 0),
            )
        )


"""
Function: main
Inputs:
  - argv: optional CLI-style argument list. When omitted, arguments are read
    from the real command line.
Description:
  Inspect a run or experiment, print a retry plan, and optionally launch
  recovery runs for retryable sample-task failures only.
Outputs:
  Returns process-style status code `0` on success and non-zero on failure.
Side Effects:
  May create a `recovery_attempts/<session_id>/` directory and launch new
  recovery runs under `Testing/results/runs/`.
"""
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect an existing run or sweep directory and relaunch only failed or unfinished tasks.",
    )
    parser.add_argument(
        "target",
        help="Path to either a completed run directory or an experiment directory",
    )
    parser.add_argument(
        "--retry-policy",
        choices=sorted(RETRYABLE_POLICIES),
        default="non_completed",
        help="Select whether to retry only explicit failures, any non-completed tasks, or also include validator-blocked tasks.",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Inspect and print the retry plan without launching recovery runs.",
    )
    parser.add_argument(
        "--quiet-child-output",
        action="store_true",
        help="Do not stream child recovery run output to the terminal.",
    )
    parser.add_argument(
        "--timeout-sec",
        type=int,
        default=0,
        help="Optional timeout passed to each recovery child run; 0 disables it.",
    )
    parser.add_argument(
        "--task-failure-retries",
        type=int,
        default=0,
        help="For each relaunched task, retry retryable failures this many times after the first attempt.",
    )
    parser.add_argument(
        "--deep-agent-request-limit",
        type=int,
        default=None,
        help="Override the deep-agent request cap used by recovery child runs. Omit to reuse the original run setting when available, or pass 0 to disable the cap.",
    )
    parser.add_argument(
        "--max-concurrent-recovery-runs",
        type=int,
        default=1,
        help="Launch up to this many recovery child runs at once. Concurrency is across recovery runs, not within one run's internal task order.",
    )
    args = parser.parse_args(argv)

    try:
        plan = execute_recovery_plan(
            Path(args.target).expanduser(),
            retry_policy=str(args.retry_policy or "non_completed"),
            plan_only=bool(args.plan_only),
            quiet_child_output=bool(args.quiet_child_output),
            timeout_sec=int(args.timeout_sec or 0),
            task_failure_retries=max(0, int(args.task_failure_retries or 0)),
            max_concurrent_recovery_runs=max(1, int(args.max_concurrent_recovery_runs or 1)),
            deep_agent_request_limit=args.deep_agent_request_limit,
        )
    except Exception as exc:
        print(f"Recovery failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    _print_plan(plan)
    if bool(args.plan_only):
        return 0
    failed_recovery_runs = int(((plan.get("summary") or {}) if isinstance(plan.get("summary"), dict) else {}).get("failed_recovery_runs") or 0)
    return 1 if failed_recovery_runs > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
