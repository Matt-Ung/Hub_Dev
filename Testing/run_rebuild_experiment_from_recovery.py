#!/usr/bin/env python3
"""
File: run_rebuild_experiment_from_recovery.py
Author: Matt-Ung
Last Updated: 2026-04-04
Purpose:
  Materialize a repaired experiment dataset by applying recovery-run outputs.

Summary:
  This command-line wrapper reads an existing experiment plus one or more
  recovery sessions, overlays recovered task artifacts onto the original run
  scope, and regenerates the experiment-level summaries/charts in a new
  repaired experiment directory.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness.recovery_rebuild import plan_rebuilt_experiment, rebuild_experiment_from_recovery


def _print_plan(plan: dict) -> None:
    print(f"Source experiment: {plan.get('source_experiment_root')}")
    print(f"Recovery sessions: {', '.join(plan.get('recovery_session_ids') or []) or 'none'}")
    print(f"Planned repaired experiment: {plan.get('output_experiment_root')}")
    print(f"Runs in scope: {int(plan.get('run_count') or 0)} | replaced tasks: {int(plan.get('replaced_task_count') or 0)}")
    print("")
    for row in plan.get("run_plans") or []:
        print(
            "- {label} [{run_id}] replacements={count}".format(
                label=str(row.get("display_label") or row.get("run_id") or "run"),
                run_id=str(row.get("run_id") or ""),
                count=int(row.get("replacement_count") or 0),
            )
        )
        for task_id in (row.get("replaced_task_ids") or []):
            print(f"  {task_id}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a repaired experiment directory by overlaying recovery-run outputs onto an existing sweep.",
    )
    parser.add_argument(
        "experiment",
        help="Path to Testing/results/experiments/<experiment_id>",
    )
    parser.add_argument(
        "--recovery-session",
        action="append",
        default=[],
        help="Optional recovery session id/path. Repeat to apply multiple sessions; default is all completed sessions under recovery_attempts/.",
    )
    parser.add_argument(
        "--output-root",
        default="",
        help="Optional destination directory root for the repaired experiment. Defaults to Testing/results/experiments.",
    )
    parser.add_argument(
        "--output-experiment-id",
        default="",
        help="Optional explicit repaired experiment directory name.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the repaired experiment directory if it already exists.",
    )
    parser.add_argument(
        "--skip-visuals",
        action="store_true",
        help="Skip PNG chart generation while rebuilding outputs.",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Print the merge/rebuild plan without writing a repaired experiment.",
    )
    args = parser.parse_args(argv)

    experiment_root = Path(args.experiment).expanduser()
    output_root = Path(args.output_root).expanduser() if str(args.output_root or "").strip() else None

    try:
        if args.plan_only:
            plan = plan_rebuilt_experiment(
                experiment_root,
                recovery_sessions=list(args.recovery_session or []),
                output_root=output_root,
                output_experiment_id=str(args.output_experiment_id or ""),
            )
            _print_plan(plan)
            return 0

        result = rebuild_experiment_from_recovery(
            experiment_root,
            recovery_sessions=list(args.recovery_session or []),
            output_root=output_root,
            output_experiment_id=str(args.output_experiment_id or ""),
            overwrite=bool(args.overwrite),
            skip_visuals=bool(args.skip_visuals),
        )
    except Exception as exc:
        print(f"Recovery rebuild failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
