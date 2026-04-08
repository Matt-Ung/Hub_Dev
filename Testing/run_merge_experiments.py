#!/usr/bin/env python3
"""
File: run_merge_experiments.py
Author: Matt-Ung
Last Updated: 2026-04-07
Purpose:
  Build a combined experiment view from two or more compatible experiment dirs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness.experiment_merge import merge_experiments, plan_merged_experiment


def _print_plan(plan: dict) -> None:
    print(f"Primary experiment: {plan.get('primary_experiment_root')}")
    print(f"Additional experiments: {', '.join(plan.get('additional_experiment_roots') or [])}")
    print(f"Planned merged experiment: {plan.get('output_experiment_root')}")
    print(
        "Variants: {variant_count} | planned child runs: {planned_run_count} | repetitions: {repetitions}".format(
            variant_count=int(plan.get("variant_count") or 0),
            planned_run_count=int(plan.get("planned_run_count") or 0),
            repetitions=int(plan.get("repetitions") or 0),
        )
    )
    print("")
    for row in plan.get("run_plans") or []:
        print(
            "- {label} [{variant_id}] from {source}".format(
                label=str(row.get("display_label") or row.get("variant_id") or "variant"),
                variant_id=str(row.get("variant_id") or ""),
                source=str(row.get("source_experiment") or ""),
            )
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Merge compatible experiment directories into one aggregate comparison view.",
    )
    parser.add_argument(
        "primary_experiment",
        help="Primary experiment directory. Its baseline and duplicate variants win by default.",
    )
    parser.add_argument(
        "additional_experiments",
        nargs="+",
        help="One or more additional compatible experiment directories to merge in.",
    )
    parser.add_argument(
        "--output-root",
        default="",
        help="Optional destination root for the merged experiment. Defaults to Testing/results/experiments.",
    )
    parser.add_argument(
        "--output-experiment-id",
        default="",
        help="Optional explicit merged experiment directory name.",
    )
    parser.add_argument(
        "--include-duplicate-variants",
        action="store_true",
        help="Include duplicate variant ids from secondary experiments instead of keeping the primary experiment's copy.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the merged experiment directory if it already exists.",
    )
    parser.add_argument(
        "--skip-visuals",
        action="store_true",
        help="Skip PNG chart generation while materializing the merged outputs.",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Print the merge plan without writing a merged experiment.",
    )
    args = parser.parse_args(argv)

    primary = Path(args.primary_experiment).expanduser()
    additional = [Path(item).expanduser() for item in args.additional_experiments]
    output_root = Path(args.output_root).expanduser() if str(args.output_root or "").strip() else None

    try:
        if args.plan_only:
            plan = plan_merged_experiment(
                primary,
                additional_experiments=additional,
                output_root=output_root,
                output_experiment_id=str(args.output_experiment_id or ""),
                include_duplicate_variants=bool(args.include_duplicate_variants),
            )
            _print_plan(plan)
            return 0

        result = merge_experiments(
            primary,
            additional_experiments=additional,
            output_root=output_root,
            output_experiment_id=str(args.output_experiment_id or ""),
            include_duplicate_variants=bool(args.include_duplicate_variants),
            overwrite=bool(args.overwrite),
            skip_visuals=bool(args.skip_visuals),
        )
    except Exception as exc:
        print(f"Experiment merge failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
