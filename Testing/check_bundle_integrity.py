#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from harness.launch_checks import build_bundle_integrity_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Check whether prepared binary-analysis bundles contain all required files for a selected evaluation scope.")
    parser.add_argument("--corpus", choices=["prototype", "experimental"], default="experimental")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample filename(s) to restrict to")
    parser.add_argument("--task", action="append", default=[], help="Optional task id(s) to restrict to")
    parser.add_argument("--difficulty-filter", action="append", default=[], help="Optional difficulty label(s) to restrict to")
    args = parser.parse_args()

    report = build_bundle_integrity_report(
        corpus_name=args.corpus,
        selected_samples=args.sample,
        selected_task_ids=args.task,
        selected_difficulties=args.difficulty_filter,
    )
    print(json.dumps(report, indent=2))
    if not report.get("ok"):
        raise SystemExit("Bundle integrity check failed; see missing_binaries, missing_required_by_sample, and stale_by_sample.")


if __name__ == "__main__":
    main()
