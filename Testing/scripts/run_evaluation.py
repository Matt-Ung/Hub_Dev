#!/usr/bin/env python3
"""
File: run_evaluation.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Launch one maintained harness evaluation run from the command line.

Summary:
  This thin entry-point script exists so developers have a stable, memorable
  command for the canonical single-run evaluation path. It delegates to the
  harness runner module, which performs build, preflight, analysis, judging,
  aggregation, and artifact writing for one configuration.
"""

from _bootstrap import TESTING_ROOT  # noqa: F401
from harness.runner import main


if __name__ == "__main__":
    main()
