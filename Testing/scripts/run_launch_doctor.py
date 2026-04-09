#!/usr/bin/env python3
"""
File: run_launch_doctor.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Run launch-readiness, bundle-integrity, and budget projection checks.

Summary:
  This entry-point script exposes the harness doctor as a stable command-line
  tool. It exists so developers can validate sweep scope, bundle readiness,
  and projected budget before starting paid evaluation runs.
"""

from _bootstrap import TESTING_ROOT  # noqa: F401
from harness.doctor import run_launch_doctor


if __name__ == "__main__":
    run_launch_doctor()
