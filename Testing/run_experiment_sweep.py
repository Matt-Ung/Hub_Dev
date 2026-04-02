#!/usr/bin/env python3
"""
File: run_experiment_sweep.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Launch a maintained baseline-first experiment sweep from the command line.

Summary:
  This entry-point script exposes the harness sweep orchestrator as a stable
  CLI command. It exists so developers can run multi-configuration experiments
  without importing harness internals directly, while preserving the canonical
  sweep planning, child-run execution, and experiment-level aggregation path.
"""

from harness.experiment_sweep import run_experiment_sweep


if __name__ == "__main__":
    run_experiment_sweep()
