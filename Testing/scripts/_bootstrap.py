"""
File: _bootstrap.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Bootstrap direct script execution so `Testing/scripts/*.py` can import the
  local harness package.

Summary:
  This module resolves the `Testing/` root and inserts it into `sys.path`
  when a script is executed directly. It keeps the command-line entrypoints
  stable without requiring callers to run them as installed Python modules.
"""

from __future__ import annotations

import sys
from pathlib import Path


TESTING_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TESTING_ROOT.parent

# All maintained script entrypoints import this module first so both
# `harness.*` and repository-root packages such as `multi_agent_wf.*`
# resolve relative to the repository layout rather than the caller's cwd.
for root in (TESTING_ROOT, REPO_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
