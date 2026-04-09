"""
File: __init__.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Expose the maintained single-run harness entrypoint at the package level.

Summary:
  This small module keeps `harness` import ergonomics stable by re-exporting
  the primary single-run entrypoint used by wrappers and tests.
"""

from .runner import main as run_evaluation_main

__all__ = ["run_evaluation_main"]
