#!/usr/bin/env python3
"""
File: check_bundle_integrity.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Preserve the old bundle-integrity command as a compatibility wrapper.

Summary:
  This script exists so older notes and muscle-memory commands still work
  after bundle integrity checks were folded into `run_launch_doctor`. It does
  not implement its own integrity logic; it delegates straight to the doctor's
  `--bundle-only` mode.
"""

from __future__ import annotations

import sys

from harness.doctor import run_launch_doctor


def main() -> None:
    """
    Function: main
    Inputs:
      - None directly. Any command-line flags are forwarded to the launch
        doctor, with `--bundle-only` appended automatically.
    Description:
      Invoke the launch doctor in bundle-only mode so this legacy command keeps
      the same operational meaning without maintaining duplicate logic.
    Outputs:
      Returns nothing. Exits with the same status code as the delegated doctor
      command.
    Side Effects:
      Runs the shared launch-doctor code path.
    """
    run_launch_doctor([*sys.argv[1:], "--bundle-only"])


if __name__ == "__main__":
    main()
