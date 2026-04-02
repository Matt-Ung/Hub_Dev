#!/usr/bin/env python3
"""
File: run_launch_preset.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Launch named testing presets that wrap the primary harness runners.

Summary:
  This script resolves a preset from `Testing/config/launch_presets.json`,
  expands it into the underlying single-run or sweep command, and executes it
  with optional live-view and model overrides. It exists to shorten common
  workflows without duplicating the real execution logic in more wrappers.
"""

from __future__ import annotations

import argparse
import json

from harness.launch_presets import available_launch_presets, build_launch_preset_command, resolve_launch_preset
from harness.paths import REPO_ROOT
from harness.subprocess_utils import run_command


def main() -> None:
    """
    Function: main
    Inputs:
      - None directly. Command-line flags provide the preset name, optional
        model overrides, and wrapper-level execution options.
    Description:
      Resolve a named launch preset, print the exact underlying command, and
      execute it through the shared subprocess helper.
    Outputs:
      Returns nothing. Exits the process with a non-zero status when the child
      command fails.
    Side Effects:
      Prints the expanded command, launches a child harness process, and may
      stream that child output to the terminal.
    """
    parser = argparse.ArgumentParser(description="Run a named launch preset such as the recommended sanity sweep or budgeted comparison study.")
    parser.add_argument("--preset", default="sanity_core_slice_r1", help="Launch preset name")
    parser.add_argument("--judge-model", default="", help="Optional explicit judge model override")
    parser.add_argument("--preflight-only", action="store_true", help="Only run the preset through its normal preflight path")
    parser.add_argument("--live-view", action="store_true", help="For sweep presets, start the lightweight local progress monitor")
    parser.add_argument("--skip-build", action="store_true", help="Pass --skip-build through to the underlying runner")
    parser.add_argument("--skip-prepare", action="store_true", help="Pass --skip-prepare through to the underlying runner")
    parser.add_argument("--ghidra-install-dir", default="", help="Optional GHIDRA_INSTALL_DIR override")
    parser.add_argument("--ghidra-headless", default="", help="Optional analyzeHeadless override")
    parser.add_argument("--timeout-sec", type=int, default=0, help="Optional subprocess timeout in seconds; 0 disables it")
    parser.add_argument("--quiet-child-output", action="store_true", help="Buffer child output and print it after completion instead of streaming live")
    args = parser.parse_args()

    try:
        preset = resolve_launch_preset(args.preset)
        command = build_launch_preset_command(
            args.preset,
            explicit_judge_model=args.judge_model,
            preflight_only=args.preflight_only,
            live_view=args.live_view,
            skip_build=args.skip_build,
            skip_prepare=args.skip_prepare,
            ghidra_install_dir=args.ghidra_install_dir,
            ghidra_headless=args.ghidra_headless,
            timeout_sec=args.timeout_sec,
        )
    except KeyError:
        print(json.dumps({"available_presets": available_launch_presets()}, indent=2))
        raise

    print("Launch preset command:")
    print(" ".join(command))
    stream_output = not (bool(args.quiet_child_output) or bool(preset.get("quiet_child_output")))
    result = run_command(
        command,
        cwd=REPO_ROOT,
        timeout_sec=max(3600, int(args.timeout_sec) * 20) if int(args.timeout_sec) > 0 else None,
        stream_output=stream_output,
        stream_prefix="",
        stream_heartbeat_sec=30,
    )
    if not stream_output and result.get("stdout"):
        print(str(result.get("stdout")).rstrip())
    if not stream_output and result.get("stderr"):
        print(str(result.get("stderr")).rstrip())
    if not result.get("ok"):
        raise SystemExit(int(result.get("returncode") or 1))


if __name__ == "__main__":
    main()
