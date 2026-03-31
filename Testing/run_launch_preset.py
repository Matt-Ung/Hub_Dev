#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from harness.launch_presets import available_launch_presets, build_launch_preset_command
from harness.paths import REPO_ROOT
from harness.subprocess_utils import run_command


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a named launch preset such as the recommended cheap paid pilot.")
    parser.add_argument("--preset", default="paid_narrow_pilot", help="Launch preset name")
    parser.add_argument("--judge-model", default="", help="Optional explicit judge model override")
    parser.add_argument("--preflight-only", action="store_true", help="Only run the preset through its normal preflight path")
    parser.add_argument("--skip-build", action="store_true", help="Pass --skip-build through to the underlying runner")
    parser.add_argument("--skip-prepare", action="store_true", help="Pass --skip-prepare through to the underlying runner")
    parser.add_argument("--ghidra-install-dir", default="", help="Optional GHIDRA_INSTALL_DIR override")
    parser.add_argument("--ghidra-headless", default="", help="Optional analyzeHeadless override")
    parser.add_argument("--timeout-sec", type=int, default=900, help="Timeout to pass through to the underlying runner")
    args = parser.parse_args()

    try:
        command = build_launch_preset_command(
            args.preset,
            explicit_judge_model=args.judge_model,
            preflight_only=args.preflight_only,
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
    result = run_command(command, cwd=REPO_ROOT, timeout_sec=max(3600, int(args.timeout_sec) * 20))
    if result.get("stdout"):
        print(str(result.get("stdout")).rstrip())
    if result.get("stderr"):
        print(str(result.get("stderr")).rstrip())
    if not result.get("ok"):
        raise SystemExit(int(result.get("returncode") or 1))


if __name__ == "__main__":
    main()
