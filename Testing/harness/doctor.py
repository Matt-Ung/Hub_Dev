from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from .launch_checks import (
    build_bundle_integrity_report,
    build_launch_preset_projection_report,
    build_sweep_projection_report,
    check_python_modules,
    resolve_launch_environment,
)
from .launch_presets import available_launch_presets, resolve_launch_preset
from .paths import RESULTS_ROOT, build_run_id, ensure_dir, write_json


def _status_line(ok: bool, label: str, detail: str) -> str:
    prefix = "[PASS]" if ok else "[FAIL]"
    return f"{prefix} {label}: {detail}"


def _recommended_commands(pilot_preset_name: str, judge_model: str, python_executable: str) -> Dict[str, str]:
    judge = str(judge_model or "openai:gpt-4o-mini").strip()
    py = str(python_executable or "python").strip() or "python"
    return {
        "install_deps": f"{py} -m pip install pydantic pydantic-ai matplotlib pandas",
        "build_binaries": "make all-exes",
        "prepare_bundles": f"{py} Testing/prepare_bundles.py --corpus experimental",
        "bundle_check": f"{py} Testing/check_bundle_integrity.py --corpus experimental",
        "single_run_preflight": (
            f"{py} Testing/run_evaluation.py "
            "--corpus experimental "
            "--sample basic_loops_test.exe "
            "--task default_analysis "
            f"--judge-model {judge} "
            "--skip-build --skip-prepare --preflight-only"
        ),
        "pilot_preflight": (
            f"{py} Testing/run_launch_preset.py --preset {pilot_preset_name} "
            f"--judge-model {judge} --preflight-only"
        ),
        "pilot_run": (
            f"{py} Testing/run_launch_preset.py --preset {pilot_preset_name} "
            f"--judge-model {judge}"
        ),
        "broad_preflight": (
            f"{py} Testing/run_experiment_sweep.py --corpus experimental "
            f"--judge-model {judge} --preflight-only"
        ),
    }


def run_launch_doctor(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Launch-readiness doctor for the paid testing harness.")
    parser.add_argument("--corpus", choices=["prototype", "experimental"], default="experimental")
    parser.add_argument("--pilot-preset", default="paid_narrow_pilot", help="Named launch preset to treat as the recommended first paid pilot")
    parser.add_argument("--judge-model", default="", help="Optional explicit judge model override for readiness checks")
    parser.add_argument("--difficulty-filter", action="append", default=[], help="Optional difficulty filter for the broad-sweep readiness estimate")
    args = parser.parse_args(argv)

    launch_env = resolve_launch_environment(explicit_judge_model=args.judge_model)
    budget_modules = ["pydantic", "pydantic_ai"]
    visuals_modules = ["matplotlib", "pandas"]
    runtime_modules = check_python_modules(launch_env["current_python"], budget_modules)
    visuals = check_python_modules(launch_env["current_python"], visuals_modules)

    broad_bundle = build_bundle_integrity_report(
        corpus_name=args.corpus,
        selected_difficulties=args.difficulty_filter,
    )
    broad_budget = build_sweep_projection_report(
        corpus_name=args.corpus,
        selected_difficulties=args.difficulty_filter,
    )

    preset = resolve_launch_preset(args.pilot_preset)
    pilot_bundle = build_bundle_integrity_report(
        corpus_name=str(preset.get("corpus") or args.corpus),
        selected_samples=list(preset.get("samples") or []),
        selected_task_ids=list(preset.get("tasks") or []),
        selected_difficulties=list(preset.get("difficulty_filters") or []),
    )
    pilot_budget = build_launch_preset_projection_report(
        args.pilot_preset,
    )

    checks: List[Dict[str, Any]] = []
    checks.append(
        {
            "name": "python_judge_deps",
            "ok": bool(runtime_modules.get("ok")),
            "detail": (
                "required judge/runtime deps present"
                if runtime_modules.get("ok")
                else "missing: " + ", ".join(runtime_modules.get("missing") or [])
            ),
        }
    )
    checks.append(
        {
            "name": "python_visual_deps",
            "ok": bool(visuals.get("ok")),
            "detail": (
                "chart deps present"
                if visuals.get("ok")
                else "missing: " + ", ".join(visuals.get("missing") or []) + " (use --skip-visuals if needed)"
            ),
        }
    )
    checks.append(
        {
            "name": "openai_api_key",
            "ok": bool(launch_env.get("openai_api_key_set")),
            "detail": "OPENAI_API_KEY is set" if launch_env.get("openai_api_key_set") else "OPENAI_API_KEY is missing",
        }
    )
    checks.append(
        {
            "name": "judge_model_config",
            "ok": bool(launch_env.get("judge_model_set")),
            "detail": (
                f"judge model: {launch_env.get('judge_model')}"
                if launch_env.get("judge_model_set")
                else f"no explicit judge model set; recommended: {preset.get('recommended_judge_model') or 'openai:gpt-4o-mini'}"
            ),
        }
    )
    checks.append(
        {
            "name": "judge_model_distinct",
            "ok": bool(launch_env.get("judge_model_distinct")),
            "detail": (
                f"judge model {launch_env.get('judge_model')} differs from agent model {launch_env.get('effective_agent_model')}"
                if launch_env.get("judge_model_distinct")
                else f"judge model matches agent model {launch_env.get('effective_agent_model') or '(unset)'}"
            ),
        }
    )
    checks.append(
        {
            "name": "ghidra_env",
            "ok": bool(launch_env.get("ghidra_headless_set") or launch_env.get("ghidra_install_dir_set")) and bool(launch_env.get("ghidra_java_home_set")),
            "detail": (
                "GHIDRA_HEADLESS/GHIDRA_INSTALL_DIR and GHIDRA_JAVA_HOME are set"
                if (launch_env.get("ghidra_headless_set") or launch_env.get("ghidra_install_dir_set")) and launch_env.get("ghidra_java_home_set")
                else "missing one or more of GHIDRA_HEADLESS / GHIDRA_INSTALL_DIR / GHIDRA_JAVA_HOME"
            ),
        }
    )
    checks.append(
        {
            "name": "pilot_bundle_integrity",
            "ok": bool(pilot_bundle.get("ok")),
            "detail": (
                f"{pilot_bundle.get('sample_count')} sample(s), {pilot_bundle.get('task_count')} task(s), all required bundle files present"
                if pilot_bundle.get("ok")
                else "missing required bundle files for pilot selection"
            ),
        }
    )
    checks.append(
        {
            "name": "pilot_budget",
            "ok": bool(pilot_budget.get("ok")),
            "detail": (
                f"projected {pilot_budget.get('projection', {}).get('projected_estimated_cost_usd')} USD across {pilot_budget.get('child_runs')} child run(s)"
                if pilot_budget.get("ok")
                else "pilot exceeds configured budget ceiling"
            ),
        }
    )
    checks.append(
        {
            "name": "broad_bundle_integrity",
            "ok": bool(broad_bundle.get("ok")),
            "detail": (
                f"{broad_bundle.get('sample_count')} sample(s), {broad_bundle.get('task_count')} task(s), all required bundle files present"
                if broad_bundle.get("ok")
                else "missing required bundle files for the broad sweep selection"
            ),
        }
    )
    checks.append(
        {
            "name": "broad_budget",
            "ok": bool(broad_budget.get("ok")),
            "detail": (
                f"projected {broad_budget.get('projection', {}).get('projected_estimated_cost_usd')} USD across {broad_budget.get('child_runs')} child run(s)"
                if broad_budget.get("ok")
                else "broad default sweep exceeds configured budget ceiling"
            ),
        }
    )

    overall_pilot_ready = all(
        check["ok"]
        for check in checks
        if check["name"] in {
            "python_judge_deps",
            "openai_api_key",
            "judge_model_config",
            "judge_model_distinct",
            "ghidra_env",
            "pilot_bundle_integrity",
            "pilot_budget",
        }
    )
    overall_broad_ready = all(
        check["ok"]
        for check in checks
        if check["name"] in {
            "python_judge_deps",
            "openai_api_key",
            "judge_model_config",
            "judge_model_distinct",
            "ghidra_env",
            "broad_bundle_integrity",
            "broad_budget",
        }
    )

    doctor_id = build_run_id("doctor", args.corpus)
    report_dir = ensure_dir(RESULTS_ROOT / "doctor" / doctor_id)
    report = {
        "doctor_id": doctor_id,
        "corpus": args.corpus,
        "pilot_preset": args.pilot_preset,
        "available_launch_presets": available_launch_presets(),
        "environment": launch_env,
        "checks": checks,
        "runtime_modules": runtime_modules,
        "visualization_modules": visuals,
        "pilot_bundle": pilot_bundle,
        "pilot_budget": pilot_budget,
        "broad_bundle": broad_bundle,
        "broad_budget": broad_budget,
        "pilot_ready": overall_pilot_ready,
        "broad_ready": overall_broad_ready,
        "recommended_commands": _recommended_commands(
            args.pilot_preset,
            str(launch_env.get("judge_model") or preset.get("recommended_judge_model") or ""),
            str(launch_env.get("current_python") or ""),
        ),
    }
    write_json(report_dir / "doctor_report.json", report)

    print(f"Launch Doctor Report: {report_dir / 'doctor_report.json'}")
    print(f"Interpreter: {launch_env.get('current_python')}")
    print(f"Virtualenv: {'yes' if launch_env.get('in_virtualenv') else 'no'}")
    if not launch_env.get("same_interpreter"):
        print(f"Preferred interpreter: {launch_env.get('preferred_python')}")
    if launch_env.get("virtual_env_envvar"):
        print(f"VIRTUAL_ENV: {launch_env.get('virtual_env_envvar')}")
    print("")
    for check in checks:
        print(_status_line(bool(check.get("ok")), str(check.get("name")), str(check.get("detail") or "")))
    print("")
    print(f"Pilot verdict: {'READY' if overall_pilot_ready else 'NOT READY'}")
    print(f"Broad sweep verdict: {'READY' if overall_broad_ready else 'NOT READY'}")
    print("")
    print("Recommended commands:")
    for key, value in report["recommended_commands"].items():
        print(f"- {key}: {value}")

    if not overall_pilot_ready:
        raise SystemExit(1)


if __name__ == "__main__":
    run_launch_doctor()
