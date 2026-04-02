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
    check_command_available,
    check_python_modules,
    resolve_launch_environment,
)
from .launch_presets import available_launch_presets, resolve_launch_preset
from .paths import RESULTS_ROOT, build_run_id, ensure_dir, write_json


def _status_line(ok: bool, label: str, detail: str, *, warning: bool = False) -> str:
    prefix = "[WARN]" if warning and ok else ("[PASS]" if ok else "[FAIL]")
    return f"{prefix} {label}: {detail}"


def _append_repeatable_flags(base: str, flag: str, values: List[str]) -> str:
    command = base
    for value in values:
        normalized = str(value or "").strip()
        if normalized:
            command += f" {flag} {normalized}"
    return command


def _build_doctor_selection_suffix(
    *,
    selected_samples: List[str],
    selected_tasks: List[str],
    selected_difficulties: List[str],
    variable_filters: List[str],
    repetitions_override: int | None,
) -> str:
    command = ""
    command = _append_repeatable_flags(command, "--sample", selected_samples)
    command = _append_repeatable_flags(command, "--task", selected_tasks)
    command = _append_repeatable_flags(command, "--difficulty-filter", selected_difficulties)
    command = _append_repeatable_flags(command, "--variable", variable_filters)
    if repetitions_override is not None and int(repetitions_override) > 0:
        command += f" --repetitions {int(repetitions_override)}"
    return command


def _budget_detail(label: str, report: Dict[str, Any]) -> str:
    comparison = report.get("ceiling_comparison") if isinstance(report.get("ceiling_comparison"), dict) else {}
    projection = report.get("projection") if isinstance(report.get("projection"), dict) else {}
    projection_status = report.get("projection_status") if isinstance(report.get("projection_status"), dict) else {}
    projected_usd = comparison.get("projected_estimated_cost_usd", projection.get("projected_estimated_cost_usd"))
    usd_limit = comparison.get("configured_max_experiment_estimated_cost_usd")
    usd_delta = comparison.get("estimated_cost_delta_usd")
    projected_relative = comparison.get("projected_relative_cost_index", projection.get("projected_relative_cost_index"))
    relative_limit = comparison.get("configured_max_experiment_relative_cost_index")
    relative_delta = comparison.get("relative_cost_delta")
    child_runs = report.get("child_runs")

    usd_part = ""
    if projected_usd is not None and usd_limit is not None:
        usd_part = f"{projected_usd} USD vs ceiling {usd_limit} USD"
        if usd_delta is not None and float(usd_delta) > 0:
            usd_part += f" (over by {round(float(usd_delta), 8)} USD)"
    elif projected_usd is not None:
        usd_part = f"{projected_usd} USD"

    relative_part = ""
    if projected_relative is not None and relative_limit is not None:
        relative_part = f"relative index {projected_relative} vs ceiling {relative_limit}"
        if relative_delta is not None and float(relative_delta) > 0:
            relative_part += f" (over by {round(float(relative_delta), 6)})"
    elif projected_relative is not None:
        relative_part = f"relative index {projected_relative}"

    pieces = [part for part in (usd_part, relative_part) if part]
    detail = ", ".join(pieces) if pieces else "no projection details available"
    if child_runs is not None:
        detail += f" across {child_runs} child run(s)"
    if not report.get("ok"):
        detail = f"{label} projects {detail}"
    warning_messages = [str(item) for item in (projection_status.get("warnings") or []) if str(item)]
    if warning_messages:
        detail += "; advisory warning: " + " | ".join(warning_messages)
    return detail


def _bundle_detail(label: str, report: Dict[str, Any]) -> str:
    sample_count = int(report.get("sample_count") or 0)
    task_count = int(report.get("task_count") or 0)
    missing_binaries = report.get("missing_binaries") if isinstance(report.get("missing_binaries"), list) else []
    missing_required_by_sample = (
        report.get("missing_required_by_sample")
        if isinstance(report.get("missing_required_by_sample"), dict)
        else {}
    )
    stale_by_sample = report.get("stale_by_sample") if isinstance(report.get("stale_by_sample"), dict) else {}

    pieces = [f"{sample_count} sample(s)", f"{task_count} task(s)"]
    if missing_binaries:
        pieces.append(f"{len(missing_binaries)} missing binary target(s)")
    if missing_required_by_sample:
        pieces.append(f"{len(missing_required_by_sample)} sample(s) missing required bundle files")
    if stale_by_sample:
        pieces.append(f"{len(stale_by_sample)} stale bundle(s)")
    detail = ", ".join(pieces)
    if not report.get("ok"):
        detail = f"{label} bundle check found {detail}"
    return detail


def _print_bundle_breakdown(scope: str, report: Dict[str, Any]) -> None:
    print(f"{scope} bundle details:")
    print(f"- bundle_root: {report.get('bundle_root')}")
    missing_binaries = [str(item) for item in (report.get("missing_binaries") or []) if str(item)]
    if missing_binaries:
        print(f"- missing_binaries: {', '.join(missing_binaries)}")
    missing_required_by_sample = (
        report.get("missing_required_by_sample")
        if isinstance(report.get("missing_required_by_sample"), dict)
        else {}
    )
    if missing_required_by_sample:
        print("- missing_required_by_sample:")
        for sample_name in sorted(missing_required_by_sample):
            missing_items = [str(item) for item in (missing_required_by_sample.get(sample_name) or []) if str(item)]
            if missing_items:
                print(f"  - {sample_name}: {', '.join(missing_items)}")
    stale_by_sample = report.get("stale_by_sample") if isinstance(report.get("stale_by_sample"), dict) else {}
    if stale_by_sample:
        print("- stale_by_sample:")
        for sample_name in sorted(stale_by_sample):
            stale_items = [str(item) for item in (stale_by_sample.get(sample_name) or []) if str(item)]
            if stale_items:
                print(f"  - {sample_name}: {', '.join(stale_items)}")
    readiness = report.get("bundle_readiness") if isinstance(report.get("bundle_readiness"), dict) else {}
    if readiness:
        print(
            "- readiness: "
            f"ready_for_analysis={bool(readiness.get('ready_for_analysis'))}, "
            f"fresh_for_analysis={bool(readiness.get('fresh_for_analysis'))}"
        )
    if not missing_binaries and not missing_required_by_sample and not stale_by_sample:
        print("- all required binaries and bundle files are present and fresh")
    print("")


def _recommended_commands(
    corpus_name: str,
    pilot_preset_name: str,
    judge_model: str,
    python_executable: str,
    *,
    selected_samples: List[str] | None = None,
    selected_tasks: List[str] | None = None,
    selected_difficulties: List[str] | None = None,
    variable_filters: List[str] | None = None,
    repetitions_override: int | None = None,
) -> Dict[str, str]:
    judge = str(judge_model or "openai:gpt-4o-mini").strip()
    py = str(python_executable or "python").strip() or "python"
    broad_suffix = _build_doctor_selection_suffix(
        selected_samples=list(selected_samples or []),
        selected_tasks=list(selected_tasks or []),
        selected_difficulties=list(selected_difficulties or []),
        variable_filters=list(variable_filters or []),
        repetitions_override=repetitions_override,
    )
    return {
        "install_deps": f"{py} -m pip install pydantic pydantic-ai matplotlib pandas",
        "build_binaries": "make all-exes",
        "prepare_bundles": f"{py} Testing/prepare_bundles.py --corpus {corpus_name}",
        "bundle_doctor_only": f"{py} Testing/run_launch_doctor.py --corpus {corpus_name} --bundle-only{broad_suffix}",
        "single_run_preflight": (
            f"{py} Testing/run_evaluation.py "
            f"--corpus {corpus_name} "
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
            f"{py} Testing/run_experiment_sweep.py --corpus {corpus_name} "
            f"--judge-model {judge}{broad_suffix} --preflight-only"
        ),
    }


def run_launch_doctor(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Launch-readiness doctor for the paid testing harness.")
    parser.add_argument("--corpus", choices=["prototype", "experimental"], default="experimental")
    parser.add_argument("--pilot-preset", default="sanity_core_slice_r1", help="Named launch preset to treat as the recommended first paid pilot")
    parser.add_argument("--judge-model", default="", help="Optional explicit judge model override for readiness checks")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample filename(s) to restrict the broad projection to")
    parser.add_argument("--task", action="append", default=[], help="Optional task id(s) to restrict the broad projection to")
    parser.add_argument("--difficulty-filter", action="append", default=[], help="Optional difficulty filter for the broad-sweep readiness estimate")
    parser.add_argument("--variable", action="append", default=[], help="Optional sweep variable family filter for the broad projection, e.g. --variable worker_persona_prompt")
    parser.add_argument("--repetitions", type=int, default=None, help="Optional repetition override for the broad-sweep readiness estimate")
    parser.add_argument("--bundle-only", action="store_true", help="Only run bundle-integrity checks for the selected scope and exit non-zero on bundle failures")
    parser.add_argument("--show-bundle-details", action="store_true", help="Always print the detailed bundle-integrity breakdown, not just summary status lines")
    args = parser.parse_args(argv)

    broad_bundle = build_bundle_integrity_report(
        corpus_name=args.corpus,
        selected_samples=args.sample,
        selected_task_ids=args.task,
        selected_difficulties=args.difficulty_filter,
    )

    if args.bundle_only:
        bundle_report = broad_bundle
        print(json.dumps(bundle_report, indent=2))
        if args.show_bundle_details or not bundle_report.get("ok"):
            print("")
            _print_bundle_breakdown("Selected scope", bundle_report)
        if not bundle_report.get("ok"):
            raise SystemExit("Bundle integrity check failed; see missing_binaries, missing_required_by_sample, and stale_by_sample.")
        return

    launch_env = resolve_launch_environment(explicit_judge_model=args.judge_model)
    budget_modules = ["pydantic", "pydantic_ai"]
    visuals_modules = ["matplotlib", "pandas"]
    runtime_modules = check_python_modules(launch_env["current_python"], budget_modules)
    visuals = check_python_modules(launch_env["current_python"], visuals_modules)
    mingw = check_command_available("x86_64-w64-mingw32-gcc")

    broad_budget = build_sweep_projection_report(
        corpus_name=args.corpus,
        selected_samples=args.sample,
        selected_task_ids=args.task,
        selected_difficulties=args.difficulty_filter,
        variable_filters=args.variable,
        repetitions_override=args.repetitions,
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
            "name": "mingw_toolchain",
            "ok": bool(mingw.get("ok")),
            "detail": (
                f"x86_64-w64-mingw32-gcc available at {mingw.get('path')}"
                if mingw.get("ok")
                else "missing x86_64-w64-mingw32-gcc; canonical corpus builds require MinGW-w64 PE output, and host-only *_gcc.exe builds are not the maintained full-experiment target"
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
            "detail": _bundle_detail("pilot", pilot_bundle),
        }
    )
    checks.append(
        {
            "name": "pilot_budget",
            "ok": bool(pilot_budget.get("ok")),
            "warning": bool(pilot_budget.get("has_warnings")),
            "detail": _budget_detail("pilot", pilot_budget),
        }
    )
    checks.append(
        {
            "name": "broad_bundle_integrity",
            "ok": bool(broad_bundle.get("ok")),
            "detail": _bundle_detail("broad sweep", broad_bundle),
        }
    )
    checks.append(
        {
            "name": "broad_budget",
            "ok": bool(broad_budget.get("ok")),
            "warning": bool(broad_budget.get("has_warnings")),
            "detail": _budget_detail("broad default sweep", broad_budget),
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
        "selected_samples": list(args.sample or []),
        "selected_tasks": list(args.task or []),
        "selected_difficulties": list(args.difficulty_filter or []),
        "selected_variables": list(args.variable or []),
        "repetitions_override": int(args.repetitions) if args.repetitions is not None else None,
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
            args.corpus,
            args.pilot_preset,
            str(launch_env.get("judge_model") or preset.get("recommended_judge_model") or ""),
            str(launch_env.get("current_python") or ""),
            selected_samples=list(args.sample or []),
            selected_tasks=list(args.task or []),
            selected_difficulties=list(args.difficulty_filter or []),
            variable_filters=list(args.variable or []),
            repetitions_override=args.repetitions,
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
        print(_status_line(bool(check.get("ok")), str(check.get("name")), str(check.get("detail") or ""), warning=bool(check.get("warning"))))
    print("")
    if args.show_bundle_details or not pilot_bundle.get("ok"):
        _print_bundle_breakdown("Pilot", pilot_bundle)
    if args.show_bundle_details or not broad_bundle.get("ok"):
        _print_bundle_breakdown("Broad sweep", broad_bundle)
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
