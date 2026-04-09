"""
File: launch_presets.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Resolve named operational presets into concrete harness commands.

Summary:
  This module loads folder-based preset definitions from
  `Testing/config/presets/*.json`, validates preset lookups, and expands one
  preset into the exact `run_evaluation.py` or `run_experiment_sweep.py`
  command that will be executed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from .paths import CONFIG_ROOT, REPO_ROOT, read_json, repo_python_executable


_COMMON_FLAG_FIELDS: tuple[tuple[str, str], ...] = (
    ("label", "--label"),
)

_SWEEP_FLAG_FIELDS: tuple[tuple[str, str], ...] = (
    ("config", "--config"),
)

_SINGLE_RUN_FLAG_FIELDS: tuple[tuple[str, str], ...] = (
    ("pipeline", "--pipeline"),
    ("architecture", "--architecture"),
    ("query", "--query"),
    ("query_variant", "--query-variant"),
    ("subagent_profile", "--subagent-profile"),
    ("worker_persona_profile", "--worker-persona-profile"),
    ("worker_role_prompt_mode", "--worker-role-prompt-mode"),
    ("validator_review_level", "--validator-review-level"),
    ("tool_profile", "--tool-profile"),
    ("model_profile", "--model-profile"),
    ("force_model", "--force-model"),
    ("judge_mode", "--judge-mode"),
)

_RUN_BUDGET_FLAG_FIELDS: tuple[tuple[str, str], ...] = (
    ("max_run_input_tokens", "--max-run-input-tokens"),
    ("max_run_output_tokens", "--max-run-output-tokens"),
    ("max_run_total_tokens", "--max-run-total-tokens"),
    ("max_run_relative_cost_index", "--max-run-relative-cost-index"),
    ("max_run_estimated_cost_usd", "--max-run-estimated-cost-usd"),
    ("hard_max_run_estimated_cost_usd", "--hard-max-run-estimated-cost-usd"),
)

_EXPERIMENT_BUDGET_FLAG_FIELDS: tuple[tuple[str, str], ...] = (
    ("max_experiment_relative_cost_index", "--max-experiment-relative-cost-index"),
    ("max_experiment_estimated_cost_usd", "--max-experiment-estimated-cost-usd"),
    ("hard_max_experiment_estimated_cost_usd", "--hard-max-experiment-estimated-cost-usd"),
)


def load_launch_presets() -> Dict[str, Any]:
    preset_dir = CONFIG_ROOT / "presets"
    presets: Dict[str, Any] = {}
    if not preset_dir.exists():
        return {"version": "launch_presets_v3", "preset_dir": str(preset_dir), "presets": {}}
    for path in sorted(preset_dir.glob("*.json")):
        raw = read_json(path)
        if not isinstance(raw, dict):
            raise ValueError(f"Preset file {path} must contain a JSON object")
        name = str(raw.get("name") or path.stem).strip()
        if not name:
            raise ValueError(f"Preset file {path} must define a non-empty preset name")
        if name in presets:
            raise ValueError(f"Duplicate launch preset name {name!r} in {path}")
        preset = dict(raw)
        preset["name"] = name
        preset["_preset_path"] = str(path.resolve())
        try:
            preset_rel_path = str(path.resolve().relative_to(REPO_ROOT.resolve()))
        except Exception:
            preset_rel_path = str(path.resolve())
        preset["_preset_rel_path"] = preset_rel_path
        runner = str(preset.get("runner") or "sweep").strip().lower()
        if (
            runner == "sweep"
            and not str(preset.get("config") or "").strip()
            and isinstance(preset.get("baseline"), dict)
            and isinstance(preset.get("sweeps"), list)
        ):
            # A sweep preset can use its own preset file as the sweep config
            # because the sweep loader only consumes the run-planning fields.
            preset["config"] = preset_rel_path
        presets[name] = preset
    return {
        "version": "launch_presets_v3",
        "preset_dir": str(preset_dir.resolve()),
        "presets": presets,
    }


def resolve_launch_preset(name: str) -> Dict[str, Any]:
    requested = str(name or "").strip()
    config = load_launch_presets()
    presets = config.get("presets") if isinstance(config.get("presets"), dict) else {}
    preset = presets.get(requested)
    if not isinstance(preset, dict):
        available = ", ".join(sorted(presets))
        raise KeyError(f"Unknown launch preset {requested!r}. Available: {available}")
    resolved = dict(preset)
    resolved["name"] = requested
    return resolved


def available_launch_presets() -> List[str]:
    config = load_launch_presets()
    presets = config.get("presets") if isinstance(config.get("presets"), dict) else {}
    return sorted(str(key) for key in presets.keys())


def _resolved_judge_model(preset: Dict[str, Any], explicit_judge_model: str = "") -> str:
    explicit = str(explicit_judge_model or "").strip()
    if explicit:
        return explicit
    env_value = str(os.environ.get("EVAL_JUDGE_MODEL") or "").strip()
    if env_value:
        return env_value
    return str(preset.get("recommended_judge_model") or "").strip()


def _append_flag(command: List[str], flag: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            return
        command.extend([flag, normalized])
        return
    command.extend([flag, str(value)])


"""
Function: build_launch_preset_command
Inputs:
  - preset_name: configured preset identifier from
    `Testing/config/presets/*.json`.
  - explicit_judge_model and the remaining keyword arguments: wrapper-level
    overrides that should be applied when expanding the preset.
Description:
  Convert one launch preset plus any runtime overrides into the exact command
  line that will launch the maintained single-run or sweep workflow.
Outputs:
  Returns the command as a list of argv strings.
Side Effects:
  Reads launch-preset config and environment variables to resolve the final
  command shape.
"""
def build_launch_preset_command(
    preset_name: str,
    *,
    explicit_judge_model: str = "",
    enable_budget_guardrails: bool = False,
    prefer_upx_unpacked: bool = False,
    task_failure_retries: int | None = None,
    preflight_only: bool = False,
    live_view: bool = False,
    max_concurrent_repetitions: int | None = None,
    skip_build: bool = False,
    skip_prepare: bool = False,
    ghidra_install_dir: str = "",
    ghidra_headless: str = "",
    timeout_sec: int | None = None,
) -> List[str]:
    preset = resolve_launch_preset(preset_name)
    runner = str(preset.get("runner") or "sweep").strip().lower()
    if runner == "sweep":
        script = "Testing/scripts/run_experiment_sweep.py"
    elif runner == "single_run":
        script = "Testing/scripts/run_evaluation.py"
    else:
        raise ValueError(f"Unsupported preset runner {runner!r} for preset {preset_name!r}")

    command: List[str] = [repo_python_executable(), script]
    command.extend(["--corpus", str(preset.get("corpus") or "experimental")])

    for sample in preset.get("samples") or []:
        command.extend(["--sample", str(sample)])
    for task_id in preset.get("tasks") or []:
        command.extend(["--task", str(task_id)])
    for variable in preset.get("variables") or []:
        if runner == "sweep":
            command.extend(["--variable", str(variable)])
    for difficulty in preset.get("difficulty_filters") or []:
        command.extend(["--difficulty-filter", str(difficulty)])

    repetitions = preset.get("repetitions")
    if runner == "sweep" and repetitions is not None:
        command.extend(["--repetitions", str(int(repetitions))])
    preset_concurrency = max_concurrent_repetitions
    if preset_concurrency is None:
        preset_concurrency = preset.get("max_concurrent_repetitions")
    if runner == "sweep" and preset_concurrency is not None and int(preset_concurrency) > 0:
        command.extend(["--max-concurrent-repetitions", str(int(preset_concurrency))])

    for key, flag in _COMMON_FLAG_FIELDS:
        _append_flag(command, flag, preset.get(key))

    if runner == "single_run":
        for key, flag in _SINGLE_RUN_FLAG_FIELDS:
            _append_flag(command, flag, preset.get(key))
    if runner == "sweep":
        for key, flag in _SWEEP_FLAG_FIELDS:
            _append_flag(command, flag, preset.get(key))

    if enable_budget_guardrails:
        command.append("--enable-budget-guardrails")
        for key, flag in _RUN_BUDGET_FLAG_FIELDS:
            _append_flag(command, flag, preset.get(key))
        if runner == "sweep":
            for key, flag in _EXPERIMENT_BUDGET_FLAG_FIELDS:
                _append_flag(command, flag, preset.get(key))

    if bool(preset.get("skip_visuals")) and runner == "sweep":
        command.append("--skip-visuals")
    if live_view and runner == "sweep":
        command.append("--live-view")
    if prefer_upx_unpacked or bool(preset.get("prefer_upx_unpacked")):
        command.append("--prefer-unpacked-upx")
    resolved_task_failure_retries = task_failure_retries
    if resolved_task_failure_retries is None:
        resolved_task_failure_retries = preset.get("task_failure_retries")
    if resolved_task_failure_retries is not None and int(resolved_task_failure_retries) > 0:
        command.extend(["--task-failure-retries", str(int(resolved_task_failure_retries))])
    if skip_build:
        command.append("--skip-build")
    if skip_prepare:
        command.append("--skip-prepare")
    if ghidra_install_dir:
        command.extend(["--ghidra-install-dir", ghidra_install_dir])
    if ghidra_headless:
        command.extend(["--ghidra-headless", ghidra_headless])
    if timeout_sec is not None and int(timeout_sec) > 0:
        command.extend(["--timeout-sec", str(int(timeout_sec))])

    judge_model = _resolved_judge_model(preset, explicit_judge_model=explicit_judge_model)
    if judge_model:
        command.extend(["--judge-model", judge_model])
    if preflight_only:
        command.append("--preflight-only")
    return command
