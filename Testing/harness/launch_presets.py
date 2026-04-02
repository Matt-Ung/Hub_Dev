from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from .paths import CONFIG_ROOT, read_json, repo_python_executable


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
    path = CONFIG_ROOT / "launch_presets.json"
    if not path.exists():
        return {"version": "launch_presets_v1", "presets": {}}
    return read_json(path)


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


def build_launch_preset_command(
    preset_name: str,
    *,
    explicit_judge_model: str = "",
    enable_budget_guardrails: bool = False,
    preflight_only: bool = False,
    live_view: bool = False,
    skip_build: bool = False,
    skip_prepare: bool = False,
    ghidra_install_dir: str = "",
    ghidra_headless: str = "",
    timeout_sec: int | None = None,
) -> List[str]:
    preset = resolve_launch_preset(preset_name)
    runner = str(preset.get("runner") or "sweep").strip().lower()
    if runner == "sweep":
        script = "Testing/run_experiment_sweep.py"
    elif runner == "single_run":
        script = "Testing/run_evaluation.py"
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
