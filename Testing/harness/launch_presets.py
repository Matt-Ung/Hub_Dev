from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from .paths import CONFIG_ROOT, read_json


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


def build_launch_preset_command(
    preset_name: str,
    *,
    explicit_judge_model: str = "",
    preflight_only: bool = False,
    skip_build: bool = False,
    skip_prepare: bool = False,
    ghidra_install_dir: str = "",
    ghidra_headless: str = "",
    timeout_sec: int = 900,
) -> List[str]:
    preset = resolve_launch_preset(preset_name)
    runner = str(preset.get("runner") or "sweep").strip().lower()
    if runner == "sweep":
        script = "Testing/run_experiment_sweep.py"
    elif runner == "single_run":
        script = "Testing/run_evaluation.py"
    else:
        raise ValueError(f"Unsupported preset runner {runner!r} for preset {preset_name!r}")

    command: List[str] = [sys.executable, script]
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

    if bool(preset.get("skip_visuals")) and runner == "sweep":
        command.append("--skip-visuals")
    if skip_build:
        command.append("--skip-build")
    if skip_prepare:
        command.append("--skip-prepare")
    if ghidra_install_dir:
        command.extend(["--ghidra-install-dir", ghidra_install_dir])
    if ghidra_headless:
        command.extend(["--ghidra-headless", ghidra_headless])
    if timeout_sec:
        command.extend(["--timeout-sec", str(int(timeout_sec))])

    judge_model = _resolved_judge_model(preset, explicit_judge_model=explicit_judge_model)
    if judge_model:
        command.extend(["--judge-model", judge_model])
    if preflight_only:
        command.append("--preflight-only")
    return command
