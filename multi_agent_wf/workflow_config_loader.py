import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _load_json_file(config_dir: Path, filename: str) -> Any:
    path = (config_dir / filename).resolve()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise RuntimeError(f"Workflow config file not found: {path}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Workflow config JSON parse failed for {path}: {e}") from e


def _expect_mapping(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _expect_string_list(value: Any, label: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"{label} must be a list of strings")
    return value


def _apply_placeholders(text: str, placeholders: Dict[str, str]) -> str:
    rendered = text
    for key, value in placeholders.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", value)
    return rendered


def _render_text_block(value: Any, label: str, placeholders: Dict[str, str]) -> str:
    if isinstance(value, str):
        return _apply_placeholders(value.rstrip(), placeholders)
    if isinstance(value, list):
        lines = _expect_string_list(value, label)
        return _apply_placeholders("\n".join(lines).rstrip(), placeholders)
    raise RuntimeError(f"{label} must be either a string or a list of strings")


def _normalize_architecture(value: Any, label: str) -> List[Tuple[str, int]]:
    if not isinstance(value, list):
        raise RuntimeError(f"{label} must be a list")

    normalized: List[Tuple[str, int]] = []
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, list) or len(item) != 2:
            raise RuntimeError(f"{label}[{idx}] must be a two-item list like [role, quantity]")
        role, quantity = item
        if not isinstance(role, str) or not role.strip():
            raise RuntimeError(f"{label}[{idx}][0] must be a non-empty role name")
        if not isinstance(quantity, int):
            raise RuntimeError(f"{label}[{idx}][1] must be an integer quantity")
        normalized.append((role, quantity))
    return normalized


def _load_architecture_presets(config_dir: Path) -> tuple[Dict[str, List[Tuple[str, int]]], Dict[str, str]]:
    raw = _expect_mapping(_load_json_file(config_dir, "architecture_presets.json"), "architecture_presets.json")
    presets: Dict[str, List[Tuple[str, int]]] = {}
    descriptions: Dict[str, str] = {}
    for preset_name, value in raw.items():
        description = ""
        slots = value
        if isinstance(value, dict):
            description_value = value.get("description")
            if description_value is not None:
                description = _render_text_block(
                    description_value,
                    f"architecture_presets.json::{preset_name}.description",
                    {},
                ).strip()
            slots = value.get("slots")
        presets[preset_name] = _normalize_architecture(slots, f"architecture_presets.json::{preset_name}")
        descriptions[preset_name] = description
    return presets, descriptions


def _normalize_pipeline_stage(raw_stage: Any, label: str) -> Dict[str, Any]:
    if not isinstance(raw_stage, dict):
        raise RuntimeError(f"{label} must be an object")

    name = raw_stage.get("name")
    stage_kind = raw_stage.get("stage_kind")
    if not isinstance(name, str) or not name.strip():
        raise RuntimeError(f"{label}.name must be a non-empty string")
    if not isinstance(stage_kind, str) or not stage_kind.strip():
        raise RuntimeError(f"{label}.stage_kind must be a non-empty string")

    architecture = _normalize_architecture(raw_stage.get("architecture", []), f"{label}.architecture")
    use_worker_architecture = bool(raw_stage.get("use_worker_architecture", False))
    model = raw_stage.get("model")
    if model is not None and (not isinstance(model, str) or not model.strip()):
        raise RuntimeError(f"{label}.model must be a non-empty string when provided")

    normalized = {
        "name": name,
        "stage_kind": stage_kind,
        "architecture": architecture,
        "use_worker_architecture": use_worker_architecture,
    }
    if isinstance(model, str) and model.strip():
        normalized["model"] = model.strip()
    return normalized


def _load_pipeline_presets(config_dir: Path) -> tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    # Tutorial 1.2 in extension_tutorial.md: add new pipeline preset entries in
    # `workflow_config/pipeline_presets.json`. If a preset references a new
    # `stage_kind`, continue with Tutorial 2 before using that preset.
    raw = _expect_mapping(_load_json_file(config_dir, "pipeline_presets.json"), "pipeline_presets.json")
    presets: Dict[str, List[Dict[str, Any]]] = {}
    descriptions: Dict[str, str] = {}
    for preset_name, stages in raw.items():
        description = ""
        if isinstance(stages, dict):
            description_value = stages.get("description")
            if description_value is not None:
                description = _render_text_block(
                    description_value,
                    f"pipeline_presets.json::{preset_name}.description",
                    {},
                ).strip()
            stages = stages.get("stages")
        if not isinstance(stages, list):
            raise RuntimeError(f"pipeline_presets.json::{preset_name} must be a list or an object with a stages list")
        presets[preset_name] = [
            _normalize_pipeline_stage(stage, f"pipeline_presets.json::{preset_name}[{idx}]")
            for idx, stage in enumerate(stages, start=1)
        ]
        descriptions[preset_name] = description
    return presets, descriptions


def _load_agent_archetype_specs(config_dir: Path) -> Dict[str, Dict[str, str]]:
    # Tutorial 3.2 in extension_tutorial.md: register each new role here before
    # any architecture preset can reference it. If the role uses a new
    # `tool_domain`, continue with Tutorial 3.6 in runtime.py.
    raw = _expect_mapping(_load_json_file(config_dir, "agent_archetype_specs.json"), "agent_archetype_specs.json")
    specs: Dict[str, Dict[str, str]] = {}
    required_keys = ("description", "tool_domain", "preferred_mode", "typical_complexity")
    for name, value in raw.items():
        entry = _expect_mapping(value, f"agent_archetype_specs.json::{name}")
        normalized: Dict[str, str] = {}
        for key in required_keys:
            raw_field = entry.get(key)
            if not isinstance(raw_field, str) or not raw_field.strip():
                raise RuntimeError(f"agent_archetype_specs.json::{name}.{key} must be a non-empty string")
            normalized[key] = raw_field
        raw_model = entry.get("model")
        if raw_model is not None:
            if not isinstance(raw_model, str) or not raw_model.strip():
                raise RuntimeError(f"agent_archetype_specs.json::{name}.model must be a non-empty string")
            normalized["model"] = raw_model.strip()
        specs[name] = normalized
    return specs


def _load_text_map(config_dir: Path, filename: str, placeholders: Dict[str, str]) -> Dict[str, str]:
    raw = _expect_mapping(_load_json_file(config_dir, filename), filename)
    return {
        name: _render_text_block(value, f"{filename}::{name}", placeholders)
        for name, value in raw.items()
    }


def _load_stage_kind_metadata(config_dir: Path) -> Dict[str, Dict[str, bool]]:
    # Tutorial 2.1 in extension_tutorial.md: every new stage kind starts here,
    # but it must stay aligned with Tutorials 2.2-2.6 before it is runnable.
    raw = _expect_mapping(_load_json_file(config_dir, "stage_kind_metadata.json"), "stage_kind_metadata.json")
    required_keys = (
        "tool_free",
        "supports_parallel_assignments",
        "finalizes_report",
        "parses_planner_work_items",
        "runs_validation_gate",
    )
    normalized: Dict[str, Dict[str, bool]] = {}
    for name, value in raw.items():
        entry = _expect_mapping(value, f"stage_kind_metadata.json::{name}")
        normalized_entry: Dict[str, bool] = {}
        for key in required_keys:
            raw_field = entry.get(key)
            if not isinstance(raw_field, bool):
                raise RuntimeError(f"stage_kind_metadata.json::{name}.{key} must be a boolean")
            normalized_entry[key] = raw_field
        normalized[name] = normalized_entry
    return normalized


def _load_base_prompts(config_dir: Path, placeholders: Dict[str, str]) -> Dict[str, str]:
    return _load_text_map(config_dir, "base_prompts.json", placeholders)


def _load_agent_archetype_prompts(
    config_dir: Path,
    base_prompts: Dict[str, str],
    placeholders: Dict[str, str],
) -> Dict[str, str]:
    raw = _expect_mapping(_load_json_file(config_dir, "agent_archetype_prompts.json"), "agent_archetype_prompts.json")
    prompts: Dict[str, str] = {}

    for name, value in raw.items():
        entry = _expect_mapping(value, f"agent_archetype_prompts.json::{name}")
        base_key = entry.get("base")
        if not isinstance(base_key, str) or base_key not in base_prompts:
            raise RuntimeError(
                f"agent_archetype_prompts.json::{name}.base must reference a key from base_prompts.json"
            )

        prompt = base_prompts[base_key].rstrip()
        specialization = entry.get("specialization")
        if specialization is not None:
            rules = _expect_string_list(specialization, f"agent_archetype_prompts.json::{name}.specialization")
            if rules:
                prompt += "\n\nSpecialization:\n" + "\n".join(f"- {rule}" for rule in rules) + "\n"

        prompts[name] = _apply_placeholders(prompt.rstrip(), placeholders)

    return prompts


def _load_worker_persona_profiles(config_dir: Path) -> Dict[str, Dict[str, Any]]:
    raw = _expect_mapping(_load_json_file(config_dir, "worker_persona_profiles.json"), "worker_persona_profiles.json")
    profiles: Dict[str, Dict[str, Any]] = {}
    for name, value in raw.items():
        entry = _expect_mapping(value, f"worker_persona_profiles.json::{name}")
        description = str(entry.get("description") or "").strip()
        specialization = entry.get("specialization")
        rules = (
            _expect_string_list(specialization, f"worker_persona_profiles.json::{name}.specialization")
            if specialization is not None
            else []
        )
        profiles[str(name).strip()] = {
            "description": description,
            "specialization": rules,
        }
    if "default" not in profiles:
        raise RuntimeError("worker_persona_profiles.json must define a `default` profile")
    return profiles


def load_workflow_config(config_dir: Path, placeholders: Dict[str, str]) -> Dict[str, Any]:
    base_prompts = _load_base_prompts(config_dir, placeholders)
    architecture_presets, architecture_preset_descriptions = _load_architecture_presets(config_dir)
    pipeline_presets, pipeline_preset_descriptions = _load_pipeline_presets(config_dir)
    return {
        "architecture_presets": architecture_presets,
        "architecture_preset_descriptions": architecture_preset_descriptions,
        "stage_kind_metadata": _load_stage_kind_metadata(config_dir),
        "pipeline_presets": pipeline_presets,
        "pipeline_preset_descriptions": pipeline_preset_descriptions,
        "agent_archetype_specs": _load_agent_archetype_specs(config_dir),
        "stage_output_contracts": _load_text_map(config_dir, "stage_output_contracts.json", placeholders),
        "stage_manager_prompts": _load_text_map(config_dir, "stage_manager_prompts.json", placeholders),
        "agent_archetype_prompts": _load_agent_archetype_prompts(config_dir, base_prompts, placeholders),
        "worker_persona_profiles": _load_worker_persona_profiles(config_dir),
    }
