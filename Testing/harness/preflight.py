from __future__ import annotations

import os
import subprocess
import sys
import importlib.util
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .artifacts import inspect_corpus_bundles, load_tool_profiles
from .judge import Agent, PYDANTIC_AVAILABLE
from .paths import CONFIG_ROOT, PROMPTS_ROOT, REPO_ROOT, read_json
from .query_variants import load_query_variants
from .samples import build_evaluation_tasks

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from multi_agent_wf.config import (
    DEEP_AGENT_ARCHITECTURE_PRESETS,
    DEEP_AGENT_PIPELINE_PRESETS,
    VALIDATOR_REVIEW_LEVEL_LABELS,
)


def _rubric_dimension_map(rubric: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for dim in rubric.get("dimensions") or []:
        if not isinstance(dim, dict):
            continue
        name = str(dim.get("name") or "").strip()
        if name:
            result[name] = dim
    return result


def validate_binary_judge_rubric() -> Dict[str, Any]:
    rubric = read_json(CONFIG_ROOT / "binary_judge_rubric.json")
    errors: List[str] = []
    warnings: List[str] = []

    dimensions = rubric.get("dimensions")
    if not isinstance(dimensions, list) or not dimensions:
        errors.append("binary_judge_rubric.json must define a non-empty dimensions list.")
        return {"ok": False, "errors": errors, "warnings": warnings, "rubric": rubric}

    names: List[str] = []
    raw_total = 0
    for idx, dim in enumerate(dimensions, start=1):
        if not isinstance(dim, dict):
            errors.append(f"Dimension #{idx} is not an object.")
            continue
        name = str(dim.get("name") or "").strip()
        if not name:
            errors.append(f"Dimension #{idx} is missing a non-empty name.")
            continue
        names.append(name)
        max_score = dim.get("max_score")
        if not isinstance(max_score, int) or max_score <= 0:
            errors.append(f"Dimension {name!r} must define a positive integer max_score.")
            continue
        raw_total += max_score
        levels = dim.get("levels")
        if not isinstance(levels, list) or not levels:
            errors.append(f"Dimension {name!r} must define a non-empty levels list.")
            continue
        seen_scores: set[int] = set()
        for level in levels:
            if not isinstance(level, dict):
                errors.append(f"Dimension {name!r} has a non-object level entry.")
                continue
            score = level.get("score")
            if not isinstance(score, int):
                errors.append(f"Dimension {name!r} has a level with a non-integer score.")
                continue
            if score < 0 or score > max_score:
                errors.append(f"Dimension {name!r} level score {score} is outside 0..{max_score}.")
            if score in seen_scores:
                errors.append(f"Dimension {name!r} has duplicate level score {score}.")
            seen_scores.add(score)
        expected_scores = set(range(0, max_score + 1))
        if seen_scores != expected_scores:
            warnings.append(
                f"Dimension {name!r} levels do not cover every score from 0..{max_score}; "
                f"found {sorted(seen_scores)}."
            )

    if len(names) != len(set(names)):
        errors.append("Rubric dimension names must be unique.")

    normalization = rubric.get("normalization") if isinstance(rubric.get("normalization"), dict) else {}
    raw_total_max = normalization.get("raw_total_max")
    if not isinstance(raw_total_max, int):
        errors.append("normalization.raw_total_max must be an integer.")
    elif raw_total_max != raw_total:
        errors.append(
            f"normalization.raw_total_max={raw_total_max} does not match the sum of dimension max scores ({raw_total})."
        )
    elif raw_total_max != 28:
        warnings.append(
            "normalization.raw_total_max changed from 28. Ensure the result schema and docs use rubric-agnostic raw-total field names."
        )

    thresholds = rubric.get("pass_thresholds") if isinstance(rubric.get("pass_thresholds"), dict) else {}
    dim_map = _rubric_dimension_map(rubric)
    for threshold_key, dim_name in (
        ("minimum_false_claim_control", "false_claim_control"),
        ("minimum_evidence_grounding", "evidence_grounding"),
    ):
        if dim_name not in dim_map:
            errors.append(f"Rubric is missing required dimension {dim_name!r} referenced by judge thresholds.")
            continue
        value = thresholds.get(threshold_key)
        if not isinstance(value, int):
            errors.append(f"pass_thresholds.{threshold_key} must be an integer.")
            continue
        max_score = int(dim_map[dim_name].get("max_score") or 0)
        if value < 0 or value > max_score:
            errors.append(f"pass_thresholds.{threshold_key}={value} is outside 0..{max_score}.")

    overall_threshold = thresholds.get("overall_score_0_to_100")
    if overall_threshold is not None:
        try:
            overall_value = float(overall_threshold)
            if overall_value < 0.0 or overall_value > 100.0:
                errors.append("pass_thresholds.overall_score_0_to_100 must be between 0 and 100.")
        except Exception:
            errors.append("pass_thresholds.overall_score_0_to_100 must be numeric.")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "dimension_names": names,
        "raw_total_max": raw_total_max,
    }


def validate_binary_judge_prompt() -> Dict[str, Any]:
    prompt_text = (PROMPTS_ROOT / "binary_judge_prompt.md").read_text(encoding="utf-8")
    rubric = read_json(CONFIG_ROOT / "binary_judge_rubric.json")
    dim_names = list(_rubric_dimension_map(rubric).keys())
    errors: List[str] = []
    warnings: List[str] = []

    for name in dim_names:
        if name not in prompt_text:
            errors.append(f"Judge prompt does not mention rubric dimension {name!r}.")
    if "target_signals" in prompt_text:
        errors.append("Judge prompt still references stale field `target_signals`; use expected_evidence / acceptance_targets instead.")
    if "acceptance_targets" not in prompt_text:
        warnings.append("Judge prompt does not explicitly mention acceptance_targets.")
    return {"ok": not errors, "errors": errors, "warnings": warnings}


def _module_available_in_python(python_executable: str, module_name: str) -> bool:
    executable = str(python_executable or "").strip()
    if executable:
        try:
            if Path(executable).resolve() != Path(sys.executable).resolve():
                completed = subprocess.run(
                    [
                        executable,
                        "-c",
                        (
                            "import importlib.util, sys; "
                            f"sys.exit(0 if importlib.util.find_spec({module_name!r}) else 1)"
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return completed.returncode == 0
        except Exception:
            return False
    if module_name == "pydantic":
        return bool(PYDANTIC_AVAILABLE)
    if module_name == "pydantic_ai":
        return Agent is not None
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False


def validate_run_configuration(
    *,
    corpus_name: str,
    sample_paths: List[Path],
    manifest: Dict[str, Any],
    selected_samples: Iterable[str],
    selected_task_ids: Iterable[str],
    selected_difficulties: Iterable[str],
    pipeline: str,
    architecture: str,
    query_variant: str,
    worker_persona_profile: str,
    validator_review_level: str,
    tool_profile: str,
    judge_mode: str,
    explicit_judge_model: str = "",
    forced_model: str = "",
    python_executable: str = "",
    bundle_root: Optional[Path] = None,
    require_ready_bundles: bool = False,
) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []

    rubric_check = validate_binary_judge_rubric()
    prompt_check = validate_binary_judge_prompt()
    errors.extend(rubric_check.get("errors") or [])
    warnings.extend(rubric_check.get("warnings") or [])
    errors.extend(prompt_check.get("errors") or [])
    warnings.extend(prompt_check.get("warnings") or [])

    variants = load_query_variants()
    selected_query_variant = str(query_variant or "default").strip() or "default"
    if "default" not in variants:
        errors.append("query_variants.json must define a `default` variant.")
    if selected_query_variant not in variants:
        errors.append(
            f"Unknown query variant {selected_query_variant!r}. Available: {', '.join(sorted(variants))}"
        )

    persona_profiles_raw = read_json(REPO_ROOT / "multi_agent_wf" / "workflow_config" / "worker_persona_profiles.json")
    persona_profiles = persona_profiles_raw if isinstance(persona_profiles_raw, dict) else {}
    selected_persona_profile = str(worker_persona_profile or "default").strip() or "default"
    if "default" not in persona_profiles:
        errors.append("worker_persona_profiles.json must define a `default` profile.")
    if selected_persona_profile not in persona_profiles:
        errors.append(
            f"Unknown worker_persona_profile {selected_persona_profile!r}. "
            f"Available: {', '.join(sorted(persona_profiles))}"
        )

    if validator_review_level not in VALIDATOR_REVIEW_LEVEL_LABELS:
        errors.append(
            f"Unknown validator_review_level {validator_review_level!r}. "
            f"Available: {', '.join(sorted(VALIDATOR_REVIEW_LEVEL_LABELS))}"
        )

    tool_profiles = load_tool_profiles()
    available_tool_profiles = (
        tool_profiles.get("profiles")
        if isinstance(tool_profiles.get("profiles"), dict)
        else {}
    )
    requested_tool_profile = str(tool_profile or "full").strip() or "full"
    if requested_tool_profile not in available_tool_profiles:
        errors.append(
            f"Unknown tool_profile {requested_tool_profile!r}. "
            f"Available: {', '.join(sorted(available_tool_profiles))}"
        )

    if pipeline not in DEEP_AGENT_PIPELINE_PRESETS:
        errors.append(
            f"Unknown pipeline preset {pipeline!r}. Available: {', '.join(sorted(DEEP_AGENT_PIPELINE_PRESETS))}"
        )
    if architecture not in DEEP_AGENT_ARCHITECTURE_PRESETS:
        errors.append(
            f"Unknown architecture preset {architecture!r}. Available: {', '.join(sorted(DEEP_AGENT_ARCHITECTURE_PRESETS))}"
        )

    selected_sample_names = [str(item).strip() for item in selected_samples if str(item).strip()]
    difficulty_filters = {str(item).strip().lower() for item in selected_difficulties if str(item).strip()}
    available_names = [path.name for path in sample_paths]
    manifest_order = list(manifest.get("sample_order") or [])
    manifest_defined = set(manifest_order)
    available_set = set(available_names)

    missing_requested = [name for name in selected_sample_names if name not in available_set]
    if missing_requested:
        errors.append(
            "Requested sample(s) are missing from the build output: " + ", ".join(sorted(missing_requested))
        )

    if not selected_sample_names:
        def _included_by_difficulty(name: str) -> bool:
            if not difficulty_filters:
                return True
            sample_meta = (manifest.get("samples") or {}).get(name) if isinstance(manifest.get("samples"), dict) else {}
            difficulty = str((sample_meta or {}).get("difficulty") or "unknown").strip().lower()
            return difficulty in difficulty_filters

        missing_manifest_samples = [name for name in manifest_order if _included_by_difficulty(name) and name not in available_set]
        if missing_manifest_samples:
            errors.append(
                "The built corpus does not cover the full manifest-defined sample set: "
                + ", ".join(missing_manifest_samples)
            )

    task_ids = [str(item).strip() for item in selected_task_ids if str(item).strip()]
    resolved_tasks = build_evaluation_tasks(
        corpus_name,
        sample_paths,
        manifest=manifest,
        selected_task_ids=task_ids,
        selected_difficulties=selected_difficulties,
    )
    if not resolved_tasks:
        errors.append("No evaluation tasks resolved for the selected sample/task scope.")
    else:
        seen_task_ids = {task.task_id for task in resolved_tasks}
        missing_tasks = [task_id for task_id in task_ids if task_id not in seen_task_ids]
        if missing_tasks:
            errors.append(
                "Requested task id(s) were not found in the selected sample set: " + ", ".join(sorted(missing_tasks))
            )
        for task in resolved_tasks:
            if not task.expected_evidence:
                warnings.append(f"{task.sample_name}::{task.task_id} has no expected_evidence anchors.")
            if not task.acceptance_targets:
                warnings.append(f"{task.sample_name}::{task.task_id} has no acceptance_targets.")

    if judge_mode == "agent":
        if not _module_available_in_python(python_executable, "pydantic"):
            errors.append("pydantic is not installed; agent-based judging cannot run.")
        if not _module_available_in_python(python_executable, "pydantic_ai"):
            errors.append("pydantic_ai is not installed; agent-based judging cannot run.")
        if not os.environ.get("OPENAI_API_KEY"):
            warnings.append(
                "OPENAI_API_KEY is not set. If you are using default OpenAI-backed models, paid runs may fail."
            )
        guardrail_config = read_json(CONFIG_ROOT / "budget_guardrails.json") if (CONFIG_ROOT / "budget_guardrails.json").exists() else {}
        guardrail_defaults = guardrail_config.get("defaults") if isinstance(guardrail_config.get("defaults"), dict) else {}
        require_explicit_judge_model = bool(guardrail_defaults.get("require_explicit_judge_model", True))
        allow_implicit_judge_model = bool(guardrail_defaults.get("allow_implicit_judge_model", False)) or os.environ.get("EVAL_ALLOW_IMPLICIT_JUDGE_MODEL", "").strip() in {"1", "true", "TRUE", "yes"}
        allow_self_evaluation = bool(guardrail_defaults.get("allow_self_evaluation", False)) or os.environ.get("EVAL_ALLOW_SELF_EVAL", "").strip() in {"1", "true", "TRUE", "yes"}
        judge_env = str(explicit_judge_model or os.environ.get("EVAL_JUDGE_MODEL") or "").strip()
        agent_env = os.environ.get("OPENAI_MODEL_ID", "").strip()
        force_model_env = str(forced_model or os.environ.get("DEEP_FORCE_MODEL_ID") or "").strip()
        if require_explicit_judge_model and not judge_env and not allow_implicit_judge_model:
            errors.append(
                "Agent judging requires an explicit judge model. Set --judge-model or EVAL_JUDGE_MODEL, "
                "or set EVAL_ALLOW_IMPLICIT_JUDGE_MODEL=1 to permit fallback behavior."
            )
        if judge_env and not allow_self_evaluation:
            if force_model_env and judge_env == force_model_env:
                errors.append(
                    f"Judge model {judge_env!r} matches the forced agent model {force_model_env!r}. "
                    "Use a distinct judge model or set EVAL_ALLOW_SELF_EVAL=1."
                )
            elif not force_model_env and agent_env and judge_env == agent_env:
                errors.append(
                    f"Judge model {judge_env!r} matches OPENAI_MODEL_ID {agent_env!r}. "
                    "Use a distinct judge model or set EVAL_ALLOW_SELF_EVAL=1."
                )
    else:
        warnings.append(
            "judge_mode is disabled; runs will not produce rubric scores or valid baseline-vs-variant score comparisons."
        )

    bundle_readiness: Dict[str, Any] | None = None
    if require_ready_bundles and bundle_root is not None:
        bundle_readiness = inspect_corpus_bundles(corpus_name, sample_paths, output_root=bundle_root)
        if not bool(bundle_readiness.get("ready_for_analysis")):
            missing_items = [
                f"{item.get('sample')}: {', '.join(item.get('missing_required') or [])}"
                for item in (bundle_readiness.get("results") or [])
                if item.get("missing_required")
            ]
            errors.append(
                "Prepared bundles are missing required files: " + "; ".join(missing_items)
            )
        if not bool(bundle_readiness.get("fresh_for_analysis")):
            stale_items = [
                f"{item.get('sample')}: {', '.join(item.get('stale_reasons') or [])}"
                for item in (bundle_readiness.get("results") or [])
                if item.get("stale_reasons")
            ]
            errors.append(
                "Prepared bundles are stale and should be regenerated: " + "; ".join(stale_items)
            )

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "sample_count": len(sample_paths),
        "task_count": len(resolved_tasks),
        "bundle_readiness": bundle_readiness,
        "rubric_check": rubric_check,
        "prompt_check": prompt_check,
    }
