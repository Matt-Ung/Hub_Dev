"""
File: judge.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Evaluate binary-analysis task outputs against the maintained judging rubric.

Summary:
  This module translates raw agent output and manifest expectations into the
  canonical `judge_result.json` structure used by reporting and sweep
  aggregation. It loads the rubric, builds the response schema, constructs the
  judge prompt payload, and handles both normal and synthetic non-result cases.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

try:
    from pydantic import BaseModel, Field, create_model
    PYDANTIC_AVAILABLE = True
except ImportError:  # pragma: no cover - optional until runtime
    PYDANTIC_AVAILABLE = False

    class BaseModel:  # type: ignore[no-redef]
        pass

    def Field(*args, **kwargs):  # type: ignore[no-redef]
        return kwargs.get("default", None)

    def create_model(*args, **kwargs):  # type: ignore[no-redef]
        raise RuntimeError("pydantic is not installed in the active Python environment")

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional until runtime
    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False

try:
    from pydantic_ai import Agent
except ImportError:  # pragma: no cover - optional until runtime
    Agent = None  # type: ignore[assignment]

from .paths import CONFIG_ROOT, PROMPTS_ROOT, REPO_ROOT, read_json, write_json
from .samples import model_visible_sample_metadata
from .costing import coerce_usage_snapshot, estimate_usage_cost


# ---------------------------------------------------------------------------
# Static fallback models
# Used when the rubric file cannot be loaded or contains no dimension entries.
# Bounds here must stay in sync with the rubric as a last-resort safety net.
# ---------------------------------------------------------------------------

class _FallbackDimScores(BaseModel):
    evidence_grounding: int = Field(ge=0, le=5)
    specificity: int = Field(ge=0, le=5)
    technique_coverage: int = Field(ge=0, le=5)
    false_claim_control: int = Field(ge=0, le=5)
    task_alignment: int = Field(ge=0, le=5)
    report_conciseness: int = Field(ge=0, le=3)


class _FallbackJudgeResponse(BaseModel):
    dimension_scores: _FallbackDimScores
    unsupported_claims: List[str] = Field(default_factory=list)
    missed_expected_points: List[str] = Field(default_factory=list)
    strongest_points: List[str] = Field(default_factory=list)
    tool_observations: List[str] = Field(default_factory=list)
    technical_summary: str
    writing_summary: str
    follow_up_recommendations: List[str] = Field(default_factory=list)
    confidence_0_to_1: float = Field(ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------

_rubric_cache: Dict[str, Any] | None = None
# Stores (rubric_version_str, DimScoresModel, JudgeResponseModel)
_models_cache: tuple | None = None


# ---------------------------------------------------------------------------
# Rubric loading and Pydantic model factory
# ---------------------------------------------------------------------------

def _load_rubric() -> Dict[str, Any]:
    """Load binary_judge_rubric.json once and cache it for the process lifetime."""
    global _rubric_cache
    if _rubric_cache is None:
        _rubric_cache = read_json(CONFIG_ROOT / "binary_judge_rubric.json")
    return _rubric_cache


def _build_response_models(rubric: Dict[str, Any]):
    """
    Build and cache Pydantic models for the judge response with Field(le=max_score)
    bounds derived from the rubric's dimension definitions.

    The models are rebuilt only when the rubric version string changes, so a
    single-process evaluation run pays the build cost at most once.

    Returns (DimScoresModel, JudgeResponseModel).
    """
    global _models_cache
    version = str(rubric.get("version") or "")
    if _models_cache is not None and _models_cache[0] == version:
        return _models_cache[1], _models_cache[2]

    dimensions = [d for d in rubric.get("dimensions", []) if d.get("name")]
    if not dimensions:
        _models_cache = (version, _FallbackDimScores, _FallbackJudgeResponse)
        return _FallbackDimScores, _FallbackJudgeResponse

    dim_fields: Dict[str, Any] = {
        str(d["name"]): (int, Field(ge=0, le=int(d.get("max_score", 5))))
        for d in dimensions
    }
    DimScores = create_model("JudgeDimensionScores", **dim_fields)

    JudgeResponse = create_model(
        "BinaryJudgeResponse",
        dimension_scores=(DimScores, ...),
        unsupported_claims=(List[str], Field(default_factory=list)),
        missed_expected_points=(List[str], Field(default_factory=list)),
        strongest_points=(List[str], Field(default_factory=list)),
        tool_observations=(List[str], Field(default_factory=list)),
        technical_summary=(str, ...),
        writing_summary=(str, ...),
        follow_up_recommendations=(List[str], Field(default_factory=list)),
        confidence_0_to_1=(float, Field(ge=0.0, le=1.0)),
    )

    _models_cache = (version, DimScores, JudgeResponse)
    return DimScores, JudgeResponse


# ---------------------------------------------------------------------------
# Label and scoring helpers
# ---------------------------------------------------------------------------

def _build_label_lookup(rubric: Dict[str, Any]) -> Dict[str, Dict[int, str]]:
    """
    Build {dim_name: {score_int: label_str}} from the rubric's dimension level arrays.
    Used to produce human-readable score labels such as "Mostly evidenced".
    """
    lookup: Dict[str, Dict[int, str]] = {}
    for dim in rubric.get("dimensions", []):
        name = str(dim.get("name") or "")
        if not name:
            continue
        score_labels: Dict[int, str] = {}
        for level in dim.get("levels", []):
            try:
                score_labels[int(level["score"])] = str(level.get("label") or "")
            except (KeyError, ValueError, TypeError):
                continue
        if score_labels:
            lookup[name] = score_labels
    return lookup


def _zero_dimension_scores(rubric: Dict[str, Any]) -> Dict[str, int]:
    """Return a zero-value dict keyed by rubric dimension names."""
    dims = [str(d["name"]) for d in rubric.get("dimensions", []) if d.get("name")]
    if not dims:
        dims = [
            "evidence_grounding", "specificity", "technique_coverage",
            "false_claim_control", "task_alignment", "report_conciseness",
        ]
    return {name: 0 for name in dims}


def _build_score_labels(scores: Dict[str, int], rubric: Dict[str, Any]) -> Dict[str, str]:
    """
    Produce per-dimension labelled strings from a scores dict and the rubric.

    Each value has the form  "Label (score/max)"  e.g. "Mostly evidenced (4/5)".
    Falls back to  "score/max"  when no label is available for that score value.
    """
    label_lookup = _build_label_lookup(rubric)
    result: Dict[str, str] = {}
    for dim in rubric.get("dimensions", []):
        name = str(dim.get("name") or "")
        max_score = int(dim.get("max_score", 5))
        score_val = scores.get(name)
        if not name or score_val is None:
            continue
        label = (label_lookup.get(name) or {}).get(int(score_val), "")
        result[name] = (
            f"{label} ({score_val}/{max_score})" if label else f"{score_val}/{max_score}"
        )
    return result


def _compute_totals(response: Any, rubric: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute raw total, normalised 0-100 score, pass/fail, and per-dimension
    labelled strings from a completed judge response and the loaded rubric.

    All thresholds and the normalisation divisor are read from the rubric so
    that binary_judge_rubric.json is the single source of truth.
    """
    scores = response.dimension_scores.model_dump()

    # Sum over rubric-defined dimension names (order-independent, future-proof)
    dim_names = [str(d["name"]) for d in rubric.get("dimensions", []) if d.get("name")]
    if not dim_names:
        dim_names = list(scores.keys())
    raw_total = sum(scores.get(name, 0) for name in dim_names)

    # Normalisation divisor from rubric["normalization"]["raw_total_max"]
    normalization = rubric.get("normalization") or {}
    raw_total_max = int(
        normalization.get("raw_total_max")
        or sum(int(d.get("max_score", 5)) for d in rubric.get("dimensions", []))
        or 28
    )
    overall = round((raw_total / raw_total_max) * 100.0, 2)

    # Pass thresholds from rubric["pass_thresholds"]
    thresholds = rubric.get("pass_thresholds") or {}
    min_overall = float(thresholds.get("overall_score_0_to_100") or 70.0)
    min_fcc = int(thresholds.get("minimum_false_claim_control") or 3)
    min_eg = int(thresholds.get("minimum_evidence_grounding") or 3)
    passed = (
        overall >= min_overall
        and scores.get("false_claim_control", 0) >= min_fcc
        and scores.get("evidence_grounding", 0) >= min_eg
    )

    return {
        "raw_total_score": raw_total,
        "raw_total_max": raw_total_max,
        "overall_score_0_to_100": overall,
        "pass": passed,
        "dimension_score_labels": _build_score_labels(scores, rubric),
    }


# ---------------------------------------------------------------------------
# Non-result helper
# ---------------------------------------------------------------------------

def _build_non_result_judge_result(
    *,
    status: str,
    model_id: str,
    rubric_version: str,
    failure_reason: str,
    agent_result: Dict[str, Any],
    rubric: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Function: _build_non_result_judge_result
    Inputs:
      - status: normalized non-result status such as `analysis_error` or
        `validator_blocked`.
      - model_id: judge model identifier for reporting.
      - rubric_version: rubric version string associated with this result.
      - failure_reason: human-readable reason the run failed to produce a final result.
      - agent_result: canonical agent result payload for the failed case.
      - rubric: parsed rubric definition used to size the zero-score payload.
    Description:
      Build the synthetic judge result used when the run did not produce an
      accepted final answer, so downstream analysis still receives a complete
      and explicit `judge_result.json`.
    Outputs:
      Returns the synthetic non-result judge payload.
    Side Effects:
      None.
    """
    validator_summary = agent_result.get("validator_summary") if isinstance(agent_result.get("validator_summary"), dict) else {}
    validation = agent_result.get("validation") if isinstance(agent_result.get("validation"), dict) else {}
    technical_summary = failure_reason or "The run did not produce an accepted final output."
    if status == "validator_blocked":
        technical_summary = (
            "The run ended in a validator-gated failure and did not produce an accepted final result. "
            + technical_summary
        ).strip()
    elif status == "worker_assignment_failed":
        technical_summary = (
            "The run produced a provisional report, but one or more host-parallel worker assignments failed. "
            + technical_summary
        ).strip()
    elif status == "analysis_error":
        technical_summary = (
            "The run terminated with an execution error before producing an accepted final result. "
            + technical_summary
        ).strip()

    zero_scores = _zero_dimension_scores(rubric)
    # For non-results, override labels to clarify that no output was produced
    # rather than using the rubric's score-0 labels (e.g. "Predominantly false"
    # is misleading when the agent simply produced nothing).
    zero_labels = {name: f"No result produced (0/{int(d.get('max_score', 5))})" for d in rubric.get("dimensions", []) for name in [str(d.get("name") or "")] if name}

    return {
        "ok": True,
        "judge_model": model_id,
        "rubric_version": rubric_version,
        "status": status,
        "evaluation_mode": "synthetic_non_result",
        "failure_reason": failure_reason,
        "dimension_scores": zero_scores,
        "dimension_score_labels": zero_labels,
        "overall_score_0_to_100": 0.0,
        "raw_total_score": 0,
        "raw_total_max": int((rubric.get("normalization") or {}).get("raw_total_max") or 0),
        "pass": False,
        "unsupported_claims": [],
        "missed_expected_points": [],
        "strongest_points": [],
        "tool_observations": [],
        "technical_summary": technical_summary,
        "writing_summary": "No accepted final answer was available to score for writing quality.",
        "follow_up_recommendations": [
            "Review the validator feedback and reduce unsupported claims before retrying.",
        ] if status == "validator_blocked" else [
            "Stabilize the host-parallel worker path and rerun the analysis.",
        ] if status == "worker_assignment_failed" else [
            "Resolve the execution failure and rerun the analysis.",
        ],
        # Synthetic non-results should not look like high-confidence judged
        # conclusions. Reserve non-zero confidence for real judge outputs.
        "confidence_0_to_1": 0.0,
        "usage": {},
        "cost_estimate": {},
        "duration_sec": 0.0,
        "validator_summary": validator_summary,
        "validation": validation,
        "produced_result": False,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _load_judge_model_id(explicit_model: str = "") -> str:
    """
    Function: _load_judge_model_id
    Inputs:
      - explicit_model: optional explicit judge model override from the caller.
    Description:
      Resolve the judge model in priority order: explicit override, evaluation
      env var, repo default env var, then the hardcoded fallback.
    Outputs:
      Returns the resolved judge model identifier string.
    Side Effects:
      Loads the repo `.env` file on first use.
    """
    load_dotenv(REPO_ROOT / ".env", override=False)
    return str(explicit_model or os.environ.get("EVAL_JUDGE_MODEL") or os.environ.get("OPENAI_MODEL_ID") or "openai:gpt-5-mini").strip()


def _load_prompt_template() -> str:
    """
    Function: _load_prompt_template
    Inputs:
      - None.
    Description:
      Load the maintained judge prompt template from disk.
    Outputs:
      Returns the prompt template text as a string.
    Side Effects:
      Reads the prompt template file from disk.
    """
    return (PROMPTS_ROOT / "binary_judge_prompt.md").read_text(encoding="utf-8")


"""
Function: _load_evaluator_reference
Inputs:
  - sample_meta: raw corpus-manifest metadata for the current evaluation case.
Description:
  Load the evaluator-only reference JSON for a sample when one is declared in
  the manifest, then normalize it into the smaller ground-truth structure that
  the judge prompt consumes.
Outputs:
  Returns a dictionary of evaluator reference fields. Returns an empty
  dictionary when no checked-in reference exists or the file cannot be read.
Side Effects:
  Reads the per-sample evaluator reference JSON from disk.
"""
def _load_evaluator_reference(sample_meta: Dict[str, Any]) -> Dict[str, Any]:
    reference_path = str(sample_meta.get("reference_json_path") or "").strip()
    if not reference_path:
        return {}

    candidate = Path(reference_path)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate

    try:
        raw = read_json(candidate)
    except Exception:
        return {}

    judge_reference = raw.get("judge_reference") if isinstance(raw.get("judge_reference"), dict) else {}
    reporting_reference = raw.get("reporting_reference") if isinstance(raw.get("reporting_reference"), dict) else {}
    grounding = raw.get("grounding") if isinstance(raw.get("grounding"), list) else []

    def _as_list(value: Any) -> List[Any]:
        return list(value) if isinstance(value, list) else []

    return {
        "sample_label": str(raw.get("family_label") or sample_meta.get("family_label") or "").strip(),
        "intended_simulation": str(raw.get("intended_simulation") or "").strip(),
        "must_hit_anchors": [str(item).strip() for item in _as_list(judge_reference.get("must_hit_anchors")) if str(item).strip()],
        "high_confidence_artifacts": [
            str(item).strip()
            for item in _as_list(judge_reference.get("high_confidence_artifacts"))
            if str(item).strip()
        ],
        "supported_behavior_claims": [
            str(item).strip()
            for item in _as_list(judge_reference.get("supported_behavior_claims"))
            if str(item).strip()
        ],
        "minimum_report_sections": [
            str(item).strip()
            for item in _as_list(judge_reference.get("minimum_report_sections") or reporting_reference.get("expected_functionality_sections"))
            if str(item).strip()
        ],
        "limitations_to_respect": [
            str(item).strip()
            for item in _as_list(judge_reference.get("limitations_to_respect") or raw.get("important_limitations"))
            if str(item).strip()
        ],
        "do_not_overclaim": [
            str(item).strip()
            for item in _as_list(judge_reference.get("do_not_overclaim"))
            if str(item).strip()
        ],
        "common_failure_modes": [
            str(item).strip()
            for item in _as_list(judge_reference.get("common_failure_modes"))
            if str(item).strip()
        ],
        "grounding_examples": grounding[:8],
    }


def _build_judge_payload(
    sample_name: str,
    sample_meta: Dict[str, Any],
    task_meta: Dict[str, Any],
    bundle_manifest: Dict[str, Any],
    agent_result: Dict[str, Any],
    rubric: Dict[str, Any],
) -> str:
    """
    Function: _build_judge_payload
    Inputs:
      - sample_name / sample_meta / task_meta: manifest-derived identifiers and
        expectations for the current evaluation case.
      - bundle_manifest: prepared bundle metadata used as reference context.
      - agent_result: canonical analysis output to be judged.
      - rubric: parsed rubric definition that describes the scoring dimensions.
    Description:
      Assemble the full judge prompt by combining the template with a JSON
      payload that describes the sample, task expectations, bundle context, and
      agent output.
    Outputs:
      Returns the full judge prompt string sent to the model judge.
    Side Effects:
      None.
    """
    prompt_template = _load_prompt_template()
    judge_visible_sample_meta = model_visible_sample_metadata(sample_meta)
    evaluator_reference = _load_evaluator_reference(sample_meta)
    payload = {
        "sample_name": sample_name,
        "sample_metadata": judge_visible_sample_meta,
        "task_metadata": task_meta,
        "reference_expectations": {
            "expected_evidence": list(task_meta.get("expected_evidence") or judge_visible_sample_meta.get("expected_evidence") or []),
            "acceptance_targets": list(task_meta.get("acceptance_targets") or judge_visible_sample_meta.get("acceptance_targets") or []),
            "primary_techniques": list(judge_visible_sample_meta.get("primary_techniques") or []),
            "target_tools": list(task_meta.get("target_tools") or judge_visible_sample_meta.get("target_tools") or []),
        },
        "evaluator_reference": evaluator_reference,
        "bundle_context": {
            "identity": bundle_manifest.get("identity") or {},
            "ghidra_analysis_summary": bundle_manifest.get("ghidra_analysis_summary") or {},
            "cli_tool_outputs": bundle_manifest.get("cli_tool_outputs") or {},
            "analysis_target": bundle_manifest.get("analysis_target") or {},
            "upx_detection": bundle_manifest.get("upx_detection") or {},
            "upx_unpack": bundle_manifest.get("upx_unpack") or {},
        },
        "agent_result": {
            "ok": bool(agent_result.get("ok")),
            "query": str(agent_result.get("query") or ""),
            "analysis_target": agent_result.get("analysis_target") or {},
            "final_report": str(agent_result.get("final_report") or ""),
            "tool_usage": agent_result.get("tool_usage") or {},
            "planned_work_items": agent_result.get("planned_work_items") or [],
            "generated_yara_rules": agent_result.get("generated_yara_rules") or [],
            "ghidra_change_proposals": agent_result.get("ghidra_change_proposals") or [],
            "status_log": str(agent_result.get("status_log") or "")[:6000],
        },
        "rubric": rubric,
    }
    return prompt_template + "\n\nEvaluation payload:\n```json\n" + json.dumps(payload, indent=2, ensure_ascii=False) + "\n```"

"""
Function: judge_agent_result
Inputs:
  - sample_name / sample_meta / task_meta: manifest-derived identifiers and
    expectations for the current evaluation case.
  - bundle_manifest: prepared bundle metadata used as evidence context.
  - agent_result: canonical `agent_result.json` payload for the case.
  - judge_model: optional explicit judge model override.
  - output_json: optional artifact path where the result should be written.
Description:
  Run the maintained judging workflow for one sample-task case, including
  synthetic handling for non-results and rubric-based scoring for completed
  agent outputs.
Outputs:
  Returns the canonical `judge_result.json` dictionary. When `output_json`
  is provided, the same payload is also written to disk.
Side Effects:
  May call the configured judge model and may write the output artifact.
"""
def judge_agent_result(
    sample_name: str,
    sample_meta: Dict[str, Any],
    task_meta: Dict[str, Any],
    bundle_manifest: Dict[str, Any],
    agent_result: Dict[str, Any],
    *,
    judge_model: str = "",
    output_json: Path | None = None,
) -> Dict[str, Any]:
    rubric = _load_rubric()
    model_id = _load_judge_model_id(judge_model)
    rubric_version = str(rubric.get("version") or "binary_judge_v1")
    agent_status = str(agent_result.get("status") or "").strip() or ("completed" if agent_result.get("ok") else "analysis_error")
    produced_result = bool(agent_result.get("produced_result"))

    # Non-results are normalized into synthetic judge payloads so downstream
    # reporting can still reason about the run without special-casing missing
    # judge artifacts everywhere.
    if not produced_result or agent_status in {"validator_blocked", "analysis_error", "no_result", "worker_assignment_failed"}:
        result = _build_non_result_judge_result(
            status=agent_status,
            model_id=model_id,
            rubric_version=rubric_version,
            failure_reason=str(agent_result.get("failure_reason") or agent_result.get("error") or ""),
            agent_result=agent_result,
            rubric=rubric,
        )
        if output_json is not None:
            write_json(output_json, result)
        return result

    if not PYDANTIC_AVAILABLE:
        result = {
            "ok": False,
            "judge_model": model_id,
            "rubric_version": rubric_version,
            "status": "judge_error",
            "error": "pydantic is not installed in the active Python environment",
            "dimension_scores": {},
            "dimension_score_labels": {},
            "overall_score_0_to_100": None,
            "raw_total_score": None,
            "raw_total_max": int((rubric.get("normalization") or {}).get("raw_total_max") or 0),
            "pass": False,
            "unsupported_claims": [],
            "missed_expected_points": [],
            "strongest_points": [],
            "tool_observations": [],
            "technical_summary": "",
            "writing_summary": "",
            "follow_up_recommendations": [],
            "confidence_0_to_1": 0.0,
            "usage": {},
            "cost_estimate": {},
            "duration_sec": None,
        }
        if output_json is not None:
            write_json(output_json, result)
        return result

    if Agent is None:
        result = {
            "ok": False,
            "judge_model": model_id,
            "rubric_version": rubric_version,
            "status": "judge_error",
            "error": "pydantic_ai is not installed in the active Python environment",
            "dimension_scores": {},
            "dimension_score_labels": {},
            "overall_score_0_to_100": None,
            "raw_total_score": None,
            "raw_total_max": int((rubric.get("normalization") or {}).get("raw_total_max") or 0),
            "pass": False,
            "unsupported_claims": [],
            "missed_expected_points": [],
            "strongest_points": [],
            "tool_observations": [],
            "technical_summary": "",
            "writing_summary": "",
            "follow_up_recommendations": [],
            "confidence_0_to_1": 0.0,
            "usage": {},
            "cost_estimate": {},
            "duration_sec": None,
        }
        if output_json is not None:
            write_json(output_json, result)
        return result

    _, JudgeResponse = _build_response_models(rubric)

    try:
        t0 = time.perf_counter()
        agent = Agent(
            model_id,
            output_type=JudgeResponse,
            instructions=(
                "You are a strict technical judge for a malware-analysis benchmark. "
                "Score only what is supported by the provided bundle context and agent output. "
                "Prefer lower scores when evidence is weak or claims are overstated."
            ),
            retries=1,
        )
        prompt = _build_judge_payload(sample_name, sample_meta, task_meta, bundle_manifest, agent_result, rubric)
        run_result = agent.run_sync(prompt)
        response = run_result.output
        usage_attr = getattr(run_result, "usage", None)
        usage_snapshot = coerce_usage_snapshot(usage_attr() if callable(usage_attr) else usage_attr)
        totals = _compute_totals(response, rubric)
        result = {
            "ok": True,
            "judge_model": model_id,
            "rubric_version": rubric_version,
            "status": "completed",
            "evaluation_mode": "agent_judge",
            **response.model_dump(),
            "usage": usage_snapshot,
            "cost_estimate": estimate_usage_cost(usage_snapshot, model_id),
            "duration_sec": round(time.perf_counter() - t0, 6),
            **totals,
        }
    except Exception as exc:
        result = {
            "ok": False,
            "judge_model": model_id,
            "rubric_version": rubric_version,
            "status": "judge_error",
            "error": f"{type(exc).__name__}: {exc}",
            "dimension_scores": {},
            "dimension_score_labels": {},
            "overall_score_0_to_100": None,
            "raw_total_score": None,
            "raw_total_max": int((rubric.get("normalization") or {}).get("raw_total_max") or 0),
            "pass": False,
            "unsupported_claims": [],
            "missed_expected_points": [],
            "strongest_points": [],
            "tool_observations": [],
            "technical_summary": "",
            "writing_summary": "",
            "follow_up_recommendations": [],
            "confidence_0_to_1": 0.0,
            "usage": {},
            "cost_estimate": {},
            "duration_sec": None,
        }
    if output_json is not None:
        write_json(output_json, result)
    return result
