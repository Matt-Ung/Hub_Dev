"""
File: samples.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Resolve corpus manifests into the sample and task objects consumed by the
  testing harness.

Summary:
  This module is the manifest-backed source of truth for corpus metadata,
  task definitions, and sample discovery. It converts corpus manifests plus
  built binaries into stable evaluation-task objects used by single runs,
  sweeps, bundle preparation, and results reporting.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .paths import (
    EXPERIMENTAL_BUILD_ROOT,
    EXPERIMENTAL_SOURCE_ROOT,
    FINAL_ROUND_BUILD_ROOT,
    FINAL_ROUND_SOURCE_ROOT,
    PROTOTYPE_BUILD_ROOT,
    PROTOTYPE_SOURCE_ROOT,
    read_json,
)


@dataclass(frozen=True)
class CorpusConfig:
    name: str
    source_root: Path
    build_root: Path
    binary_root: Path
    manifest_path: Path
    default_pipeline: str
    default_architecture: str


@dataclass(frozen=True)
class EvaluationTask:
    sample_name: str
    sample_path: Path
    task_id: str
    task_name: str
    query: str
    difficulty: str
    primary_techniques: List[str]
    target_tools: List[str]
    expected_evidence: List[str]
    acceptance_targets: List[str]
    tags: List[str]


CORPORA: Dict[str, CorpusConfig] = {
    "prototype": CorpusConfig(
        name="prototype",
        source_root=PROTOTYPE_SOURCE_ROOT,
        build_root=PROTOTYPE_BUILD_ROOT,
        binary_root=PROTOTYPE_BUILD_ROOT,
        manifest_path=PROTOTYPE_SOURCE_ROOT / "sample_manifest.json",
        default_pipeline="preflight_planner_workers_reporter",
        default_architecture="balanced",
    ),
    "experimental": CorpusConfig(
        name="experimental",
        source_root=EXPERIMENTAL_SOURCE_ROOT,
        build_root=EXPERIMENTAL_BUILD_ROOT,
        binary_root=EXPERIMENTAL_BUILD_ROOT,
        manifest_path=EXPERIMENTAL_SOURCE_ROOT / "sample_manifest.json",
        default_pipeline="auto_triage",
        default_architecture="balanced",
    ),
    "final_round": CorpusConfig(
        name="final_round",
        source_root=FINAL_ROUND_SOURCE_ROOT,
        build_root=FINAL_ROUND_BUILD_ROOT,
        binary_root=FINAL_ROUND_BUILD_ROOT / "output",
        manifest_path=FINAL_ROUND_SOURCE_ROOT / "sample_manifest.json",
        default_pipeline="auto_triage",
        default_architecture="balanced",
    ),
}


def get_corpus_config(corpus_name: str) -> CorpusConfig:
    corpus_key = str(corpus_name or "").strip().lower()
    if corpus_key not in CORPORA:
        raise KeyError(f"Unknown corpus: {corpus_name}")
    return CORPORA[corpus_key]


"""
Function: load_sample_manifest
Inputs:
  - corpus_name: logical corpus identifier such as `prototype`,
    `experimental`, or `final_round`.
Description:
  Load one corpus manifest and normalize it into a fast lookup structure keyed
  by runtime sample name plus any declared `sample_id`.
Outputs:
  Returns a dictionary containing the raw manifest, a normalized `samples`
  lookup, and manifest-defined sample order.
Side Effects:
  Reads the corpus manifest JSON from disk.
"""
def load_sample_manifest(corpus_name: str) -> Dict[str, Any]:
    config = get_corpus_config(corpus_name)
    raw = read_json(config.manifest_path)
    samples = raw.get("samples") if isinstance(raw.get("samples"), list) else []
    by_name: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        name = str(sample.get("sample") or sample.get("name") or sample.get("sample_id") or "").strip()
        if name:
            by_name[name] = sample
            sample_id = str(sample.get("sample_id") or "").strip()
            if sample_id:
                by_name.setdefault(sample_id, sample)
            order.append(name)
    return {"meta": raw, "samples": by_name, "sample_order": order}


def model_visible_sample_metadata(sample_meta: Dict[str, Any]) -> Dict[str, Any]:
    raw = dict(sample_meta or {})
    visible = raw.get("model_visible") if isinstance(raw.get("model_visible"), dict) else {}
    normalized: Dict[str, Any] = dict(visible or {})
    for key in (
        "sample",
        "name",
        "sample_id",
        "difficulty",
        "primary_techniques",
        "target_tools",
        "expected_evidence",
        "acceptance_targets",
        "default_query",
        "tasks",
    ):
        if key not in normalized and raw.get(key) is not None:
            normalized[key] = raw.get(key)
    if "sample" not in normalized and raw.get("sample"):
        normalized["sample"] = raw.get("sample")
    return normalized


def sample_slug(sample_name_or_path: str | Path) -> str:
    path = Path(sample_name_or_path)
    return path.stem


def _lookup_candidate_names(binary_name: str) -> List[str]:
    candidates = [binary_name]
    if binary_name.endswith("_gcc.exe"):
        candidates.append(binary_name.replace("_gcc.exe", ".exe"))
    return candidates


def resolve_sample_metadata(corpus_name: str, binary_name: str, manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    manifest_data = manifest or load_sample_manifest(corpus_name)
    by_name = manifest_data.get("samples") if isinstance(manifest_data.get("samples"), dict) else {}
    raw_value = str(binary_name or "").strip()
    candidates = _lookup_candidate_names(Path(raw_value).name) if raw_value else []
    if raw_value and raw_value not in candidates:
        candidates.append(raw_value)
    for candidate in candidates:
        sample_meta = by_name.get(candidate)
        if isinstance(sample_meta, dict):
            return sample_meta
    return {}


def _default_task_from_sample_meta(sample_meta: Dict[str, Any], binary_name: str) -> Dict[str, Any]:
    visible_meta = model_visible_sample_metadata(sample_meta)
    default_query = str(visible_meta.get("default_query") or "").strip()
    default_name = str(visible_meta.get("sample") or binary_name or "sample").strip()
    return {
        "task_id": "default_analysis",
        "name": "Default Analysis",
        "query": default_query,
        "target_tools": list(visible_meta.get("target_tools") or []),
        "expected_evidence": list(visible_meta.get("expected_evidence") or []),
        "acceptance_targets": list(visible_meta.get("acceptance_targets") or []),
        "tags": [],
        "sample": default_name,
    }


def resolve_sample_tasks(corpus_name: str, binary_name: str, manifest: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    sample_meta = resolve_sample_metadata(corpus_name, binary_name, manifest=manifest)
    visible_meta = model_visible_sample_metadata(sample_meta)
    raw_tasks = visible_meta.get("tasks") if isinstance(visible_meta.get("tasks"), list) else []
    tasks: List[Dict[str, Any]] = []
    for raw_task in raw_tasks:
        if not isinstance(raw_task, dict):
            continue
        task_id = str(raw_task.get("task_id") or raw_task.get("id") or "").strip()
        query = str(raw_task.get("query") or raw_task.get("prompt") or "").strip()
        if not task_id:
            continue
        tasks.append(
            {
                "task_id": task_id,
                "name": str(raw_task.get("name") or task_id).strip(),
                "query": query or str(visible_meta.get("default_query") or "").strip(),
                "target_tools": list(raw_task.get("target_tools") or visible_meta.get("target_tools") or []),
                "expected_evidence": list(raw_task.get("expected_evidence") or visible_meta.get("expected_evidence") or []),
                "acceptance_targets": list(raw_task.get("acceptance_targets") or visible_meta.get("acceptance_targets") or []),
                "tags": [str(item).strip() for item in (raw_task.get("tags") or []) if str(item).strip()],
                "sample": str(visible_meta.get("sample") or binary_name or "").strip(),
            }
        )
    if tasks:
        return tasks
    return [_default_task_from_sample_meta(sample_meta, binary_name)]


def sample_task_key(sample_name: str, task_id: str) -> str:
    stem = Path(sample_name).stem
    task = str(task_id or "default_analysis").strip() or "default_analysis"
    return f"{stem}::{task}"


def normalize_sample_task_key(value: str) -> str:
    text = str(value or "").strip()
    if not text or "::" not in text:
        return text
    sample_name, task_id = text.split("::", 1)
    return sample_task_key(sample_name, task_id)


"""
Function: build_evaluation_tasks
Inputs:
  - corpus_name: logical corpus identifier.
  - sample_paths: concrete built binary paths that should be evaluated.
  - manifest / selected_task_ids / selected_task_keys / selected_difficulties:
    optional filters and preloaded manifest data.
Description:
  Expand manifest-backed task definitions into normalized `EvaluationTask`
  records for the concrete sample binaries currently in scope.
Outputs:
  Returns a list of `EvaluationTask` objects in manifest/sample order.
Side Effects:
  Reads manifest metadata when a preloaded manifest is not provided.
"""
def build_evaluation_tasks(
    corpus_name: str,
    sample_paths: List[Path],
    *,
    manifest: Optional[Dict[str, Any]] = None,
    selected_task_ids: Optional[Iterable[str]] = None,
    selected_task_keys: Optional[Iterable[str]] = None,
    selected_difficulties: Optional[Iterable[str]] = None,
) -> List[EvaluationTask]:
    manifest_data = manifest or load_sample_manifest(corpus_name)
    selected = {str(item).strip() for item in (selected_task_ids or []) if str(item).strip()}
    selected_keys = {normalize_sample_task_key(str(item)) for item in (selected_task_keys or []) if str(item).strip()}
    difficulty_filter = {str(item).strip().lower() for item in (selected_difficulties or []) if str(item).strip()}
    tasks: List[EvaluationTask] = []
    for sample_path in sample_paths:
        sample_meta = resolve_sample_metadata(corpus_name, sample_path.name, manifest=manifest_data)
        visible_meta = model_visible_sample_metadata(sample_meta)
        sample_difficulty = str(visible_meta.get("difficulty") or "unknown").strip() or "unknown"
        if difficulty_filter and sample_difficulty.lower() not in difficulty_filter:
            continue
        for task_meta in resolve_sample_tasks(corpus_name, sample_path.name, manifest=manifest_data):
            task_id = str(task_meta.get("task_id") or "").strip()
            task_key = sample_task_key(sample_path.name, task_id)
            if selected and task_id not in selected:
                continue
            if selected_keys and task_key not in selected_keys:
                continue
            tasks.append(
                EvaluationTask(
                    sample_name=sample_path.name,
                    sample_path=sample_path,
                    task_id=task_id,
                    task_name=str(task_meta.get("name") or task_id).strip() or task_id,
                    query=str(task_meta.get("query") or "").strip(),
                    difficulty=sample_difficulty,
                    primary_techniques=[str(item).strip() for item in (visible_meta.get("primary_techniques") or []) if str(item).strip()],
                    target_tools=[str(item).strip() for item in (task_meta.get("target_tools") or []) if str(item).strip()],
                    expected_evidence=[str(item).strip() for item in (task_meta.get("expected_evidence") or []) if str(item).strip()],
                    acceptance_targets=[str(item).strip() for item in (task_meta.get("acceptance_targets") or []) if str(item).strip()],
                    tags=[str(item).strip() for item in (task_meta.get("tags") or []) if str(item).strip()],
                )
            )
    return tasks


"""
Function: list_sample_binaries
Inputs:
  - corpus_name: logical corpus identifier.
  - selected: optional runtime sample names or manifest sample ids.
  - difficulty_filters / manifest: optional selection helpers.
Description:
  Discover built `.exe` files for one corpus, preserve manifest order, and
  apply explicit sample or difficulty filters without guessing extra files.
Outputs:
  Returns a list of binary paths under the corpus build root.
Side Effects:
  Reads the corpus manifest when one is not supplied.
"""
def list_sample_binaries(
    corpus_name: str,
    selected: Optional[Iterable[str]] = None,
    *,
    difficulty_filters: Optional[Iterable[str]] = None,
    manifest: Optional[Dict[str, Any]] = None,
) -> List[Path]:
    config = get_corpus_config(corpus_name)
    requested = {str(item).strip() for item in (selected or []) if str(item).strip()}
    binaries = {path.name: path for path in config.binary_root.glob("*.exe") if path.is_file()}
    manifest_data = manifest or load_sample_manifest(corpus_name)
    ordered_names = list(manifest_data.get("sample_order") or [])
    sample_lookup = manifest_data.get("samples") if isinstance(manifest_data.get("samples"), dict) else {}
    difficulty_filter = {str(item).strip().lower() for item in (difficulty_filters or []) if str(item).strip()}

    def _matches(name: str) -> bool:
        if not difficulty_filter:
            return True
        sample_meta = resolve_sample_metadata(corpus_name, name, manifest=manifest_data)
        difficulty = str(model_visible_sample_metadata(sample_meta).get("difficulty") or "unknown").strip().lower()
        return difficulty in difficulty_filter

    if requested:
        requested_runtime_names = {
            str((sample_lookup.get(name) or {}).get("sample") or name).strip()
            if isinstance(sample_lookup.get(name), dict)
            else name
            for name in requested
        }
        selected_paths = [binaries[name] for name in ordered_names if name in requested_runtime_names and name in binaries and _matches(name)]
        selected_paths.extend(
            binaries[name]
            for name in sorted(requested_runtime_names)
            if name not in {path.name for path in selected_paths} and name in binaries and _matches(name)
        )
        return selected_paths
    manifest_paths = [binaries[name] for name in ordered_names if name in binaries and _matches(name)]
    return manifest_paths


def default_query_for_sample(corpus_name: str, binary_name: str, manifest: Optional[Dict[str, Any]] = None) -> str:
    sample_meta = resolve_sample_metadata(corpus_name, binary_name, manifest=manifest)
    return str(model_visible_sample_metadata(sample_meta).get("default_query") or "").strip()


def build_planned_evaluation_tasks(
    corpus_name: str,
    *,
    manifest: Optional[Dict[str, Any]] = None,
    selected_samples: Optional[Iterable[str]] = None,
    selected_task_ids: Optional[Iterable[str]] = None,
    selected_task_keys: Optional[Iterable[str]] = None,
    selected_difficulties: Optional[Iterable[str]] = None,
) -> List[EvaluationTask]:
    manifest_data = manifest or load_sample_manifest(corpus_name)
    requested = {str(item).strip() for item in (selected_samples or []) if str(item).strip()}
    sample_order = list(manifest_data.get("sample_order") or [])
    synthetic_paths: List[Path] = []
    for sample_name in sample_order:
        sample_meta = resolve_sample_metadata(corpus_name, sample_name, manifest=manifest_data)
        runtime_name = str(sample_meta.get("sample") or sample_name).strip() or sample_name
        sample_id = str(sample_meta.get("sample_id") or "").strip()
        if requested and runtime_name not in requested and sample_name not in requested and sample_id not in requested:
            continue
        synthetic_paths.append(get_corpus_config(corpus_name).binary_root / runtime_name)
    return build_evaluation_tasks(
        corpus_name,
        synthetic_paths,
        manifest=manifest_data,
        selected_task_ids=selected_task_ids,
        selected_task_keys=selected_task_keys,
        selected_difficulties=selected_difficulties,
    )
