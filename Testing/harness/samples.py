from __future__ import annotations

"""
Manifest-backed sample/task resolution for the binary testing harness.

Extension points:
- add a new executable sample by updating the relevant `sample_manifest.json`
- add focused tasks under that sample's `tasks[]` array
- keep `task_id` stable once a task is part of a sweep, because results,
  lineage grouping, and comparison tables key off `sample_task_id`
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .paths import (
    EXPERIMENTAL_BUILD_ROOT,
    EXPERIMENTAL_SOURCE_ROOT,
    PROTOTYPE_BUILD_ROOT,
    PROTOTYPE_SOURCE_ROOT,
    read_json,
)


@dataclass(frozen=True)
class CorpusConfig:
    name: str
    source_root: Path
    build_root: Path
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
        manifest_path=PROTOTYPE_SOURCE_ROOT / "sample_manifest.json",
        default_pipeline="preflight_planner_workers_reporter",
        default_architecture="balanced",
    ),
    "experimental": CorpusConfig(
        name="experimental",
        source_root=EXPERIMENTAL_SOURCE_ROOT,
        build_root=EXPERIMENTAL_BUILD_ROOT,
        manifest_path=EXPERIMENTAL_SOURCE_ROOT / "sample_manifest.json",
        default_pipeline="auto_triage",
        default_architecture="balanced",
    ),
}


def get_corpus_config(corpus_name: str) -> CorpusConfig:
    corpus_key = str(corpus_name or "").strip().lower()
    if corpus_key not in CORPORA:
        raise KeyError(f"Unknown corpus: {corpus_name}")
    return CORPORA[corpus_key]


def load_sample_manifest(corpus_name: str) -> Dict[str, Any]:
    config = get_corpus_config(corpus_name)
    raw = read_json(config.manifest_path)
    samples = raw.get("samples") if isinstance(raw.get("samples"), list) else []
    by_name: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        name = str(sample.get("sample") or sample.get("name") or "").strip()
        if name:
            by_name[name] = sample
            order.append(name)
    return {"meta": raw, "samples": by_name, "sample_order": order}


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
    for candidate in _lookup_candidate_names(binary_name):
        sample_meta = by_name.get(candidate)
        if isinstance(sample_meta, dict):
            return sample_meta
    return {}


def _default_task_from_sample_meta(sample_meta: Dict[str, Any], binary_name: str) -> Dict[str, Any]:
    default_query = str(sample_meta.get("default_query") or "").strip()
    default_name = str(sample_meta.get("sample") or binary_name or "sample").strip()
    return {
        "task_id": "default_analysis",
        "name": "Default Analysis",
        "query": default_query,
        "target_tools": list(sample_meta.get("target_tools") or []),
        "expected_evidence": list(sample_meta.get("expected_evidence") or []),
        "acceptance_targets": list(sample_meta.get("acceptance_targets") or []),
        "tags": [],
        "sample": default_name,
    }


def resolve_sample_tasks(corpus_name: str, binary_name: str, manifest: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    sample_meta = resolve_sample_metadata(corpus_name, binary_name, manifest=manifest)
    raw_tasks = sample_meta.get("tasks") if isinstance(sample_meta.get("tasks"), list) else []
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
                "query": query or str(sample_meta.get("default_query") or "").strip(),
                "target_tools": list(raw_task.get("target_tools") or sample_meta.get("target_tools") or []),
                "expected_evidence": list(raw_task.get("expected_evidence") or sample_meta.get("expected_evidence") or []),
                "acceptance_targets": list(raw_task.get("acceptance_targets") or sample_meta.get("acceptance_targets") or []),
                "tags": [str(item).strip() for item in (raw_task.get("tags") or []) if str(item).strip()],
                "sample": str(sample_meta.get("sample") or binary_name or "").strip(),
            }
        )
    if tasks:
        return tasks
    return [_default_task_from_sample_meta(sample_meta, binary_name)]


def sample_task_key(sample_name: str, task_id: str) -> str:
    stem = Path(sample_name).stem
    task = str(task_id or "default_analysis").strip() or "default_analysis"
    return f"{stem}::{task}"


def build_evaluation_tasks(
    corpus_name: str,
    sample_paths: List[Path],
    *,
    manifest: Optional[Dict[str, Any]] = None,
    selected_task_ids: Optional[Iterable[str]] = None,
    selected_difficulties: Optional[Iterable[str]] = None,
) -> List[EvaluationTask]:
    manifest_data = manifest or load_sample_manifest(corpus_name)
    selected = {str(item).strip() for item in (selected_task_ids or []) if str(item).strip()}
    difficulty_filter = {str(item).strip().lower() for item in (selected_difficulties or []) if str(item).strip()}
    tasks: List[EvaluationTask] = []
    for sample_path in sample_paths:
        sample_meta = resolve_sample_metadata(corpus_name, sample_path.name, manifest=manifest_data)
        sample_difficulty = str(sample_meta.get("difficulty") or "unknown").strip() or "unknown"
        if difficulty_filter and sample_difficulty.lower() not in difficulty_filter:
            continue
        for task_meta in resolve_sample_tasks(corpus_name, sample_path.name, manifest=manifest_data):
            task_id = str(task_meta.get("task_id") or "").strip()
            if selected and task_id not in selected:
                continue
            tasks.append(
                EvaluationTask(
                    sample_name=sample_path.name,
                    sample_path=sample_path,
                    task_id=task_id,
                    task_name=str(task_meta.get("name") or task_id).strip() or task_id,
                    query=str(task_meta.get("query") or "").strip(),
                    difficulty=sample_difficulty,
                    primary_techniques=[str(item).strip() for item in (sample_meta.get("primary_techniques") or []) if str(item).strip()],
                    target_tools=[str(item).strip() for item in (task_meta.get("target_tools") or []) if str(item).strip()],
                    expected_evidence=[str(item).strip() for item in (task_meta.get("expected_evidence") or []) if str(item).strip()],
                    acceptance_targets=[str(item).strip() for item in (task_meta.get("acceptance_targets") or []) if str(item).strip()],
                    tags=[str(item).strip() for item in (task_meta.get("tags") or []) if str(item).strip()],
                )
            )
    return tasks


def list_sample_binaries(
    corpus_name: str,
    selected: Optional[Iterable[str]] = None,
    *,
    difficulty_filters: Optional[Iterable[str]] = None,
    manifest: Optional[Dict[str, Any]] = None,
) -> List[Path]:
    config = get_corpus_config(corpus_name)
    requested = {str(item).strip() for item in (selected or []) if str(item).strip()}
    binaries = {path.name: path for path in config.build_root.glob("*.exe") if path.is_file()}
    manifest_data = manifest or load_sample_manifest(corpus_name)
    ordered_names = list(manifest_data.get("sample_order") or [])
    difficulty_filter = {str(item).strip().lower() for item in (difficulty_filters or []) if str(item).strip()}

    def _matches(name: str) -> bool:
        if not difficulty_filter:
            return True
        sample_meta = resolve_sample_metadata(corpus_name, name, manifest=manifest_data)
        difficulty = str(sample_meta.get("difficulty") or "unknown").strip().lower()
        return difficulty in difficulty_filter

    if requested:
        selected_paths = [binaries[name] for name in ordered_names if name in requested and name in binaries and _matches(name)]
        selected_paths.extend(
            binaries[name]
            for name in sorted(requested)
            if name not in {path.name for path in selected_paths} and name in binaries and _matches(name)
        )
        return selected_paths
    manifest_paths = [binaries[name] for name in ordered_names if name in binaries and _matches(name)]
    return manifest_paths


def default_query_for_sample(corpus_name: str, binary_name: str, manifest: Optional[Dict[str, Any]] = None) -> str:
    sample_meta = resolve_sample_metadata(corpus_name, binary_name, manifest=manifest)
    return str(sample_meta.get("default_query") or "").strip()
