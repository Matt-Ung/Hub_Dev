"""
File: result_store.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Define the canonical on-disk layout for run and experiment result artifacts.

Summary:
  This module keeps path construction for runs, experiment child runs, case
  directories, and log locations in one place. It also preserves minimal
  compatibility for pre-refactor result trees while steering new code toward
  the canonical `cases/` and `logs/` layout.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .paths import RESULTS_ROOT, ensure_dir, slugify
from .samples import normalize_sample_task_key, sample_slug


def standalone_run_dir(run_id: str) -> Path:
    return RESULTS_ROOT / "runs" / str(run_id or "").strip()


def experiment_runs_root(experiment_root: Path) -> Path:
    return Path(experiment_root) / "runs"


def experiment_run_dir(experiment_root: Path, variant_id: str, replicate_index: int) -> Path:
    variant_folder = slugify(str(variant_id or "").strip()) or "variant"
    return experiment_runs_root(experiment_root) / variant_folder / f"r{max(1, int(replicate_index or 1)):03d}"


"""
Function: resolve_catalog_run_dir
Inputs:
  - experiment_root: experiment directory that owns the run catalog.
  - entry: one run entry from `run_catalog.json`.
Description:
  Resolve the canonical run directory for a catalog entry, preferring the
  newer experiment-relative `run_path` field and falling back to legacy
  absolute `run_dir` values when older results are being read.
Outputs:
  Returns the resolved run directory path. The path may be non-existent when
  the catalog entry is stale or incomplete.
Side Effects:
  None.
"""
def resolve_catalog_run_dir(experiment_root: Path, entry: dict) -> Path:
    run_path = str((entry or {}).get("run_path") or "").strip()
    if run_path:
        candidate = (Path(experiment_root) / run_path).resolve()
        if candidate.exists():
            return candidate
    run_dir = str((entry or {}).get("run_dir") or "").strip()
    if run_dir:
        return Path(run_dir).expanduser().resolve()
    if run_path:
        return (Path(experiment_root) / run_path).resolve()
    return Path()


def task_cases_root(run_dir: Path) -> Path:
    return Path(run_dir) / "cases"


def run_logs_root(run_dir: Path) -> Path:
    return Path(run_dir) / "logs"


def run_log_path(run_dir: Path) -> Path:
    return run_logs_root(run_dir) / "run.log"


def task_log_path(run_dir: Path, sample_name: str, task_id: str) -> Path:
    sample_folder = str(sample_name or "").strip() or "unknown_sample"
    task_folder = str(task_id or "").strip() or "default_analysis"
    return run_logs_root(run_dir) / "tasks" / sample_folder / f"{task_folder}.log"


def task_case_dir(run_dir: Path, sample_name: str, task_id: str) -> Path:
    sample_folder = str(sample_name or "").strip() or "unknown_sample"
    task_folder = str(task_id or "").strip() or "default_analysis"
    return task_cases_root(run_dir) / sample_folder / task_folder


def legacy_task_case_dir(run_dir: Path, sample_name: str, task_id: str) -> Path:
    task_folder = str(task_id or "").strip() or "default_analysis"
    return Path(run_dir) / "samples" / f"{sample_slug(sample_name)}__{task_folder}"


def resolve_task_case_dir(run_dir: Path, sample_name: str, task_id: str) -> Path:
    # New runs write under `cases/<sample>/<task>/`, but readers still need to
    # locate older `samples/<sample__task>/` trees while historical results are
    # being refreshed or compared.
    canonical = task_case_dir(run_dir, sample_name, task_id)
    if canonical.exists():
        return canonical
    legacy = legacy_task_case_dir(run_dir, sample_name, task_id)
    if legacy.exists():
        return legacy
    return canonical


def task_case_dir_from_sample_task_id(run_dir: Path, sample_task_id: str) -> Path:
    normalized = normalize_sample_task_key(sample_task_id)
    if "::" not in normalized:
        return task_cases_root(run_dir)
    sample_name, task_id = normalized.split("::", 1)
    return resolve_task_case_dir(run_dir, sample_name, task_id)


def iter_record_paths(run_dir: Path) -> Iterator[Path]:
    cases_root = task_cases_root(run_dir)
    if cases_root.exists():
        yield from sorted(cases_root.glob("*/*/record.json"))
        return
    legacy_root = Path(run_dir) / "samples"
    if legacy_root.exists():
        yield from sorted(legacy_root.glob("*/record.json"))


def ensure_task_case_dir(run_dir: Path, sample_name: str, task_id: str) -> Path:
    return ensure_dir(task_case_dir(run_dir, sample_name, task_id))
