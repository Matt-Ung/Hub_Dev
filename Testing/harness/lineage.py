from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .paths import RESULTS_ROOT, ensure_dir, read_json, slugify, write_json
from .reporting import aggregate_records


LINEAGE_SCHEMA_VERSION = "config_lineage_v1"
LINEAGES_ROOT = RESULTS_ROOT / "lineages"


def _sorted_strings(values: Any) -> List[str]:
    items = [str(item).strip() for item in (values or []) if str(item).strip()]
    return sorted(dict.fromkeys(items))


def normalize_run_lineage_payload(run_metadata: Dict[str, Any]) -> Dict[str, Any]:
    metadata = run_metadata if isinstance(run_metadata, dict) else {}
    return {
        "schema_version": LINEAGE_SCHEMA_VERSION,
        "corpus": str(metadata.get("corpus") or "").strip(),
        "pipeline": str(metadata.get("pipeline") or "").strip(),
        "architecture": str(metadata.get("architecture") or "").strip(),
        "query_override": str(metadata.get("query_override") or "").strip(),
        "query_variant": str(metadata.get("query_variant") or "").strip(),
        "subagent_profile": str(metadata.get("subagent_profile") or "").strip(),
        "worker_persona_profile": str(metadata.get("worker_persona_profile") or "").strip(),
        "validator_review_level": str(metadata.get("validator_review_level") or "").strip(),
        "tool_profile": str(metadata.get("tool_profile") or "").strip(),
        "model_profile": str(metadata.get("model_profile") or "").strip(),
        "force_model": str(metadata.get("force_model") or "").strip(),
        "judge_mode": str(metadata.get("judge_mode") or "").strip(),
        "judge_model": str(metadata.get("judge_model") or "").strip(),
        "selected_samples": _sorted_strings(metadata.get("selected_samples") or []),
        "selected_tasks": _sorted_strings(metadata.get("selected_tasks") or []),
        "selected_difficulties": _sorted_strings(metadata.get("selected_difficulties") or []),
    }


def compute_lineage_id(run_metadata: Dict[str, Any]) -> str:
    payload = normalize_run_lineage_payload(run_metadata)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:12]
    corpus = slugify(str(payload.get("corpus") or "run"))
    return f"cfg-{corpus}-{digest}"


def lineage_paths(lineage_id: str) -> Dict[str, Path]:
    root = ensure_dir(LINEAGES_ROOT)
    return {
        "root": root,
        "index": root / "index.json",
        "lineage": root / f"{lineage_id}.json",
    }


def _lineage_run_summary(run_dir: Path, run_manifest: Dict[str, Any], aggregate: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "run_id": str(run_manifest.get("run_id") or ""),
        "run_dir": str(run_dir.resolve()),
        "experiment_id": str(run_manifest.get("experiment_id") or "").strip(),
        "variant_name": str(run_manifest.get("variant_name") or "").strip(),
        "changed_variable": str(run_manifest.get("changed_variable") or "").strip(),
        "comparison_baseline_id": str(run_manifest.get("comparison_baseline_id") or "").strip(),
        "comparison_baseline_label": str(run_manifest.get("comparison_baseline_label") or "").strip(),
        "replicate_index": int(run_manifest.get("replicate_index") or 1),
        "replicate_count": int(run_manifest.get("replicate_count") or 1),
        "overall_score_mean": aggregate.get("overall_score_mean"),
        "task_success_rate": aggregate.get("task_success_rate"),
        "judge_pass_rate": aggregate.get("judge_pass_rate"),
        "mean_relative_cost_index": aggregate.get("mean_relative_cost_index"),
        "mean_total_duration_sec": aggregate.get("mean_total_duration_sec"),
        "mean_task_wall_clock_duration_sec": aggregate.get("mean_task_wall_clock_duration_sec"),
        "record_count": len(aggregate.get("records") or []),
    }


def refresh_lineage_index_for_run(
    *,
    run_dir: Path,
    run_manifest: Dict[str, Any],
    aggregate: Dict[str, Any],
) -> Dict[str, Any]:
    lineage_id = str(run_manifest.get("config_lineage_id") or "").strip()
    if not lineage_id:
        lineage_id = compute_lineage_id(run_manifest)
        run_manifest["config_lineage_id"] = lineage_id
        run_manifest["config_lineage_key"] = normalize_run_lineage_payload(run_manifest)

    paths = lineage_paths(lineage_id)
    lineage_path = paths["lineage"]
    index_path = paths["index"]
    payload = read_json(lineage_path) if lineage_path.exists() else {}

    runs_by_id: Dict[str, Dict[str, Any]] = {}
    for entry in payload.get("runs") or []:
        if isinstance(entry, dict) and str(entry.get("run_id") or "").strip():
            runs_by_id[str(entry.get("run_id") or "").strip()] = entry

    runs_by_id[str(run_manifest.get("run_id") or "").strip()] = _lineage_run_summary(run_dir, run_manifest, aggregate)
    ordered_runs = sorted(
        runs_by_id.values(),
        key=lambda row: (
            str(row.get("experiment_id") or ""),
            int(row.get("replicate_index") or 0),
            str(row.get("run_id") or ""),
        ),
    )

    records: List[Dict[str, Any]] = []
    experiments: List[str] = []
    for row in ordered_runs:
        experiments.append(str(row.get("experiment_id") or "").strip())
        existing_run_dir = Path(str(row.get("run_dir") or "")).resolve()
        aggregate_path = existing_run_dir / "aggregate.json"
        if not aggregate_path.exists():
            continue
        try:
            run_aggregate = read_json(aggregate_path)
        except Exception:
            continue
        records.extend(list(run_aggregate.get("records") or []))

    lineage_metadata = dict(normalize_run_lineage_payload(run_manifest))
    lineage_metadata["config_lineage_id"] = lineage_id
    lineage_metadata["lineage_run_count"] = len(ordered_runs)
    lineage_metadata["experiments"] = sorted({item for item in experiments if item})

    lineage_aggregate = aggregate_records(lineage_metadata, records)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lineage_payload = {
        "schema_version": LINEAGE_SCHEMA_VERSION,
        "config_lineage_id": lineage_id,
        "config_lineage_key": normalize_run_lineage_payload(run_manifest),
        "updated_at_utc": timestamp,
        "run_count": len(ordered_runs),
        "records_count": len(records),
        "experiments": lineage_metadata["experiments"],
        "runs": ordered_runs,
        "aggregate": lineage_aggregate,
    }
    write_json(lineage_path, lineage_payload)

    index_payload = read_json(index_path) if index_path.exists() else {"schema_version": LINEAGE_SCHEMA_VERSION, "lineages": []}
    lineages = index_payload.get("lineages") if isinstance(index_payload.get("lineages"), list) else []
    retained = [
        row for row in lineages
        if isinstance(row, dict) and str(row.get("config_lineage_id") or "").strip() != lineage_id
    ]
    retained.append(
        {
            "config_lineage_id": lineage_id,
            "path": str(lineage_path.resolve()),
            "updated_at_utc": timestamp,
            "run_count": len(ordered_runs),
            "records_count": len(records),
            "overall_score_mean": lineage_aggregate.get("overall_score_mean"),
            "task_success_rate": lineage_aggregate.get("task_success_rate"),
            "mean_relative_cost_index": lineage_aggregate.get("mean_relative_cost_index"),
            "mean_total_duration_sec": lineage_aggregate.get("mean_total_duration_sec"),
            "mean_task_wall_clock_duration_sec": lineage_aggregate.get("mean_task_wall_clock_duration_sec"),
            "corpus": lineage_payload["config_lineage_key"].get("corpus"),
            "pipeline": lineage_payload["config_lineage_key"].get("pipeline"),
            "architecture": lineage_payload["config_lineage_key"].get("architecture"),
            "query_variant": lineage_payload["config_lineage_key"].get("query_variant"),
            "worker_persona_profile": lineage_payload["config_lineage_key"].get("worker_persona_profile"),
            "selected_samples": lineage_payload["config_lineage_key"].get("selected_samples"),
            "selected_tasks": lineage_payload["config_lineage_key"].get("selected_tasks"),
            "selected_difficulties": lineage_payload["config_lineage_key"].get("selected_difficulties"),
        }
    )
    index_payload = {
        "schema_version": LINEAGE_SCHEMA_VERSION,
        "lineages": sorted(retained, key=lambda row: (str(row.get("corpus") or ""), str(row.get("config_lineage_id") or ""))),
    }
    write_json(index_path, index_payload)
    return lineage_payload


def load_lineage_payload(lineage_id: str) -> Dict[str, Any]:
    path = lineage_paths(lineage_id)["lineage"]
    if not path.exists():
        return {}
    return read_json(path)
