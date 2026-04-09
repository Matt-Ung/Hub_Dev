"""
File: config_groups.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Normalize run configuration metadata into stable configuration-group ids.

Summary:
  This module replaces the older global lineage concept with a smaller,
  experiment-friendly configuration fingerprint. It keeps equivalent runs
  grouped consistently across repetitions and experiment summaries.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from .paths import slugify


CONFIG_GROUP_SCHEMA_VERSION = "config_group_v1"


def _sorted_strings(values: Any) -> List[str]:
    items = [str(item).strip() for item in (values or []) if str(item).strip()]
    return sorted(dict.fromkeys(items))


def normalize_run_config_group_payload(run_metadata: Dict[str, Any]) -> Dict[str, Any]:
    metadata = run_metadata if isinstance(run_metadata, dict) else {}
    return {
        "schema_version": CONFIG_GROUP_SCHEMA_VERSION,
        "corpus": str(metadata.get("corpus") or "").strip(),
        "pipeline": str(metadata.get("pipeline") or "").strip(),
        "architecture": str(metadata.get("architecture") or "").strip(),
        "query_override": str(metadata.get("query_override") or "").strip(),
        "query_variant": str(metadata.get("query_variant") or "").strip(),
        "subagent_profile": str(metadata.get("subagent_profile") or "").strip(),
        "worker_persona_profile": str(metadata.get("worker_persona_profile") or "").strip(),
        "worker_role_prompt_mode": str(metadata.get("worker_role_prompt_mode") or "").strip(),
        "validator_review_level": str(metadata.get("validator_review_level") or "").strip(),
        "tool_profile": str(metadata.get("tool_profile") or "").strip(),
        "prefer_upx_unpacked": bool(metadata.get("prefer_upx_unpacked")),
        "model_profile": str(metadata.get("model_profile") or "").strip(),
        "force_model": str(metadata.get("force_model") or "").strip(),
        "judge_mode": str(metadata.get("judge_mode") or "").strip(),
        "judge_model": str(metadata.get("judge_model") or "").strip(),
        "selected_samples": _sorted_strings(metadata.get("selected_samples") or []),
        "selected_tasks": _sorted_strings(metadata.get("selected_tasks") or []),
        "selected_difficulties": _sorted_strings(metadata.get("selected_difficulties") or []),
    }


def compute_config_group_id(run_metadata: Dict[str, Any]) -> str:
    payload = normalize_run_config_group_payload(run_metadata)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:12]
    corpus = slugify(str(payload.get("corpus") or "run"))
    return f"cfg-{corpus}-{digest}"
