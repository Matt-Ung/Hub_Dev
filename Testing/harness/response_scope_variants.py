"""
File: response_scope_variants.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Load and apply named response-scope wrappers for manifest-backed tasks.

Summary:
  This module keeps report-scope prompt wrappers declarative by loading
  `Testing/config/response_scope_variants.json` and applying the selected
  wrapper to a base task query plus a small amount of sample metadata.
"""

from __future__ import annotations

from typing import Any, Dict

from .paths import CONFIG_ROOT, read_json


def load_response_scope_variants() -> Dict[str, Dict[str, str]]:
    raw = read_json(CONFIG_ROOT / "response_scope_variants.json")
    variants = raw.get("variants") if isinstance(raw.get("variants"), dict) else {}
    return {
        str(name): {
            "description": str((entry or {}).get("description") or ""),
            "prefix": str((entry or {}).get("prefix") or ""),
            "suffix": str((entry or {}).get("suffix") or ""),
        }
        for name, entry in variants.items()
        if isinstance(entry, dict)
    }


def apply_response_scope_variant(
    base_query: str,
    sample_meta: Dict[str, Any],
    variant_name: str = "default",
) -> str:
    variants = load_response_scope_variants()
    selected_name = str(variant_name or "default").strip() or "default"
    variant = variants.get(selected_name) or variants.get("default") or {"prefix": "", "suffix": ""}

    base = str(base_query or "").strip()
    if not base:
        base = "Analyze this executable and explain the most important behaviors and technical pivots."

    techniques = ", ".join(str(item).strip() for item in (sample_meta.get("primary_techniques") or []) if str(item).strip())
    target_tools = ", ".join(str(item).strip() for item in (sample_meta.get("target_tools") or []) if str(item).strip())
    difficulty = str(sample_meta.get("difficulty") or "unknown").strip()
    sample_name = str(sample_meta.get("sample") or sample_meta.get("name") or "sample").strip()

    format_kwargs = {
        "base_query": base,
        "difficulty": difficulty,
        "sample": sample_name,
        "primary_techniques": techniques,
        "target_tools": target_tools,
    }

    prefix = str(variant.get("prefix") or "").format(**format_kwargs).strip()
    suffix = str(variant.get("suffix") or "").format(**format_kwargs).strip()

    parts = [part for part in [prefix, base, suffix] if str(part).strip()]
    return " ".join(parts).strip()
