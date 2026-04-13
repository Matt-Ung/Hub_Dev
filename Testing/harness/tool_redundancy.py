"""
File: tool_redundancy.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Normalize tool-call logs and quantify redundant tool usage within one run.

Summary:
  This module converts parsed tool-log transcript entries into stable
  tool-call events, derives semantic targets for common analysis tools, and
  computes exact and near-duplicate usage metrics that later reporting layers
  can use to highlight wasted effort.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .artifacts import tool_name_to_server_guess


_ADDRESS_KEYS = {
    "address",
    "function_address",
    "entry",
    "entry_point",
    "ea",
    "offset",
    "start",
    "start_address",
    "target_address",
    "va",
    "rva",
}
_PATH_KEYS = {
    "binary_path",
    "directory",
    "executable_path",
    "file_path",
    "output_path",
    "path",
    "program_path",
    "project_path",
    "rule_path",
    "rules_path",
    "sample_path",
}
_NAME_KEYS = {
    "function",
    "function_name",
    "name",
    "symbol",
    "symbol_name",
}
_HASH_KEYS = {
    "api_hash",
    "hash",
    "hash_value",
    "md5",
    "sha1",
    "sha256",
    "value",
}
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{4,}$")


def _collapse_ws(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def _normalize_pathlike(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    if re.match(r"^[A-Za-z]:/", text):
        drive = text[0].lower()
        text = f"{drive}:{text[2:]}"
    while "//" in text:
        text = text.replace("//", "/")
    return text.rstrip("/") if text != "/" else text


def _normalize_address(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value).strip()
    if not text:
        return ""
    if not _HEX_RE.match(text):
        return text.lower()
    text = text[2:] if text.lower().startswith("0x") else text
    return f"0x{text.lower()}"


def _looks_like_address(value: Any) -> bool:
    if isinstance(value, int):
        return True
    text = str(value or "").strip()
    return bool(text and _HEX_RE.match(text))


def _normalize_value(value: Any, *, key: str = "") -> Any:
    lowered_key = str(key or "").strip().lower()
    if isinstance(value, dict):
        return {
            str(child_key): _normalize_value(child_value, key=str(child_key))
            for child_key, child_value in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, list):
        return [_normalize_value(item, key=key) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value

    text = _collapse_ws(value)
    if not text:
        return ""
    if lowered_key in _PATH_KEYS or any(marker in lowered_key for marker in ("path", "file", "directory")):
        return _normalize_pathlike(text)
    if lowered_key in _ADDRESS_KEYS or "address" in lowered_key or "entry" == lowered_key:
        return _normalize_address(text)
    if lowered_key in _HASH_KEYS or lowered_key.endswith("_hash"):
        return text.lower()
    if _looks_like_address(text):
        return _normalize_address(text)
    return text


def _tool_family(tool_name: str) -> str:
    name = str(tool_name or "").strip().lower()
    if name in {"callstrings", "list_strings"}:
        return "strings_scan"
    if name in {"runfloss"}:
        return "floss_scan"
    if name in {"runcapa"}:
        return "capa_scan"
    if name in {"binwalkscan"}:
        return "binwalk_scan"
    if name in {"yarascan"}:
        return "yara_scan"
    if name in {"decompile_function", "decompile_function_by_address"}:
        return "ghidra_decompile_function"
    if name in {"get_function_xrefs", "get_function_by_name", "get_function_by_address"}:
        return "ghidra_function_lookup"
    if name in {"get_xrefs_to", "get_xrefs_to_address"}:
        return "ghidra_xref_lookup"
    if name in {"get_program_info"}:
        return "ghidra_program_info"
    if name in {"list_imports"}:
        return "ghidra_imports"
    if name in {"resolve_hash_in_hashdb_to_plain"}:
        return "hash_lookup"
    if name in {"list_data_items"}:
        return "ghidra_data_listing"
    if name in {"binarypatchinspect"}:
        return "binary_patch_inspect"
    if name in {"upxunpack"}:
        return "upx_unpack"
    if name in {"read_todos"}:
        return "todo_read"
    if name in {"task"}:
        return "subagent_task"
    if name in {"ls"}:
        return "filesystem_list"
    return name or "unknown_tool"


def _first_present(args: Dict[str, Any], keys: List[str]) -> Any:
    for key in keys:
        value = args.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _description_fingerprint(value: Any) -> str:
    text = _collapse_ws(value)
    if not text:
        return ""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def _semantic_target(tool_family: str, normalized_args: Dict[str, Any]) -> Tuple[str, str, str]:
    address = _first_present(normalized_args, sorted(_ADDRESS_KEYS))
    name = _first_present(normalized_args, sorted(_NAME_KEYS))
    path = _first_present(normalized_args, sorted(_PATH_KEYS))
    hash_value = _first_present(normalized_args, sorted(_HASH_KEYS))

    if tool_family in {"ghidra_decompile_function", "ghidra_function_lookup", "ghidra_xref_lookup"}:
        target = str(address or name or "<unknown-function>")
        return ("function", target, f"{tool_family}|function|{target}")
    if tool_family in {"ghidra_program_info", "ghidra_imports"}:
        target = str(path or "active_program")
        return ("program", target, f"{tool_family}|program|{target}")
    if tool_family in {"strings_scan", "floss_scan", "capa_scan", "binwalk_scan", "binary_patch_inspect", "upx_unpack"}:
        target = str(path or "active_sample")
        return ("file", target, f"{tool_family}|file|{target}")
    if tool_family == "todo_read":
        target = str(path or _description_fingerprint(normalized_args.get("task")) or "todo_state")
        return ("state", target, f"{tool_family}|state|{target}")
    if tool_family == "yara_scan":
        target = str(path or "active_sample")
        rule_ref = str(
            _first_present(
                normalized_args,
                ["rule_path", "rules_path", "rules_sha256", "rule_sha256", "rule_name"],
            )
            or ""
        )
        semantic_id = f"{tool_family}|scan|{target}"
        if rule_ref:
            semantic_id = f"{semantic_id}|rules={rule_ref}"
        return ("scan", target, semantic_id)
    if tool_family == "hash_lookup":
        target = str(hash_value or "<unknown-hash>")
        return ("hash", target, f"{tool_family}|hash|{target}")
    if tool_family == "ghidra_data_listing":
        target = str(address or path or "program_data_items")
        return ("data_region", target, f"{tool_family}|data_region|{target}")
    if tool_family == "filesystem_list":
        target = str(path or ".")
        return ("path", target, f"{tool_family}|path|{target}")
    if tool_family == "subagent_task":
        subagent_type = str(normalized_args.get("subagent_type") or "generic")
        desc_hash = _description_fingerprint(normalized_args.get("description"))
        target = f"{subagent_type}:{desc_hash or 'no_desc'}"
        return ("subagent_request", target, f"{tool_family}|subagent_request|{target}")
    if address:
        target = str(address)
        return ("address", target, f"{tool_family}|address|{target}")
    if path:
        target = str(path)
        return ("path", target, f"{tool_family}|path|{target}")
    if name:
        target = str(name)
        return ("name", target, f"{tool_family}|name|{target}")
    if hash_value:
        target = str(hash_value)
        return ("hash", target, f"{tool_family}|hash|{target}")
    exact_fingerprint = hashlib.sha1(
        json.dumps(normalized_args, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()[:12]
    return ("call", exact_fingerprint, f"{tool_family}|call|{exact_fingerprint}")


def _exact_key(tool_family: str, normalized_args: Dict[str, Any]) -> str:
    return json.dumps(
        {"tool_family": tool_family, "normalized_args": normalized_args},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )


"""
Function: normalize_tool_call_entries
Inputs:
  - entries: parsed tool-log transcript entries from `parse_tool_log_sections`.
Description:
  Convert raw tool-call transcript entries into structured call records with
  normalized arguments, semantic target identifiers, and stable grouping keys
  suitable for post-run redundancy analysis.
Outputs:
  Returns a list of normalized tool-call dictionaries ordered as they appeared
  during the run.
Side Effects:
  None.
"""
def normalize_tool_call_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized_calls: List[Dict[str, Any]] = []
    exact_seen: Counter[str] = Counter()
    semantic_seen: Counter[str] = Counter()
    for index, entry in enumerate(entries):
        if str(entry.get("kind") or "") != "tool_call":
            continue
        tool_name = str(entry.get("tool_name") or "").strip()
        if not tool_name:
            continue
        normalized_args = _normalize_value(entry.get("args") or {}, key="args")
        if not isinstance(normalized_args, dict):
            normalized_args = {"value": normalized_args}
        tool_family = _tool_family(tool_name)
        target_kind, target_label, semantic_key = _semantic_target(tool_family, normalized_args)
        exact_key = _exact_key(tool_family, normalized_args)
        exact_repeat_index = int(exact_seen.get(exact_key, 0))
        semantic_repeat_index = int(semantic_seen.get(semantic_key, 0))
        exact_seen[exact_key] += 1
        semantic_seen[semantic_key] += 1
        normalized_calls.append(
            {
                "sequence_index": len(normalized_calls),
                "entry_index": index,
                "stage": str(entry.get("stage") or ""),
                "source": str(entry.get("source") or ""),
                "event_at": str(entry.get("event_at") or ""),
                "server_id": str(entry.get("server_id") or "").strip() or tool_name_to_server_guess(tool_name),
                "tool_name": tool_name,
                "tool_family": tool_family,
                "tool_call_id": str(entry.get("tool_call_id") or ""),
                "normalized_args": normalized_args,
                "exact_key": exact_key,
                "semantic_key": semantic_key,
                "semantic_target_kind": target_kind,
                "semantic_target_label": target_label,
                "exact_repeat_index": exact_repeat_index,
                "semantic_repeat_index": semantic_repeat_index,
                "is_exact_repeat": exact_repeat_index > 0,
                "is_semantic_repeat": semantic_repeat_index > 0,
            }
        )
    return normalized_calls


def _cache_event_summary(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "tool_cache_hit": 0,
        "tool_cache_store": 0,
        "tool_cache_wait": 0,
        "tool_cache_skip": 0,
    }
    for entry in entries:
        kind = str(entry.get("kind") or "")
        if kind in counts:
            counts[kind] += 1
    return counts


"""
Function: summarize_tool_call_redundancy
Inputs:
  - entries: parsed tool-log transcript entries for one task run.
  - normalized_calls: optional pre-normalized call list from
    `normalize_tool_call_entries`.
Description:
  Compute exact and semantic duplicate-call metrics, cache-event counts, and
  hotspot summaries that highlight repeated low-value tool usage within a
  single run.
Outputs:
  Returns a machine-readable redundancy summary for the run.
Side Effects:
  None.
"""
def summarize_tool_call_redundancy(
    entries: List[Dict[str, Any]],
    *,
    normalized_calls: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    calls = list(normalized_calls or normalize_tool_call_entries(entries))
    total_calls = len(calls)
    exact_counts = Counter(call["exact_key"] for call in calls)
    semantic_counts = Counter(call["semantic_key"] for call in calls)
    exact_counts_by_source = Counter(
        (str(call.get("source") or ""), call["exact_key"])
        for call in calls
        if str(call.get("source") or "").strip()
    )
    semantic_counts_by_source = Counter(
        (str(call.get("source") or ""), call["semantic_key"])
        for call in calls
        if str(call.get("source") or "").strip()
    )
    cache_counts = _cache_event_summary(entries)

    exact_duplicates = sum(max(0, count - 1) for count in exact_counts.values())
    semantic_duplicates = sum(max(0, count - 1) for count in semantic_counts.values())
    same_source_exact_duplicates = sum(max(0, count - 1) for count in exact_counts_by_source.values())
    same_source_semantic_duplicates = sum(max(0, count - 1) for count in semantic_counts_by_source.values())

    tool_buckets: Dict[str, Dict[str, Any]] = {}
    for call in calls:
        bucket = tool_buckets.setdefault(
            str(call.get("tool_family") or ""),
            {
                "tool_name": str(call.get("tool_name") or ""),
                "tool_family": str(call.get("tool_family") or ""),
                "total_calls": 0,
                "unique_exact_calls": set(),
                "unique_semantic_targets": set(),
                "exact_counts_by_source": Counter(),
                "semantic_counts_by_source": Counter(),
            },
        )
        bucket["total_calls"] += 1
        bucket["unique_exact_calls"].add(str(call.get("exact_key") or ""))
        bucket["unique_semantic_targets"].add(str(call.get("semantic_key") or ""))
        source_label = str(call.get("source") or "").strip()
        if source_label:
            bucket["exact_counts_by_source"][(source_label, str(call.get("exact_key") or ""))] += 1
            bucket["semantic_counts_by_source"][(source_label, str(call.get("semantic_key") or ""))] += 1

    top_duplicate_tools: List[Dict[str, Any]] = []
    for bucket in tool_buckets.values():
        total = int(bucket.get("total_calls") or 0)
        unique_exact = len(bucket.get("unique_exact_calls") or [])
        unique_semantic = len(bucket.get("unique_semantic_targets") or [])
        exact_dup = max(0, total - unique_exact)
        semantic_dup = max(0, total - unique_semantic)
        same_source_exact_dup = sum(max(0, count - 1) for count in (bucket.get("exact_counts_by_source") or Counter()).values())
        same_source_semantic_dup = sum(max(0, count - 1) for count in (bucket.get("semantic_counts_by_source") or Counter()).values())
        top_duplicate_tools.append(
            {
                "tool_name": str(bucket.get("tool_name") or ""),
                "tool_family": str(bucket.get("tool_family") or ""),
                "total_calls": total,
                "unique_exact_calls": unique_exact,
                "unique_semantic_targets": unique_semantic,
                "exact_duplicate_calls": exact_dup,
                "semantic_duplicate_calls": semantic_dup,
                "same_source_exact_duplicate_calls": same_source_exact_dup,
                "same_source_semantic_duplicate_calls": same_source_semantic_dup,
                "exact_duplicate_rate": round(exact_dup / total, 6) if total else 0.0,
                "semantic_duplicate_rate": round(semantic_dup / total, 6) if total else 0.0,
                "same_source_exact_duplicate_rate": round(same_source_exact_dup / total, 6) if total else 0.0,
                "same_source_semantic_duplicate_rate": round(same_source_semantic_dup / total, 6) if total else 0.0,
            }
        )
    top_duplicate_tools.sort(
        key=lambda item: (
            -int(item.get("same_source_semantic_duplicate_calls") or 0),
            -int(item.get("semantic_duplicate_calls") or 0),
            -int(item.get("same_source_exact_duplicate_calls") or 0),
            str(item.get("tool_family") or ""),
        )
    )

    target_groups: Dict[str, Dict[str, Any]] = {}
    for call in calls:
        semantic_key = str(call.get("semantic_key") or "")
        bucket = target_groups.setdefault(
            semantic_key,
            {
                "tool_name": str(call.get("tool_name") or ""),
                "tool_family": str(call.get("tool_family") or ""),
                "semantic_target_kind": str(call.get("semantic_target_kind") or ""),
                "semantic_target_label": str(call.get("semantic_target_label") or ""),
                "call_count": 0,
                "exact_keys": set(),
                "stages": set(),
                "sources": set(),
                "source_counts": Counter(),
                "example_normalized_args": call.get("normalized_args") or {},
            },
        )
        bucket["call_count"] += 1
        bucket["exact_keys"].add(str(call.get("exact_key") or ""))
        if call.get("stage"):
            bucket["stages"].add(str(call.get("stage")))
        if call.get("source"):
            source_label = str(call.get("source"))
            bucket["sources"].add(source_label)
            bucket["source_counts"][source_label] += 1

    top_duplicate_targets: List[Dict[str, Any]] = []
    for bucket in target_groups.values():
        call_count = int(bucket.get("call_count") or 0)
        unique_exact = len(bucket.get("exact_keys") or [])
        duplicate_calls = max(0, call_count - 1)
        if duplicate_calls <= 0:
            continue
        source_counts = bucket.get("source_counts") or Counter()
        same_source_duplicates = sum(max(0, int(count) - 1) for count in source_counts.values())
        top_duplicate_targets.append(
            {
                "tool_name": str(bucket.get("tool_name") or ""),
                "tool_family": str(bucket.get("tool_family") or ""),
                "semantic_target_kind": str(bucket.get("semantic_target_kind") or ""),
                "semantic_target_label": str(bucket.get("semantic_target_label") or ""),
                "call_count": call_count,
                "duplicate_calls": duplicate_calls,
                "unique_exact_call_shapes": unique_exact,
                "stages": sorted(bucket.get("stages") or []),
                "sources": sorted(bucket.get("sources") or []),
                "source_count": len(source_counts),
                "same_source_duplicate_calls": same_source_duplicates,
                "example_normalized_args": bucket.get("example_normalized_args") or {},
            }
        )
    top_duplicate_targets.sort(
        key=lambda item: (
            -int(item.get("duplicate_calls") or 0),
            -int(item.get("call_count") or 0),
            str(item.get("tool_family") or ""),
            str(item.get("semantic_target_label") or ""),
        )
    )

    suspicious_patterns = [
        {
            "pattern": f"{item['tool_family']} repeatedly targeted {item['semantic_target_label']}",
            "tool_family": item["tool_family"],
            "semantic_target_kind": item["semantic_target_kind"],
            "semantic_target_label": item["semantic_target_label"],
            "call_count": item["call_count"],
            "duplicate_calls": item["duplicate_calls"],
            "stages": item["stages"],
        }
        for item in top_duplicate_targets
        if int(item.get("call_count") or 0) >= 3
    ][:12]

    return {
        "schema_version": "tool_redundancy_v1",
        "total_tool_calls": total_calls,
        "unique_exact_calls": len(exact_counts),
        "exact_duplicate_calls": exact_duplicates,
        "exact_duplicate_rate": round(exact_duplicates / total_calls, 6) if total_calls else 0.0,
        "same_source_exact_duplicate_calls": same_source_exact_duplicates,
        "same_source_exact_duplicate_rate": round(same_source_exact_duplicates / total_calls, 6) if total_calls else 0.0,
        "unique_semantic_targets": len(semantic_counts),
        "semantic_duplicate_calls": semantic_duplicates,
        "semantic_duplicate_rate": round(semantic_duplicates / total_calls, 6) if total_calls else 0.0,
        "same_source_semantic_duplicate_calls": same_source_semantic_duplicates,
        "same_source_semantic_duplicate_rate": round(same_source_semantic_duplicates / total_calls, 6) if total_calls else 0.0,
        "cache_event_counts": cache_counts,
        "top_duplicate_tools": top_duplicate_tools[:12],
        "top_duplicate_targets": top_duplicate_targets[:20],
        "suspicious_patterns": suspicious_patterns,
    }
