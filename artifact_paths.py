from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_AGENT_ARTIFACT_DIR = REPO_ROOT / "agent_artifacts"
PREFERRED_YARA_RULES_DIR = REPO_ROOT / "third_party" / "signature-base"
LEGACY_YARA_RULES_DIR = REPO_ROOT / "MCPServers" / "yara_rules"

ARTIFACT_TYPE_DEFAULTS: Dict[str, str] = {
    "yara": "yara",
    "python": "python",
    "java": "java",
    "reports": "reports",
    "ghidra": "ghidra",
}

ARTIFACT_TYPE_ENV_OVERRIDES: Dict[str, str] = {
    "yara": "AGENT_YARA_ARTIFACT_DIR",
    "python": "AGENT_PYTHON_ARTIFACT_DIR",
    "java": "AGENT_JAVA_ARTIFACT_DIR",
    "reports": "AGENT_REPORT_ARTIFACT_DIR",
    "ghidra": "AGENT_GHIDRA_ARTIFACT_DIR",
}

ARTIFACT_TYPE_DEFAULT_EXTENSIONS: Dict[str, str] = {
    "yara": ".yar",
    "python": ".py",
    "java": ".java",
    "reports": ".md",
    "ghidra": "",
}

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _normalize_artifact_type(artifact_type: str) -> str:
    normalized = str(artifact_type or "").strip().lower()
    if normalized not in ARTIFACT_TYPE_DEFAULTS:
        allowed = ", ".join(sorted(ARTIFACT_TYPE_DEFAULTS))
        raise ValueError(f"unknown artifact_type {artifact_type!r}; expected one of: {allowed}")
    return normalized


def _resolve_path(raw_path: str, *, base: Path) -> Path:
    candidate = Path(os.path.expandvars(os.path.expanduser(str(raw_path).strip())))
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate.resolve()


def _sanitize_component(value: str, default: str) -> str:
    cleaned = _SAFE_COMPONENT_RE.sub("_", str(value or "").strip())
    cleaned = cleaned.strip("._-")
    return cleaned or default


def _sanitize_subdir_parts(subdir: str) -> Iterable[str]:
    raw = str(subdir or "").strip().replace("\\", "/")
    if not raw:
        return []
    return [_sanitize_component(part, "artifact") for part in raw.split("/") if part.strip()]


def get_agent_artifact_root() -> Path:
    raw = str(os.environ.get("AGENT_ARTIFACT_DIR") or "").strip()
    if raw:
        return _resolve_path(raw, base=REPO_ROOT)
    return DEFAULT_AGENT_ARTIFACT_DIR.resolve()


def get_agent_artifact_dir(artifact_type: str) -> Path:
    normalized = _normalize_artifact_type(artifact_type)
    override_env = ARTIFACT_TYPE_ENV_OVERRIDES[normalized]
    override_raw = str(os.environ.get(override_env) or "").strip()
    if override_raw:
        return _resolve_path(override_raw, base=REPO_ROOT)
    return (get_agent_artifact_root() / ARTIFACT_TYPE_DEFAULTS[normalized]).resolve()


def ensure_agent_artifact_dir(artifact_type: str) -> Path:
    directory = get_agent_artifact_dir(artifact_type)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def resolve_agent_artifact_path(
    artifact_type: str,
    filename: str = "",
    *,
    default_stem: str,
    default_extension: Optional[str] = None,
    subdir: str = "",
) -> Path:
    normalized = _normalize_artifact_type(artifact_type)
    directory = ensure_agent_artifact_dir(normalized)
    for part in _sanitize_subdir_parts(subdir):
        directory = directory / part
    directory.mkdir(parents=True, exist_ok=True)

    candidate = str(filename or "").strip()
    if candidate:
        if "/" in candidate or "\\" in candidate:
            raise ValueError("filename must be a simple file name, not a path")
        stem = _sanitize_component(Path(candidate).stem, default_stem)
        suffix = Path(candidate).suffix
    else:
        stem = _sanitize_component(default_stem, "artifact")
        suffix = ""

    extension = default_extension
    if extension is None:
        extension = ARTIFACT_TYPE_DEFAULT_EXTENSIONS.get(normalized, "")
    if suffix:
        extension = suffix
    if extension and not extension.startswith("."):
        extension = "." + extension
    return (directory / f"{stem}{extension}").resolve()


def list_agent_artifact_dirs() -> Dict[str, str]:
    payload: Dict[str, str] = {
        "root": str(get_agent_artifact_root()),
        "base_yara_rules": str(get_base_yara_rules_dir()),
    }
    for artifact_type in sorted(ARTIFACT_TYPE_DEFAULTS):
        payload[artifact_type] = str(get_agent_artifact_dir(artifact_type))
    return payload


def get_base_yara_rules_dir() -> Path:
    raw = str(os.environ.get("YARA_RULES_DIR") or "").strip()
    if raw:
        return _resolve_path(raw, base=REPO_ROOT)
    if PREFERRED_YARA_RULES_DIR.exists():
        return PREFERRED_YARA_RULES_DIR.resolve()
    return LEGACY_YARA_RULES_DIR.resolve()
