"""
File: paths.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Centralize repository-rooted path helpers and small filesystem utilities for
  the testing harness.

Summary:
  This module anchors the harness to the current repository layout, loads
  repo-local environment defaults, and provides shared helpers for directory
  creation, JSON I/O, interpreter resolution, and stable identifier building.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency fallback
    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False


REPO_ROOT = Path(__file__).resolve().parents[2]
TESTING_ROOT = REPO_ROOT / "Testing"
DOCS_ROOT = TESTING_ROOT / "docs"
SCRIPTS_ROOT = TESTING_ROOT / "scripts"
SOURCES_ROOT = TESTING_ROOT / "sources"


def _fallback_load_dotenv(path: Path) -> bool:
    if not path.exists():
        return False
    loaded = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if value:
            try:
                parsed = shlex.split(value, comments=False, posix=True)
                value = parsed[0] if parsed else ""
            except Exception:
                value = value.strip("'\"")
        os.environ.setdefault(key, value)
        loaded = True
    return loaded


"""
Function: load_repo_dotenv
Inputs:
  - None directly. This helper always targets the repository-local `.env`
    file at the repo root.
Description:
  Load environment defaults for the harness once, preferring `python-dotenv`
  when available and falling back to a small parser when it is not.
Outputs:
  Returns `True` when any variables were loaded and `False` otherwise.
Side Effects:
  Mutates `os.environ` by setting variables that are not already defined.
"""
def load_repo_dotenv() -> bool:
    env_path = REPO_ROOT / ".env"
    loaded = bool(load_dotenv(env_path, override=False))
    if loaded:
        return True
    return _fallback_load_dotenv(env_path)


# Load repo-local environment defaults once for the testing harness so
# bundle prep and evaluation scripts can resolve GHIDRA_* settings without
# requiring extra shell exports.
load_repo_dotenv()

PROTOTYPE_SOURCE_ROOT = SOURCES_ROOT / "prototype"
EXPERIMENTAL_SOURCE_ROOT = SOURCES_ROOT / "experimental"
FINAL_ROUND_SOURCE_ROOT = SOURCES_ROOT / "final_round"
REFERENCE_BINARIES_ROOT = TESTING_ROOT / "reference_binaries"

BUILD_ROOT = TESTING_ROOT / "build"
PROTOTYPE_BUILD_ROOT = BUILD_ROOT / "prototype"
EXPERIMENTAL_BUILD_ROOT = BUILD_ROOT / "experimental"
FINAL_ROUND_BUILD_ROOT = BUILD_ROOT / "deepseek_final"

GENERATED_ROOT = TESTING_ROOT / "generated"
BUNDLE_ROOT = GENERATED_ROOT / "bundles"

RESULTS_ROOT = TESTING_ROOT / "results"
RUNS_ROOT = RESULTS_ROOT / "runs"
PREFLIGHT_ROOT = RESULTS_ROOT / "preflight"

CONFIG_ROOT = TESTING_ROOT / "config"
PROMPTS_ROOT = CONFIG_ROOT / "prompts"

DEFAULT_SERVERS_MANIFEST = REPO_ROOT / "MCPServers" / "servers.json"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


"""
Function: write_json
Inputs:
  - path: destination JSON file path.
  - payload: dictionary payload to serialize.
Description:
  Serialize one JSON payload with stable formatting and replace the target
  file atomically so polling readers never observe truncated content.
Outputs:
  Returns nothing.
Side Effects:
  Creates parent directories, writes a same-directory temporary file, and
  replaces the destination path on disk.
"""
def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    # Polling readers should never observe truncated JSON when concurrent runs
    # update live status or catalogs. Write to a same-directory temp file and
    # then atomically replace the destination.
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
        prefix=f".{path.name}.",
        suffix=".tmp",
    ) as handle:
        handle.write(rendered)
        temp_path = Path(handle.name)
    os.replace(temp_path, path)


"""
Function: repo_python_executable
Inputs:
  - None.
Description:
  Resolve the preferred Python interpreter for child harness processes,
  favoring the repository virtual environment when it exists.
Outputs:
  Returns the interpreter path as a string.
Side Effects:
  None.
"""
def repo_python_executable() -> str:
    candidates = [
        REPO_ROOT / ".venv" / "bin" / "python",
        REPO_ROOT.parent / ".venv" / "bin" / "python",
    ]
    for venv_python in candidates:
        if venv_python.exists():
            # Do not resolve the venv interpreter symlink. Resolving it turns
            # `/path/to/.venv/bin/python` into the underlying Homebrew/System
            # interpreter and drops the virtualenv context for child processes.
            return str(venv_python)
    return sys.executable


def slugify(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    text = text.strip("-._")
    return text or "run"


def build_run_id(prefix: str, corpus: str, label: str = "") -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    parts = [prefix, corpus, timestamp]
    if label:
        parts.append(slugify(label))
    return "-".join(parts)
