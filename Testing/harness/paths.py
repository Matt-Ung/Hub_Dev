from __future__ import annotations

import json
import os
import re
import shlex
import sys
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

PROTOTYPE_SOURCE_ROOT = TESTING_ROOT / "Prototype_Test_Source"
EXPERIMENTAL_SOURCE_ROOT = TESTING_ROOT / "Experimental_Test_Source"
REFERENCE_BINARIES_ROOT = TESTING_ROOT / "reference_binaries"

BUILD_ROOT = TESTING_ROOT / "build"
PROTOTYPE_BUILD_ROOT = BUILD_ROOT / "prototype"
EXPERIMENTAL_BUILD_ROOT = BUILD_ROOT / "experimental"

GENERATED_ROOT = TESTING_ROOT / "generated"
BUNDLE_ROOT = GENERATED_ROOT / "bundles"

RESULTS_ROOT = TESTING_ROOT / "results"
RUNS_ROOT = RESULTS_ROOT / "runs"

CONFIG_ROOT = TESTING_ROOT / "config"
PROMPTS_ROOT = CONFIG_ROOT / "prompts"

DEFAULT_SERVERS_MANIFEST = REPO_ROOT / "MCPServers" / "servers.json"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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
