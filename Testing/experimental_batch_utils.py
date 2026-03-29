from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTAL_SAMPLES_ROOT = REPO_ROOT / "Testing" / "Experimental_Test_Executables"
GENERATED_ROOT = REPO_ROOT / "Testing" / "generated"
EXPERIMENTAL_ANALYSIS_ROOT = GENERATED_ROOT / "experimental_analysis"
EXPERIMENTAL_REPORTS_ROOT = GENERATED_ROOT / "experimental_reports"
DEFAULT_MANIFEST_PATH = EXPERIMENTAL_SAMPLES_ROOT / "sample_manifest.json"
DEFAULT_SERVERS_MANIFEST = REPO_ROOT / "MCPServers" / "servers.json"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def load_sample_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> Dict[str, Any]:
    raw = read_json(path)
    samples = raw.get("samples") if isinstance(raw.get("samples"), list) else []
    by_name: Dict[str, Any] = {}
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        name = str(sample.get("sample") or sample.get("name") or "").strip()
        if name:
            by_name[name] = sample
    return {"meta": raw, "samples": by_name}


def sample_slug(sample_path: Path) -> str:
    return sample_path.stem


def list_experimental_samples(samples_root: Path = EXPERIMENTAL_SAMPLES_ROOT) -> List[Path]:
    return sorted(path for path in samples_root.glob("*.exe") if path.is_file())


def compute_file_identity(path: Path, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            size_bytes += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "name": path.name,
        "size_bytes": size_bytes,
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "mtime_epoch": int(stat.st_mtime),
    }


def resolve_analyze_headless(ghidra_install_dir: str = "", ghidra_headless: str = "") -> Path | None:
    explicit = str(ghidra_headless or os.environ.get("GHIDRA_HEADLESS") or "").strip()
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.exists():
            return candidate.resolve()

    install_dir = str(ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR") or "").strip()
    if install_dir:
        candidate = Path(install_dir).expanduser() / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        if candidate.exists():
            return candidate.resolve()

    discovered = shutil.which("analyzeHeadless")
    if discovered:
        return Path(discovered).resolve()

    return None


def tool_available(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(
    argv: List[str],
    *,
    cwd: Path | None = None,
    timeout_sec: int = 300,
) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "command": argv,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "command": argv,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": f"timeout after {timeout_sec}s",
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "command": argv,
            "stdout": "",
            "stderr": "",
            "error": f"{type(exc).__name__}: {exc}",
        }


def shorten_text(value: str, max_chars: int = 16000) -> str:
    text = value or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]..."


def absolutize_server_manifest(raw_manifest: Dict[str, Any], manifest_path: Path) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    base_dir = manifest_path.parent.resolve()
    for server_name, raw_cfg in raw_manifest.items():
        if not isinstance(raw_cfg, dict):
            continue
        cfg = dict(raw_cfg)
        args = list(cfg.get("args") or [])
        if args and isinstance(args[0], str) and args[0].endswith(".py"):
            candidate = Path(args[0]).expanduser()
            if not candidate.is_absolute():
                candidate = (base_dir / candidate).resolve()
            args[0] = str(candidate)
            cfg["args"] = args
        normalized[server_name] = cfg
    return normalized


def build_artifact_servers_manifest(bundle_dir: Path, output_path: Path) -> Path:
    raw_manifest = read_json(DEFAULT_SERVERS_MANIFEST)
    manifest = absolutize_server_manifest(raw_manifest, DEFAULT_SERVERS_MANIFEST)
    artifact_server = REPO_ROOT / "MCPServers" / "artifactGhidraMCP.py"
    manifest["ghidramcp"] = {
        "transport": "stdio",
        "command": "python",
        "args": [str(artifact_server.resolve()), "--transport", "stdio", "--bundle-dir", str(bundle_dir.resolve())],
    }
    write_json(output_path, manifest)
    return output_path


def tool_name_to_server_guess(tool_name: str) -> str:
    name = str(tool_name or "").strip().lower()
    if name in {
        "list_methods",
        "list_classes",
        "decompile_function",
        "rename_function",
        "rename_data",
        "list_segments",
        "list_imports",
        "list_exports",
        "list_namespaces",
        "list_data_items",
        "search_functions_by_name",
        "rename_variable",
        "get_function_by_address",
        "get_current_address",
        "get_current_function",
        "list_functions",
        "decompile_function_by_address",
        "disassemble_function",
        "set_decompiler_comment",
        "set_disassembly_comment",
        "rename_function_by_address",
        "set_function_prototype",
        "set_local_variable_type",
        "get_xrefs_to",
        "get_xrefs_from",
        "get_function_xrefs",
        "list_strings",
        "get_program_info",
        "get_call_graph",
    }:
        return "ghidramcp"
    if "floss" in name:
        return "flareflossmcp"
    if "capa" in name:
        return "CapaMCP"
    if "yara" in name:
        return "yaramcp"
    if "upx" in name:
        return "upxmcp"
    if "binwalk" in name:
        return "binwalkmcp"
    if "hash" in name:
        return "hashdbmcp"
    if "string" in name:
        return "stringmcp"
    return "unknown"


def parse_tool_log_sections(sections: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for stage_name, raw_text in (sections or {}).items():
        text = str(raw_text or "").strip()
        if not text:
            continue
        decoder = json.JSONDecoder()
        idx = 0
        length = len(text)
        while idx < length:
            while idx < length and text[idx].isspace():
                idx += 1
            if idx >= length:
                break
            try:
                obj, end = decoder.raw_decode(text, idx)
            except json.JSONDecodeError:
                next_obj = text.find("\n{", idx + 1)
                if next_obj == -1:
                    break
                idx = next_obj + 1
                continue
            if isinstance(obj, dict):
                if "stage" not in obj:
                    obj["stage"] = stage_name
                entries.append(obj)
            idx = end
    return entries


def summarize_tool_usage(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_tool: Dict[str, int] = {}
    by_server: Dict[str, int] = {}
    for entry in entries:
        if str(entry.get("kind") or "") != "tool_call":
            continue
        tool_name = str(entry.get("tool_name") or "").strip()
        if not tool_name:
            continue
        server_id = str(entry.get("server_id") or "").strip() or tool_name_to_server_guess(tool_name)
        by_tool[tool_name] = int(by_tool.get(tool_name, 0)) + 1
        by_server[server_id] = int(by_server.get(server_id, 0)) + 1
    return {
        "by_tool_name": dict(sorted(by_tool.items(), key=lambda item: (-item[1], item[0]))),
        "by_server": dict(sorted(by_server.items(), key=lambda item: (-item[1], item[0]))),
    }


def repo_python_executable() -> str:
    venv_python = REPO_ROOT.parent / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python.resolve())
    return sys.executable
