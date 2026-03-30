#!/usr/bin/env python3
"""
Adapted for this repository from FuzzingLabs mcp-security-hub:
https://github.com/FuzzingLabs/mcp-security-hub
Original inspiration: binary-analysis/yara-mcp/server.py

This version is rewritten into the lightweight FastMCP wrapper style used by
the local MCPServers/ directory.
"""

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

from fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False


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
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded = True
    return loaded


def _load_repo_dotenv() -> None:
    env_path = REPO_ROOT / ".env"
    loaded = bool(load_dotenv(env_path, override=False))
    if not loaded:
        _fallback_load_dotenv(env_path)


_load_repo_dotenv()

from artifact_paths import (
    get_base_yara_rules_dir,
    get_agent_artifact_dir,
    list_agent_artifact_dirs,
)

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")

RULE_NAME_RE = re.compile(r"(?mi)^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
mcp = FastMCP(
    "yara_mcp",
    instructions="MCP server that exposes structured YARA scanning tools.",
)


def _base_rules_dir() -> Path:
    return get_base_yara_rules_dir()


def _generated_rules_dir() -> Path:
    return get_agent_artifact_dir("yara")


def truncate_text(text: str, max_chars: int = 12000) -> str:
    value = text or ""
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...[truncated]..."


def has_command(command: str) -> bool:
    return shutil.which(command) is not None


def normalize_user_path(path: str) -> str:
    value = (path or "").strip()
    if not value:
        return value

    if IS_WINDOWS:
        match = _DRIVE_RE.match(value)
        if match:
            return value[1:]

        match = _MNT_RE.match(value)
        if match:
            drive = match.group(1).upper()
            rest = match.group(2).replace("/", "\\")
            return f"{drive}:\\{rest}"

    return os.path.expandvars(os.path.expanduser(value))


def ensure_existing_path(path: str) -> str:
    candidate = Path(normalize_user_path(path))
    if not candidate.is_absolute():
        candidate = candidate.resolve()
    if not candidate.exists():
        raise FileNotFoundError(f"path not found: {candidate}")
    return str(candidate)


def run_command(argv: list[str], timeout_sec: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=max(1, int(timeout_sec)),
    )


def run_help_command(binary: str, timeout_sec: int = 5) -> str:
    if not has_command(binary):
        return f"Error: `{binary}` not found on PATH."
    result = run_command([binary, "--help"], timeout_sec=timeout_sec)
    return (
        f"{binary} --help\n"
        f"rc={result.returncode}\n"
        "stdout:\n"
        f"{truncate_text(result.stdout or '', max_chars=16000)}\n"
        "stderr:\n"
        f"{truncate_text(result.stderr or '', max_chars=4000)}"
    )


def _parse_yara_output(output: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) < 2:
            continue
        rule_name, rest = parts[0], parts[1].strip()
        if rule_name.startswith("0x"):
            continue
        matches.append({"rule": rule_name, "target": rest})
    return matches


def _iter_rule_files(rules_dir: Path) -> list[Path]:
    files: list[Path] = []
    if not rules_dir.is_dir():
        return files
    for pattern in ("*.yar", "*.yara"):
        for path in sorted(rules_dir.rglob(pattern)):
            if path.name.lower() == "index.yar":
                continue
            files.append(path)
    return files


def _build_composite_rules_file(rule_paths: list[Path]) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False, encoding="utf-8") as handle:
        for path in rule_paths:
            handle.write(f"// source: {path}\n")
            handle.write(path.read_text(encoding="utf-8", errors="replace"))
            handle.write("\n\n")
        return handle.name


def _resolve_rules_path(rules_path: Optional[str]) -> tuple[str, list[str], dict[str, Any]]:
    if rules_path:
        return ensure_existing_path(rules_path), [], {"source": "explicit"}

    base_rules_dir = _base_rules_dir()
    generated_rules_dir = _generated_rules_dir()
    base_rule_files = _iter_rule_files(base_rules_dir)
    generated_rule_files = _iter_rule_files(generated_rules_dir)
    all_rule_files = [*base_rule_files, *generated_rule_files]
    if not all_rule_files:
        raise FileNotFoundError(
            "no YARA rules found. Provide rules_path or create rules under "
            f"{base_rules_dir} or {generated_rules_dir}"
        )

    metadata = {
        "source": "default_combined",
        "base_rules_dir": str(base_rules_dir),
        "generated_rules_dir": str(generated_rules_dir),
        "base_rule_count": len(base_rule_files),
        "generated_rule_count": len(generated_rule_files),
        "total_rule_count": len(all_rule_files),
    }
    if len(all_rule_files) == 1:
        return str(all_rule_files[0]), [], metadata

    composite_path = _build_composite_rules_file(all_rule_files)
    return composite_path, [composite_path], metadata


def _extract_rule_name(rule_text: str) -> str:
    match = RULE_NAME_RE.search(rule_text or "")
    if not match:
        raise ValueError("could not find a YARA `rule <name>` declaration in rule_text")
    return match.group(1)


def _normalize_rule_filename(filename: str, rule_name: str) -> str:
    candidate = (filename or "").strip()
    if candidate:
        if "/" in candidate or "\\" in candidate:
            raise ValueError("filename must be a simple file name, not a path")
        safe = SAFE_FILENAME_RE.sub("_", candidate)
    else:
        safe = SAFE_FILENAME_RE.sub("_", rule_name)

    safe = safe.strip("._-") or rule_name
    if not safe.lower().endswith((".yar", ".yara")):
        safe += ".yar"
    return safe


def _build_index_contents(rules_dir: Path) -> str:
    includes: list[str] = []
    for pattern in ("*.yar", "*.yara"):
        for path in sorted(rules_dir.glob(pattern)):
            if path.name.lower() == "index.yar":
                continue
            includes.append(f'include "./{path.name}"')
    return "\n".join(includes) + ("\n" if includes else "")


def _validate_rule_text(rule_text: str, timeout_sec: int) -> dict[str, Any]:
    if not has_command("yara"):
        return {
            "ok": True,
            "validated": False,
            "warning": "yara not found on PATH; rule text was not syntax-validated before writing",
        }

    rule_temp: Optional[str] = None
    target_temp: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as handle:
            handle.write(rule_text)
            rule_temp = handle.name
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as handle:
            handle.write(b"")
            target_temp = handle.name

        result = run_command(["yara", "-w", rule_temp, target_temp], timeout_sec=timeout_sec)
        ok = result.returncode == 0
        payload = {
            "ok": ok,
            "validated": ok,
            "validation_command": ["yara", "-w", rule_temp, target_temp],
            "validation_stdout": truncate_text(result.stdout or "", max_chars=8000),
            "validation_stderr": truncate_text(result.stderr or "", max_chars=4000),
        }
        if not ok:
            payload["error"] = "YARA validation failed; rule was not written"
        return payload
    finally:
        for temp_path in (rule_temp, target_temp):
            if temp_path:
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except Exception:
                    pass


def _run_yara_scan(
    target_path: str,
    rules_arg: str,
    recursive: bool,
    timeout_sec: int,
    show_strings: bool,
) -> dict[str, Any]:
    if not has_command("yara"):
        return {"ok": False, "error": "yara not found on PATH"}

    resolved_target = ensure_existing_path(target_path)
    target = Path(resolved_target)

    cmd = ["yara", "-w"]
    if recursive and target.is_dir():
        cmd.append("-r")
    if show_strings:
        cmd.append("-s")
    cmd.extend([rules_arg, resolved_target])

    result = run_command(cmd, timeout_sec=timeout_sec)
    matches = _parse_yara_output(result.stdout or "")
    unique_rules = sorted({m["rule"] for m in matches})
    unique_targets = sorted({m["target"] for m in matches})

    return {
        "ok": result.returncode == 0,
        "rc": result.returncode,
        "command": cmd,
        "rules_path": rules_arg,
        "target_path": resolved_target,
        "recursive": recursive,
        "show_strings": show_strings,
        "matches": matches,
        "stats": {
            "match_count": len(matches),
            "unique_rule_count": len(unique_rules),
            "unique_target_count": len(unique_targets),
            "rules": unique_rules,
        },
        "stdout": truncate_text(result.stdout or "", max_chars=16000),
        "stderr": truncate_text(result.stderr or "", max_chars=4000),
    }


@mcp.tool()
def yaraScan(
    target_path: str,
    rules_path: str = "",
    recursive: bool = True,
    show_strings: bool = False,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """Scan a file or directory with YARA rules."""
    try:
        rules_arg, cleanup_paths, rules_meta = _resolve_rules_path(rules_path.strip() or None)
        return _run_yara_scan(
            target_path=target_path,
            rules_arg=rules_arg,
            recursive=recursive,
            timeout_sec=timeout_sec,
            show_strings=show_strings,
        ) | rules_meta
    except Exception as e:
        logger.exception("yaraScan failed")
        return {"ok": False, "error": str(e)}
    finally:
        for temp_path in locals().get("cleanup_paths", []):
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass


@mcp.tool()
def yaraScanInline(
    target_path: str,
    rule_text: str,
    recursive: bool = True,
    show_strings: bool = False,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """Scan a file or directory with inline YARA rule text."""
    if not rule_text.strip():
        return {"ok": False, "error": "rule_text cannot be empty"}

    temp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as handle:
            handle.write(rule_text)
            temp_path = handle.name
        return _run_yara_scan(
            target_path=target_path,
            rules_arg=temp_path,
            recursive=recursive,
            timeout_sec=timeout_sec,
            show_strings=show_strings,
        )
    except Exception as e:
        logger.exception("yaraScanInline failed")
        return {"ok": False, "error": str(e)}
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass


@mcp.tool()
def yaraListRules(max_rules: int = 200) -> dict[str, Any]:
    """List available rule files under the configured rules directory."""
    entries: list[dict[str, str]] = []
    rules: list[str] = []
    base_rules_dir = _base_rules_dir()
    generated_rules_dir = _generated_rules_dir()
    for source_name, rules_dir in (("base", base_rules_dir), ("generated", generated_rules_dir)):
        for path in _iter_rule_files(rules_dir):
            relative_path = str(path.relative_to(rules_dir))
            entries.append(
                {
                    "source": source_name,
                    "relative_path": relative_path,
                    "absolute_path": str(path),
                }
            )
            rules.append(f"{source_name}:{relative_path}")
            if len(entries) >= max_rules:
                break
        if len(entries) >= max_rules:
            break
    return {
        "ok": True,
        "rules_dir": str(base_rules_dir),
        "generated_rules_dir": str(generated_rules_dir),
        "artifact_dirs": list_agent_artifact_dirs(),
        "rules": sorted(rules),
        "rule_entries": entries,
        "count": len(entries),
    }


@mcp.tool()
def yaraWriteRule(
    rule_text: str,
    filename: str = "",
    overwrite: bool = False,
    validate: bool = True,
    timeout_sec: int = 15,
) -> dict[str, Any]:
    """Write YARA rule text into the configured rules directory and refresh index.yar."""
    text = (rule_text or "").strip()
    if not text:
        return {"ok": False, "error": "rule_text cannot be empty"}

    try:
        rule_name = _extract_rule_name(text)
        normalized_name = _normalize_rule_filename(filename, rule_name)
        base_rules_dir = _base_rules_dir()
        rules_dir = _generated_rules_dir().resolve()
        rules_dir.mkdir(parents=True, exist_ok=True)
        rule_path = rules_dir / normalized_name
        existed_before_write = rule_path.exists()

        if existed_before_write and not overwrite:
            return {
                "ok": False,
                "error": f"rule file already exists: {rule_path}",
                "rule_path": str(rule_path),
            }

        validation: dict[str, Any] = {"ok": True, "validated": False}
        if validate:
            validation = _validate_rule_text(text, timeout_sec=timeout_sec)
            if not validation.get("ok"):
                return {
                    "ok": False,
                    "error": str(validation.get("error") or "rule validation failed"),
                    "rule_name": rule_name,
                    "proposed_rule_path": str(rule_path),
                    "validation_stdout": validation.get("validation_stdout", ""),
                    "validation_stderr": validation.get("validation_stderr", ""),
                }

        rule_path.write_text(text.rstrip() + "\n", encoding="utf-8")
        index_path = rules_dir / "index.yar"
        index_path.write_text(_build_index_contents(rules_dir), encoding="utf-8")

        return {
            "ok": True,
            "rule_name": rule_name,
            "rule_path": str(rule_path),
            "rules_dir": str(rules_dir),
            "base_rules_dir": str(base_rules_dir),
            "index_path": str(index_path),
            "overwrote_existing": existed_before_write and overwrite,
            "validated": bool(validation.get("validated")),
            "validation_warning": validation.get("warning", ""),
            "validation_stdout": validation.get("validation_stdout", ""),
            "validation_stderr": validation.get("validation_stderr", ""),
        }
    except Exception as e:
        logger.exception("yaraWriteRule failed")
        return {"ok": False, "error": str(e)}


@mcp.tool()
def yaraHelp(timeout_sec: int = 5) -> str:
    """Return `yara --help` output."""
    dirs = list_agent_artifact_dirs()
    base_rules_dir = _base_rules_dir()
    generated_rules_dir = _generated_rules_dir()
    return (
        run_help_command("yara", timeout_sec=timeout_sec)
        + "\n\n"
        + "Configured rule directories:\n"
        + f"- base rules: {base_rules_dir}\n"
        + f"- generated rules: {generated_rules_dir}\n"
        + f"- artifact root: {dirs['root']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for YARA")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8092,
        help="Port to run MCP server on (only used for sse), default: 8092",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse"],
        help="Transport protocol for MCP, default: stdio",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level, default: INFO",
    )
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level, logging.INFO)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    if args.transport == "sse":
        try:
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8092
            mcp.run(transport="sse", show_banner=False)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
