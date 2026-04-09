#!/usr/bin/env python3
"""
FastMCP server that exposes ssdeep-compatible fuzzy hashing tools.

Backend strategy:
- Prefer a Python binding (`ppdeep` or `ssdeep`) when available.
- Fall back to the `ssdeep` CLI for file fingerprinting.
- Return structured dependency errors when neither backend exists.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "ssdeep_mcp",
    instructions="MCP server that exposes ssdeep-style fuzzy hashing and comparison tools.",
)

IS_WINDOWS = sys.platform.startswith("win")
_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")


def has_command(command: str) -> bool:
    return shutil.which(command) is not None


def truncate_text(text: str, max_chars: int = 4000) -> str:
    value = text or ""
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...[truncated]..."


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


def ensure_existing_file(path: str) -> str:
    candidate = Path(normalize_user_path(path))
    if not candidate.is_absolute():
        candidate = candidate.resolve()
    if not candidate.exists():
        raise FileNotFoundError(f"path not found: {candidate}")
    if not candidate.is_file():
        raise FileNotFoundError(f"not a file: {candidate}")
    return str(candidate)


def run_command(argv: list[str], timeout_sec: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=max(1, int(timeout_sec)),
    )


def _load_python_backend() -> tuple[str, Callable[[str], str] | None, Callable[[str, str], int] | None]:
    for module_name in ("ppdeep", "ssdeep"):
        try:
            module = __import__(module_name)
        except Exception:
            continue

        def _hash_from_file(file_path: str, _module: Any = module) -> str:
            for attr in ("hash_from_file", "hash_from_filename"):
                fn = getattr(_module, attr, None)
                if callable(fn):
                    return str(fn(file_path))
            data = Path(file_path).read_bytes()
            for attr in ("hash", "ssdeep"):
                fn = getattr(_module, attr, None)
                if callable(fn):
                    return str(fn(data))
            raise RuntimeError(f"{module_name} does not expose a supported file hashing API")

        compare_fn = getattr(module, "compare", None)
        if not callable(compare_fn):
            compare_fn = None

        return (f"python:{module_name}", _hash_from_file, compare_fn)

    return ("", None, None)


def _parse_ssdeep_signature(signature: str) -> dict[str, Any]:
    value = str(signature or "").strip()
    parts = value.split(":", 2)
    if len(parts) != 3:
        return {
            "signature": value,
            "blocksize": None,
            "hash_part_1": "",
            "hash_part_2": "",
        }
    blocksize = None
    try:
        blocksize = int(parts[0])
    except Exception:
        blocksize = None
    return {
        "signature": value,
        "blocksize": blocksize,
        "hash_part_1": parts[1],
        "hash_part_2": parts[2],
    }


def _fingerprint_with_cli(file_path: str, timeout_sec: int = 30) -> dict[str, Any]:
    if not has_command("ssdeep"):
        return {
            "ok": False,
            "error": "No ssdeep backend available. Install `ssdeep` on PATH or a Python binding such as `ppdeep`.",
            "backend": "",
        }

    resolved = ensure_existing_file(file_path)
    result = run_command(["ssdeep", resolved], timeout_sec=timeout_sec)
    if result.returncode != 0:
        return {
            "ok": False,
            "error": "ssdeep command failed",
            "backend": "cli:ssdeep",
            "rc": result.returncode,
            "stdout": truncate_text(result.stdout or ""),
            "stderr": truncate_text(result.stderr or ""),
            "file_path": resolved,
        }

    for raw_line in (result.stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith("ssdeep") or lowered.startswith("blocksize"):
            continue
        signature_text = line.rsplit(",", 1)[0].strip() if "," in line else line
        parsed = _parse_ssdeep_signature(signature_text)
        if parsed["signature"]:
            return {
                "ok": True,
                "backend": "cli:ssdeep",
                "file_path": resolved,
                **parsed,
            }

    return {
        "ok": False,
        "error": "Could not parse ssdeep output",
        "backend": "cli:ssdeep",
        "stdout": truncate_text(result.stdout or ""),
        "stderr": truncate_text(result.stderr or ""),
        "file_path": resolved,
    }


@mcp.tool()
def ssdeepFingerprintFile(file_path: str, timeout_sec: int = 30) -> dict[str, Any]:
    """Compute an ssdeep-compatible fuzzy hash for a local file."""
    try:
        backend_name, hash_from_file, _compare = _load_python_backend()
        resolved = ensure_existing_file(file_path)
        if hash_from_file is not None:
            signature = str(hash_from_file(resolved))
            return {
                "ok": True,
                "backend": backend_name,
                "file_path": resolved,
                **_parse_ssdeep_signature(signature),
            }
        return _fingerprint_with_cli(resolved, timeout_sec=timeout_sec)
    except Exception as exc:
        logger.exception("ssdeepFingerprintFile failed")
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def ssdeepCompare(
    signature_a: str = "",
    signature_b: str = "",
    file_path_a: str = "",
    file_path_b: str = "",
) -> dict[str, Any]:
    """Compare two ssdeep signatures or two local files and return a similarity score."""
    try:
        backend_name, hash_from_file, compare_fn = _load_python_backend()
        if compare_fn is None:
            return {
                "ok": False,
                "error": "ssdeep comparison requires a Python binding (`ppdeep` or `ssdeep`).",
                "backend": backend_name or "",
            }

        sig_a = str(signature_a or "").strip()
        sig_b = str(signature_b or "").strip()

        if not sig_a and file_path_a:
            if hash_from_file is None:
                return {"ok": False, "error": "No file hashing backend available for file_path_a", "backend": backend_name}
            sig_a = str(hash_from_file(ensure_existing_file(file_path_a)))
        if not sig_b and file_path_b:
            if hash_from_file is None:
                return {"ok": False, "error": "No file hashing backend available for file_path_b", "backend": backend_name}
            sig_b = str(hash_from_file(ensure_existing_file(file_path_b)))

        if not sig_a or not sig_b:
            return {
                "ok": False,
                "error": "Provide either both signatures or both file paths.",
                "backend": backend_name,
            }

        score = int(compare_fn(sig_a, sig_b))
        return {
            "ok": True,
            "backend": backend_name,
            "score": score,
            "signature_a": sig_a,
            "signature_b": sig_b,
            "meaning": "Higher scores indicate greater fuzzy-hash similarity.",
        }
    except Exception as exc:
        logger.exception("ssdeepCompare failed")
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def ssdeepHelp(timeout_sec: int = 5) -> str:
    """Return backend availability information and `ssdeep --help` output when available."""
    backend_name, _hash_from_file, compare_fn = _load_python_backend()
    lines = [
        f"python_backend={backend_name or 'none'}",
        f"compare_supported={bool(compare_fn)}",
        f"cli_available={has_command('ssdeep')}",
    ]
    if not has_command("ssdeep"):
        return "\n".join(lines)
    result = run_command(["ssdeep", "--help"], timeout_sec=timeout_sec)
    lines.extend(
        [
            f"rc={result.returncode}",
            "stdout:",
            truncate_text(result.stdout or "", max_chars=12000),
            "stderr:",
            truncate_text(result.stderr or "", max_chars=4000),
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for ssdeep")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8096,
        help="Port to run MCP server on (only used for sse), default: 8096",
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

    logger.info("Using transport: %s", args.transport)

    if args.transport == "sse":
        mcp.settings.log_level = args.log_level
        mcp.settings.host = args.mcp_host or "127.0.0.1"
        mcp.settings.port = args.mcp_port or 8096
        mcp.run(transport="sse", show_banner=False)
    else:
        mcp.run(show_banner=False)


if __name__ == "__main__":
    main()
