"""
capa_mcp.py

FastMCP server that exposes a `callCapa(file_path, ...)` tool to run Mandiant capa.

Key features:
- Cross-platform path normalization (fixes `/C:/...` and `/mnt/c/...` cases)
- Robust CLI flag selection by probing `capa -h` at runtime (avoids -j/--json mismatches)
- Configurable rules dir, sigs dir, output format, timeout, and extra args
- Improved subprocess error reporting (stdout/stderr/return code)
- Preserves your existing argparse CLI:
    --transport {stdio,sse}
    --mcp-host
    --mcp-port
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from fastmcp import FastMCP

mcp = FastMCP("capa_mcp")

# ----------------------------
# Helpers
# ----------------------------

def _normalize_path(p: Union[str, Path]) -> str:
    """
    Normalize cross-platform paths:
      - "/C:/Users/..."  -> "C:\\Users\\..." on Windows
      - "/mnt/c/Users/..." -> "C:\\Users\\..." on Windows (best-effort)
      - expands ~ and env vars
    Returns an absolute path string when possible.
    """
    s = str(p).strip()
    if not s:
        raise ValueError("file_path cannot be empty")

    s = os.path.expandvars(os.path.expanduser(s))

    # Handle "/C:/..." style on Windows
    if os.name == "nt":
        if s.startswith("/") and len(s) >= 4 and s[2] == ":":
            # "/C:/foo" -> "C:/foo"
            s = s[1:]

        # Handle WSL mount paths like "/mnt/c/foo"
        if s.lower().startswith("/mnt/") and len(s) > 6:
            drive = s[5].upper()
            rest = s[6:]
            # "/mnt/c/foo/bar" -> "C:/foo/bar"
            s = f"{drive}:{rest}"

    try:
        return str(Path(s).resolve())
    except Exception:
        # fallback: return as-is if resolve fails for some reason
        return s


def _which_capa() -> str:
    """
    Find capa executable:
      - CAPA_PATH env var wins
      - else search PATH for 'capa' (or 'capa.exe' on Windows)
    """
    env = os.environ.get("CAPA_PATH")
    if env and env.strip():
        return env.strip()

    exe = "capa.exe" if os.name == "nt" else "capa"
    found = shutil.which(exe)
    if not found:
        # also try plain "capa" even on Windows in case user has it that way
        found = shutil.which("capa")
    if not found:
        raise FileNotFoundError(
            "Could not find capa on PATH. Install capa or set CAPA_PATH to the capa executable."
        )
    return found


@dataclass
class CapaHelpCaps:
    has_rules_short: bool = False    # "-r"
    has_rules_long: bool = False     # "--rules"
    has_sigs_short: bool = False     # "-s"
    has_sigs_long: bool = False      # "--signatures" / "--sigs" / etc.
    has_json_short: bool = False     # "-j"
    has_json_long: bool = False      # "--json"
    has_format_long: bool = False    # "--format"
    has_output_long: bool = False    # "--output"
    has_stdout_default: bool = True  # assume stdout if no output flag needed


_HELP_CACHE: Optional[Tuple[str, CapaHelpCaps]] = None


def _probe_capa_help(capa_exe: str) -> CapaHelpCaps:
    """
    Run 'capa -h' and detect supported flags.
    Cached per-process.
    """
    global _HELP_CACHE
    if _HELP_CACHE and _HELP_CACHE[0] == capa_exe:
        return _HELP_CACHE[1]

    caps = CapaHelpCaps()

    try:
        proc = subprocess.run(
            [capa_exe, "-h"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        help_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        help_text = ""

    ht = help_text

    caps.has_rules_short = "-r" in ht
    caps.has_rules_long = "--rules" in ht

    caps.has_sigs_short = "-s" in ht
    # capa has used different long names over time; check a few.
    caps.has_sigs_long = any(x in ht for x in ["--signatures", "--sigs", "--signature"])

    caps.has_json_short = "-j" in ht
    caps.has_json_long = "--json" in ht

    caps.has_format_long = "--format" in ht
    caps.has_output_long = "--output" in ht

    _HELP_CACHE = (capa_exe, caps)
    return caps


def _build_capa_cmd(
    capa_exe: str,
    file_path: str,
    rules_dir: Optional[str],
    sigs_dir: Optional[str],
    output_format: str,
    output_file: Optional[str],
    extra_args: Optional[List[str]],
) -> List[str]:
    caps = _probe_capa_help(capa_exe)

    cmd: List[str] = [capa_exe]

    # Rules directory
    if rules_dir:
        if caps.has_rules_short:
            cmd += ["-r", rules_dir]
        elif caps.has_rules_long:
            cmd += ["--rules", rules_dir]
        else:
            # If capa doesn't support flags we detected, still try "-r" as a best-effort.
            cmd += ["-r", rules_dir]

    # FLIRT / signatures directory (if your workflow uses it)
    if sigs_dir:
        if caps.has_sigs_short:
            cmd += ["-s", sigs_dir]
        elif caps.has_sigs_long:
            # Pick one plausible long name if present; otherwise fall back to -s
            # (We can't know exact long spelling without full help parsing.)
            cmd += ["-s", sigs_dir]
        else:
            cmd += ["-s", sigs_dir]

    fmt = (output_format or "json").strip().lower()

    # Output selection:
    # - If user asked for JSON, prefer JSON flags or format flags if present.
    if fmt == "json":
        if caps.has_json_long:
            cmd += ["--json"]
        elif caps.has_json_short:
            cmd += ["-j"]
        elif caps.has_format_long:
            cmd += ["--format", "json"]
        # else: rely on whatever default capa uses and we'll try to parse stdout anyway.
    else:
        # For non-json formats, try --format if available.
        if caps.has_format_long:
            cmd += ["--format", fmt]

    # Output file (optional)
    if output_file:
        if caps.has_output_long:
            cmd += ["--output", output_file]
        else:
            # If no output flag, we won't force it; caller can redirect externally if needed.
            pass

    # Target
    cmd += [file_path]

    # Extra args
    if extra_args:
        cmd += list(extra_args)

    return cmd


def _run_subprocess(cmd: List[str], timeout_sec: int) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        return {
            "ok": proc.returncode == 0,
            "return_code": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "return_code": None,
            "stdout": (e.stdout or "") if hasattr(e, "stdout") else "",
            "stderr": (e.stderr or "") if hasattr(e, "stderr") else "",
            "error": f"timeout after {timeout_sec}s",
        }
    except Exception as e:
        return {
            "ok": False,
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "error": f"subprocess error: {type(e).__name__}: {e}",
        }


def _best_effort_parse_json(stdout: str) -> Optional[Any]:
    """
    capa JSON output is usually a full JSON document.
    We'll try strict parsing first; if that fails, no parse.
    """
    s = (stdout or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


# ----------------------------
# MCP tool
# ----------------------------

@mcp.tool
def callCapa(
    file_path: str,
    rules_dir: Optional[str] = None,
    sigs_dir: Optional[str] = None,
    output_format: str = "json",
    timeout_sec: int = 120,
    output_file: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run capa on the given file and return output.

    Params:
      file_path: path to binary/sample to analyze
      rules_dir: capa rules directory (or set CAPA_RULES_DIR env var)
      sigs_dir: capa FLIRT signatures directory (or set CAPA_SIGS_DIR env var)
      output_format: "json" (default) or another format supported by your capa build
      timeout_sec: subprocess timeout (default 120s)
      output_file: optional output file path (only used if capa supports --output)
      extra_args: optional list of additional capa args (advanced)

    Returns:
      dict with command, return code, stdout/stderr, and parsed_json when available
    """
    capa_exe = _which_capa()

    fp = _normalize_path(file_path)

    # env var defaults
    if not rules_dir:
        rules_dir = os.environ.get("CAPA_RULES_DIR") or None
    if not sigs_dir:
        sigs_dir = os.environ.get("CAPA_SIGS_DIR") or None

    if rules_dir:
        rules_dir = _normalize_path(rules_dir)
    if sigs_dir:
        sigs_dir = _normalize_path(sigs_dir)
    if output_file:
        output_file = _normalize_path(output_file)

    cmd = _build_capa_cmd(
        capa_exe=capa_exe,
        file_path=fp,
        rules_dir=rules_dir,
        sigs_dir=sigs_dir,
        output_format=output_format,
        output_file=output_file,
        extra_args=extra_args,
    )

    res = _run_subprocess(cmd, timeout_sec=timeout_sec)

    parsed = None
    if (output_format or "").strip().lower() == "json" and res.get("stdout"):
        parsed = _best_effort_parse_json(res["stdout"])

    return {
        "ok": res.get("ok", False),
        "command": cmd,
        "return_code": res.get("return_code"),
        "error": res.get("error"),
        "stdout": res.get("stdout", ""),
        "stderr": res.get("stderr", ""),
        "parsed_json": parsed,
        "notes": {
            "capa_exe": capa_exe,
            "rules_dir": rules_dir,
            "sigs_dir": sigs_dir,
        },
    }


# ----------------------------
# CLI entrypoint (stdio/sse)
# ----------------------------

def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="FastMCP server for capa")
    ap.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    ap.add_argument("--mcp-host", default="127.0.0.1")
    ap.add_argument("--mcp-port", type=int, default=8090)
    return ap.parse_args()


def main() -> None:
    args = _parse_args()

    if args.transport == "stdio":
        mcp.run_stdio()
    else:
        mcp.run_sse(host=args.mcp_host, port=args.mcp_port)


if __name__ == "__main__":
    main()
