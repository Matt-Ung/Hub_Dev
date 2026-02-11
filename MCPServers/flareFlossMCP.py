#!/usr/bin/env python3
"""
flareFlossMCP.py

FastMCP server that exposes FLOSS via a tool.

- Requires: pip install flare-floss  (FLOSS requires Python >= 3.10)
- Uses FLOSS CLI with JSON output (-j) for stable integration.
- Normalizes Windows/MSYS/WSL-ish paths like "/C:/..." and "/mnt/c/..."

References:
- FLOSS usage flags (-j, -n, --only/--no, etc.): https://raw.githubusercontent.com/mandiant/flare-floss/master/doc/usage.md
- FLOSS string types (static/stack/tight/decoded): https://github.com/mandiant/flare-floss
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from fastmcp import FastMCP

logger = logging.getLogger(__name__)
mcp = FastMCP("flare_floss_mcp", instructions="MCP server that provides FLOSS (flare-floss) string extraction.")


# ----------------------------
# Platform + path normalization
# ----------------------------
IS_WINDOWS = sys.platform.startswith("win")

_DRIVE_RE = re.compile(r"^/([A-Za-z]):/")          # "/C:/Users/..." (MSYS-style)
_MNT_RE = re.compile(r"^/mnt/([A-Za-z])/(.*)")     # "/mnt/c/Users/..." (WSL-style)


def normalize_path_for_windows(p: str) -> str:
    """
    Convert common pseudo-posix paths into a Windows-friendly path string:
      - "/C:/Users/x" -> "C:/Users/x"
      - "/mnt/c/Users/x" -> "C:\\Users\\x"
    """
    p = (p or "").strip()
    if not p:
        return p

    m = _DRIVE_RE.match(p)
    if m:
        return p[1:]  # strip leading "/"

    m = _MNT_RE.match(p)
    if m:
        drive = m.group(1).upper()
        rest = m.group(2).replace("/", "\\")
        return f"{drive}:\\{rest}"

    return p


def normalize_input_path(p: str) -> str:
    p = (p or "").strip()
    if not p:
        return p

    if IS_WINDOWS:
        p = normalize_path_for_windows(p)

    # Expand user/relative
    try:
        return str(Path(p).expanduser().resolve())
    except Exception:
        return p


def file_exists(p: str) -> bool:
    try:
        return Path(p).exists()
    except Exception:
        return False


def split_csv_arg(s: str) -> List[str]:
    """
    Parse a comma/space-separated list, e.g. "stack,tight" or "stack tight".
    """
    s = (s or "").strip()
    if not s:
        return []
    # allow commas or whitespace
    parts = re.split(r"[,\s]+", s)
    return [p for p in (x.strip() for x in parts) if p]


# ----------------------------
# FLOSS invocation
# ----------------------------
def floss_cmd_base() -> List[str]:
    """
    Prefer the installed `floss` console script.
    If missing, you can still try `python -m floss` but that's not guaranteed.
    """
    if shutil.which("floss"):
        return ["floss"]

    # Fallback attempt: some installs might support module execution.
    # If this fails, we provide a clear error in the tool output.
    return [sys.executable, "-m", "floss"]


def run_floss_json(
    file_path: str,
    minimum_length: int = 4,
    only_types: Optional[List[str]] = None,
    no_types: Optional[List[str]] = None,
    fmt: str = "",
    verbose: bool = False,
) -> Tuple[int, str, str]:
    """
    Run FLOSS and return (rc, stdout, stderr). Uses -j JSON output.

    Based on FLOSS usage docs:
      - -j/--json: JSON output
      - -n/--minimum-length
      - --only {static,decoded,stack,tight}
      - --no {static,decoded,stack,tight}
      - -f/--format for shellcode formats (sc32/sc64/etc.)
    """
    only_types = only_types or []
    no_types = no_types or []

    if only_types and no_types:
        raise ValueError("only_types and no_types cannot both be set (FLOSS restriction).")

    cmd = floss_cmd_base()

    # JSON output
    cmd.append("-j")

    # min length
    if minimum_length and minimum_length != 4:
        cmd += ["-n", str(int(minimum_length))]

    # verbose (does not affect JSON, but can influence stderr logging in some modes)
    if verbose:
        cmd.append("-v")

    # optional format (shellcode)
    if fmt:
        cmd += ["-f", fmt]

    # string-type selection
    if only_types:
        cmd += ["--only", *only_types, "--"]
    elif no_types:
        cmd += ["--no", *no_types, "--"]
    else:
        # Always terminate options so weird filenames don't get parsed as flags
        cmd.append("--")

    cmd.append(file_path)

    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return r.returncode, r.stdout or "", r.stderr or ""


def summarize_floss_json(json_text: str, max_strings: int = 2000) -> str:
    """
    Convert FLOSS JSON to a stable, agent-friendly summary object (as JSON string).
    This keeps categories separate and caps output size.
    """
    data = json.loads(json_text)

    def cap_list(xs):
        if not isinstance(xs, list):
            return []
        return xs[:max_strings]

    # FLOSS JSON schema can evolve; we defensively pick common keys.
    # If keys differ, we include raw top-level keys to aid debugging.
    out = {
        "static_strings": cap_list(data.get("static_strings") or data.get("strings") or []),
        "decoded_strings": cap_list(data.get("decoded_strings") or []),
        "stack_strings": cap_list(data.get("stack_strings") or []),
        "tight_strings": cap_list(data.get("tight_strings") or []),
        "metadata_keys": sorted(list(data.keys())),
    }
    return json.dumps(out, ensure_ascii=False, indent=2)


# ----------------------------
# MCP tool
# ----------------------------
@mcp.tool()
def callFloss(
    file_path: str,
    minimum_length: int = 4,
    output: str = "summary",
    max_strings: int = 10,
    only: str = "",
    no: str = "",
    format: str = "",
    verbose: bool = False,
) -> str:
    """
    Run FLOSS against a file and return results.

    Args:
        file_path: Path to target file.
        minimum_length: Minimum string length (default 4).
        output: "json" (raw FLOSS JSON) or "summary" (capped/normalized JSON).
        max_strings: Max strings per category in summary output (default 10).
        only: Comma/space-separated types: static,decoded,stack,tight
        no:   Comma/space-separated types: static,decoded,stack,tight
        format: Optional FLOSS format (e.g. sc32/sc64) for shellcode.
        verbose: Enables FLOSS verbose mode (-v).

    Returns:
        JSON string: either raw FLOSS JSON or normalized summary JSON.
    """
    try:
        fp = normalize_input_path(file_path)
        if not fp or not file_exists(fp):
            return f"Error: file not found: {fp}"

        only_types = split_csv_arg(only)
        no_types = split_csv_arg(no)

        rc, out, err = run_floss_json(
            file_path=fp,
            minimum_length=minimum_length,
            only_types=only_types,
            no_types=no_types,
            fmt=format.strip(),
            verbose=verbose,
        )

        if rc != 0:
            # Give the caller actionable context without dumping huge logs.
            err_snip = err[-2000:] if err else ""
            out_snip = out[-2000:] if out else ""
            return (
                "Error: FLOSS returned non-zero exit status.\n"
                f"rc={rc}\n"
                f"cmd_hint={' '.join(floss_cmd_base())}\n"
                f"stderr_tail={err_snip}\n"
                f"stdout_tail={out_snip}\n"
            )

        if output.lower() == "summary":
            try:
                return summarize_floss_json(out, max_strings=max_strings)
            except Exception as e:
                return f"Error: FLOSS JSON parse failed: {e}\nRaw JSON tail:\n{out[-2000:]}"
        else:
            return out

    except Exception as e:
        logger.exception("callFloss failed")
        return f"Error: {e}"


# ----------------------------
# CLI / main (keeps your transport args)
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="MCP server for FLOSS (flare-floss)")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8083,
                        help="Port to run MCP server on (only used for sse), default: 8083")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Logging level, default: INFO")
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level, logging.INFO)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    logger.info(f"sys.platform={sys.platform} transport={args.transport}")
    logger.info("Note: FLOSS requires Python >= 3.10 and is installed via `pip install flare-floss`.")

    if args.transport == "sse":
        try:
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8083
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
