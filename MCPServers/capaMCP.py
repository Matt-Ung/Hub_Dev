#!/usr/bin/env python3
"""
capaMCP_thesis.py

FastMCP server that exposes Mandiant capa via:
- runCapa(command: str, rules_dir: Optional[str] = None): execute a caller-supplied capa command string (argv[0] must be capa)
  - If rules_dir is not provided, the server will try:
      1) CAPA_RULES_DIR env var
      2) ./MCPServers/capa-rules (relative to CWD)
      3) MCPServers/capa-rules relative to this file (and one directory up)
  - If a rules directory is found and the command does NOT already include -r/--rules, the server injects -r <rules_dir>.
- capaHelp(): returns `capa --help` output for flag discovery

Notes:
- Uses subprocess with shell=False (argv is parsed via shlex).
- Intentionally lightweight and "run/help"-only, mirroring flareFlossMCP.py.
"""

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "capa_mcp",
    instructions="MCP server that executes Mandiant capa from a provided command string (with optional rules dir injection).",
)

CAPA_COMPACT_MAX_RULES = int(os.environ.get("CAPA_COMPACT_MAX_RULES", "80"))
CAPA_STREAM_MAX_CHARS = int(os.environ.get("CAPA_STREAM_MAX_CHARS", "25000"))

# ----------------------------
# Command parsing + validation
# ----------------------------

def _split_command(command: str) -> List[str]:
    command = (command or "").strip()
    if not command:
        return []

    if os.name == "nt":
        return shlex.split(command, posix=False)
    return shlex.split(command, posix=True)


def _is_capa_argv0(argv0: str) -> bool:
    if not argv0:
        return False
    base = os.path.basename(argv0).lower()
    return base in ("capa", "capa.exe")


def _find_rules_dir(user_rules_dir: Optional[str]) -> Optional[str]:
    """
    Resolve rules directory (best-effort):
      - explicit tool arg wins
      - then CAPA_RULES_DIR env var
      - then ./MCPServers/capa-rules relative to CWD
      - then MCPServers/capa-rules relative to this file (and one directory up)
    Returns an absolute path string if found and looks like a directory; otherwise None.
    """
    candidates: List[Path] = []

    if user_rules_dir and str(user_rules_dir).strip():
        candidates.append(Path(os.path.expandvars(os.path.expanduser(str(user_rules_dir).strip()))))

    env = os.environ.get("CAPA_RULES_DIR")
    if env and env.strip():
        candidates.append(Path(os.path.expandvars(os.path.expanduser(env.strip()))))

    # Relative to CWD
    candidates.append(Path.cwd() / "MCPServers" / "capa-rules")

    # Relative to this file
    here = Path(__file__).resolve().parent
    candidates.append(here / "MCPServers" / "capa-rules")
    candidates.append(here.parent / "MCPServers" / "capa-rules")
    candidates.append(here / "capa-rules")
    candidates.append(here.parent / "capa-rules")

    for c in candidates:
        try:
            if c.exists() and c.is_dir():
                return str(c.resolve())
        except Exception:
            continue
    return None


def _argv_has_rules_flag(argv: List[str]) -> bool:
    # cheap check: handles "-r PATH" and "--rules PATH" and "-rPATH"
    for a in argv:
        if a == "-r" or a.startswith("-r"):
            return True
        if a == "--rules" or a.startswith("--rules="):
            return True
    return False


def _inject_rules(argv: List[str], rules_dir: Optional[str]) -> List[str]:
    """If rules_dir is available and argv does not already specify rules, inject "-r <rules_dir>"."""
    if not rules_dir:
        return argv
    if _argv_has_rules_flag(argv):
        return argv
    if len(argv) < 1:
        return argv
    return [argv[0], "-r", rules_dir] + argv[1:]


def _argv_has_signatures_flag(argv: List[str]) -> bool:
    for a in argv:
        if a == "-s" or a.startswith("-s"):
            return True
        if a == "--signatures" or a.startswith("--signatures="):
            return True
    return False


def _inject_signatures(argv: List[str], signatures_dir: Optional[str]) -> List[str]:
    if not signatures_dir:
        return argv
    if _argv_has_signatures_flag(argv):
        return argv
    if len(argv) < 1:
        return argv
    return [argv[0], "-s", signatures_dir] + argv[1:]


def _find_signatures_dir() -> Optional[str]:
    env = os.environ.get("CAPA_SIGS_DIR")
    candidates: List[Path] = []
    if env and env.strip():
        candidates.append(Path(os.path.expandvars(os.path.expanduser(env.strip()))))

    candidates.append(Path.cwd() / "MCPServers" / "capa-sigs")
    here = Path(__file__).resolve().parent
    candidates.append(here / "MCPServers" / "capa-sigs")
    candidates.append(here.parent / "MCPServers" / "capa-sigs")
    candidates.append(here / "capa-sigs")
    candidates.append(here.parent / "capa-sigs")

    for c in candidates:
        try:
            if c.exists() and c.is_dir():
                return str(c.resolve())
        except Exception:
            continue
    return None


def _remove_json_flags(argv: List[str]) -> List[str]:
    out: List[str] = []
    for a in argv:
        if a in {"-j", "--json"}:
            continue
        out.append(a)
    return out


def _looks_like_unquoted_spaced_target(argv: List[str]) -> bool:
    # Common case: command uses `--` and the target path with spaces gets split into multiple tokens.
    if "--" in argv:
        idx = argv.index("--")
        trailing = [a for a in argv[idx + 1 :] if a.strip()]
        if len(trailing) > 1:
            return True

    # Heuristic: adjacent non-flag tokens that resemble a split file path.
    suspicious_exts = (".exe", ".dll", ".sys", ".bin", ".dat", ".json", ".txt", ".zip", ".7z", ".msi")
    for i in range(1, len(argv) - 1):
        left, right = argv[i], argv[i + 1]
        if left.startswith("-") or right.startswith("-"):
            continue
        combined = f"{left} {right}".lower()
        if (":" in left or "\\" in left or "/" in left) and any(ext in combined for ext in suspicious_exts):
            return True
    return False


def _truncate_text(text: str, max_chars: int = CAPA_STREAM_MAX_CHARS) -> str:
    value = text or ""
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n...[truncated]..."


def _parse_json_maybe(text: str) -> Optional[Dict[str, Any]]:
    payload = (text or "").strip()
    if not payload:
        return None
    try:
        parsed = json.loads(payload)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        pass

    # Some tools prefix warnings before JSON output.
    start = payload.find("{")
    end = payload.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(payload[start : end + 1])
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None
    return None


def _list_preview(value: Any, max_items: int = 3) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value[:max_items]:
        if isinstance(item, str):
            out.append(item)
            continue
        if isinstance(item, dict):
            label = (
                item.get("id")
                or item.get("name")
                or item.get("technique")
                or item.get("objective")
                or item.get("tactic")
            )
            if label:
                out.append(str(label))
            else:
                out.append(_truncate_text(json.dumps(item, ensure_ascii=False), max_chars=200))
            continue
        out.append(str(item))
    return out


def _match_count(rule_body: Any) -> Optional[int]:
    if not isinstance(rule_body, dict):
        return None
    matches = rule_body.get("matches")
    if isinstance(matches, list):
        return len(matches)
    if isinstance(matches, dict):
        return len(matches)
    return None


def _compact_capa_payload(payload: Dict[str, Any], max_rules: int) -> Dict[str, Any]:
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    sample = meta.get("sample") if isinstance(meta.get("sample"), dict) else {}
    analysis = meta.get("analysis") if isinstance(meta.get("analysis"), dict) else {}
    rules_obj = payload.get("rules") if isinstance(payload.get("rules"), dict) else {}

    rows: List[Dict[str, Any]] = []
    for idx, (rule_name, rule_body) in enumerate(rules_obj.items()):
        if idx >= max_rules:
            break

        rule_meta = {}
        if isinstance(rule_body, dict) and isinstance(rule_body.get("meta"), dict):
            rule_meta = rule_body.get("meta") or {}

        row: Dict[str, Any] = {
            "name": str(rule_name),
            "namespace": rule_meta.get("namespace"),
        }

        mc = _match_count(rule_body)
        if mc is not None:
            row["match_count"] = mc

        if rule_meta.get("scopes") is not None:
            row["scopes"] = rule_meta.get("scopes")

        attack = _list_preview(rule_meta.get("att&ck"), max_items=3)
        if attack:
            row["attck"] = attack

        mbc = _list_preview(rule_meta.get("mbc"), max_items=3)
        if mbc:
            row["mbc"] = mbc

        rows.append(row)

    return {
        "meta": {
            "sample": {
                "path": sample.get("path"),
                "sha256": sample.get("sha256"),
                "md5": sample.get("md5"),
            },
            "analysis": {
                "format": analysis.get("format"),
                "arch": analysis.get("arch"),
                "os": analysis.get("os"),
                "extractor": analysis.get("extractor"),
            },
        },
        "summary": {
            "total_rules": len(rules_obj),
            "returned_rules": len(rows),
            "truncated": len(rules_obj) > len(rows),
        },
        "rules": rows,
    }


def _try_get_capa_help(timeout_sec: int = 3, max_chars: int = 1800) -> Optional[str]:
    """Best-effort: capture a short snippet of `capa --help` to embed into tool descriptions."""
    try:
        r = subprocess.run(
            ["capa", "--help"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        text = (r.stdout or "") + ("\n" + (r.stderr or "") if (r.stderr or "").strip() else "")
        text = text.strip()
        if not text:
            return None
        if len(text) > max_chars:
            text = text[:max_chars] + "\n...[truncated]..."
        return text
    except Exception:
        return None


_HELP_SNIPPET = _try_get_capa_help()

RUN_CAPA_DESCRIPTION = (
    "Execute Mandiant capa using a caller-supplied command string.\n\n"
    "Usage:\n"
    "  - Provide the FULL command as one string (e.g., `capa -- sample.exe`).\n"
    "  - argv[0] must be `capa` (or `capa.exe`).\n"
    "  - If a file path contains spaces, wrap it in double quotes.\n"
    "    Example: `capa -- \"C:\\Users\\Alice\\Desktop\\sample with spaces.exe\"`.\n"
    "  - Prefer using `--` before the target path.\n"
    "  - If you pass rules_dir (or the server finds ./MCPServers/capa-rules), and your command does not include -r/--rules,\n"
    "    the server will inject `-r <rules_dir>` automatically.\n"
    "  - `output_mode='json_compact'` (default) forces JSON output and returns a reduced capability summary.\n"
    "  - Use `output_mode='json_full'` to return full capa JSON, or `output_mode='text'` for raw text.\n"
    "  - For the full flag list, call `capaHelp` (runs `capa --help`).\n\n"
    "  - Please use -t {communication, analysis, or execution} tags in your command to help categorize the command's purpose (these tags don't affect execution, just for your organization).\n\n"
    "Notes:\n"
    "  - Execution uses subprocess with shell=False (argv is parsed via shlex).\n"
)

if _HELP_SNIPPET:
    RUN_CAPA_DESCRIPTION += "\nCAPA --help (snippet):\n" + _HELP_SNIPPET


# ----------------------------
# MCP tools
# ----------------------------

@mcp.tool(description=RUN_CAPA_DESCRIPTION)
def runCapa(
    command: str,
    rules_dir: Optional[str] = None,
    timeout_sec: int = 300,
    output_mode: Literal["json_compact", "json_full", "text"] = "json_compact",
    max_rules: int = CAPA_COMPACT_MAX_RULES,
) -> str:
    """Execute capa and return a human-readable result summary."""
    try:
        argv = _split_command(command)
        if not argv:
            return "Error: empty command string."

        if not _is_capa_argv0(argv[0]):
            return f"Error: first argument must be 'capa' (or 'capa.exe'). Got: {argv[0]!r}"
        if _looks_like_unquoted_spaced_target(argv):
            return (
                "Error: command likely contains an unquoted path with spaces.\n"
                "Wrap the target path in double quotes.\n"
                "Example: capa -- \"C:\\Users\\Alice\\Desktop\\sample with spaces.exe\""
            )

        resolved_rules = _find_rules_dir(rules_dir)
        argv = _inject_rules(argv, resolved_rules)
        argv = _inject_signatures(argv, _find_signatures_dir())

        mode = (output_mode or "json_compact").strip().lower()
        if mode not in {"json_compact", "json_full", "text"}:
            return f"Error: invalid output_mode={output_mode!r}. Use one of: json_compact, json_full, text."

        argv = _remove_json_flags(argv)
        if mode in {"json_compact", "json_full"}:
            argv = [argv[0], "--json"] + argv[1:]

        r = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        
        cmd_str = " ".join(shlex.quote(a) for a in argv)

        if mode == "text":
            return (
                "capa execution complete.\n"
                f"rc={r.returncode}\n"
                f"rules_dir={'(none)' if not resolved_rules else resolved_rules}\n"
                f"command={cmd_str}\n"
                "stdout:\n"
                f"{_truncate_text(r.stdout or '')}\n"
                "stderr:\n"
                f"{_truncate_text(r.stderr or '')}"
            )

        parsed = _parse_json_maybe(r.stdout or "")
        if parsed is None:
            return (
                "Error: expected JSON from capa but parsing failed.\n"
                f"rc={r.returncode}\n"
                f"command={cmd_str}\n"
                "stdout_snippet:\n"
                f"{_truncate_text(r.stdout or '', max_chars=2000)}\n"
                "stderr_snippet:\n"
                f"{_truncate_text(r.stderr or '', max_chars=2000)}"
            )

        envelope: Dict[str, Any] = {
            "status": "ok" if r.returncode == 0 else "error",
            "rc": r.returncode,
            "rules_dir": resolved_rules,
            "command": cmd_str,
            "stderr": _truncate_text(r.stderr or "", max_chars=3000),
        }
        if mode == "json_full":
            envelope["result"] = parsed
        else:
            safe_max_rules = max(1, int(max_rules))
            envelope["result"] = _compact_capa_payload(parsed, max_rules=safe_max_rules)

        return json.dumps(envelope, indent=2, ensure_ascii=False)

    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        return (
            "Error: capa execution timed out.\n"
            f"timeout_sec={timeout_sec}\n"
            "stdout:\n"
            f"{out}\n"
            "stderr:\n"
            f"{err}"
        )
    except FileNotFoundError:
        return "Error: `capa` not found on PATH. Install capa and ensure `capa` is on PATH."
    except Exception as e:
        logger.exception("runCapa failed")
        return f"Error: {e}"


@mcp.tool(description="Return capa CLI help output (runs `capa --help`) so clients can discover flags.")
def capaHelp(timeout_sec: int = 5) -> str:
    try:
        r = subprocess.run(
            ["capa", "--help"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        return (
            "capa --help\n"
            f"rc={r.returncode}\n"
            "stdout:\n"
            f"{r.stdout or ''}\n"
            "stderr:\n"
            f"{r.stderr or ''}"
        )
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        err = e.stderr if isinstance(e.stderr, str) else ""
        return (
            "Error: `capa --help` timed out.\n"
            f"timeout_sec={timeout_sec}\n"
            "stdout:\n"
            f"{out}\n"
            "stderr:\n"
            f"{err}"
        )
    except FileNotFoundError:
        return "Error: `capa` not found on PATH. Install capa and ensure `capa` is on PATH."
    except Exception as e:
        logger.exception("capaHelp failed")
        return f"Error: {e}"


# ----------------------------
# CLI / main (server args only)
# ----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server for capa (thesis tool)")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8090,
        help="Port to run MCP server on (only used for sse), default: 8090",
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

    logger.info(f"sys.platform={sys.platform} transport={args.transport}")

    if args.transport == "sse":
        try:
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8090
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
