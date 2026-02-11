"""
hashdbMCP.py

FastMCP server that exposes a `resolve_hash_in_hashdb_to_plain(algorithm, hash_value)` tool.

Key features:
- Accepts `hash_value` as int, decimal string, or hex string (with or without `0x`)
- Normalizes and validates inputs with clear, structured error responses
- Queries HashDB over HTTP and returns structured JSON (`ok: true/false`)
- Timeouts + HTTP error handling with useful diagnostics (status/body snippet/url)
- Configurable HashDB base URL via `HASHDB_BASE_URL` environment variable
- Preserves a simple CLI for running the MCP server:
    --transport {stdio,sse}
    --mcp-host
    --mcp-port
"""
# from __future__ import annotations
import argparse
from typing import Any, Dict, Union
import os
import requests
from fastmcp import FastMCP
import logging
import platform
import sys

logger = logging.getLogger(__name__)

mcp = FastMCP("hashdb")

# Configure your HashDB base URL (set env var or hardcode)
HASHDB_BASE_URL = os.getenv("HASHDB_BASE_URL", "https://hashdb.openanalysis.net").rstrip("/")
HASH_URL = f"{HASHDB_BASE_URL}/hash"

def _normalize_hash_to_int(hash_value: Union[int, str]) -> int:
    if hash_value is None:
        raise ValueError("hash_value cannot be None")

    if isinstance(hash_value, int):
        return hash_value

    s = str(hash_value).strip()
    if not s:
        raise ValueError("hash_value cannot be an empty string")

    # decimal first, then hex
    try:
        return int(s, 10)
    except ValueError:
        pass

    # hex: allow with or without 0x
    s2 = s[2:] if s.lower().startswith("0x") else s
    return int(s2, 16)


@mcp.tool()
def resolve_hash_in_hashdb_to_plain(algorithm: str, hash_value: Union[int, str]) -> Dict[str, Any]:
    """
    MCP tool: Given an algorithm and a single hash (int/decimal/hex string),
    query HashDB and return the JSON response or a structured error.
    """
    try:
        h_int = _normalize_hash_to_int(hash_value)
    except Exception as e:
        return {
            "ok": False,
            "error": {
                "type": "invalid_argument",
                "message": str(e),
                "algorithm": algorithm,
                "hash_value": hash_value,
            },
        }

    url = f"{HASH_URL}/{algorithm}/{h_int}"

    try:
        resp = requests.get(url, timeout=10)
        # If HashDB returns non-2xx, surface status + body snippet
        if not resp.ok:
            return {
                "ok": False,
                "error": {
                    "type": "http_error",
                    "status_code": resp.status_code,
                    "message": f"HashDB request failed: {resp.status_code}",
                    "url": url,
                    "body": resp.text[:1000],
                },
            }

        data = resp.json()
        return {
            "ok": True,
            "url": url,
            "algorithm": algorithm,
            "hash_int": h_int,
            "result": data,
        }

    except requests.Timeout:
        return {
            "ok": False,
            "error": {
                "type": "timeout",
                "message": "HashDB request timed out",
                "url": url,
            },
        }
    except Exception as e:
        return {
            "ok": False,
            "error": {
                "type": "exception",
                "message": str(e),
                "url": url,
            },
        }

# ----------------------------
# CLI / main (your existing argparse preserved)
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="MCP server for Strings")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host to run MCP server on (only used for sse), default: 127.0.0.1",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=8084,
        help="Port to run MCP server on (only used for sse), default: 8084",
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

    # Logging setup
    log_level = getattr(logging, args.log_level, logging.INFO)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    logger.info(f"Platform: {platform.platform()} (sys.platform={sys.platform})")
    logger.info(f"Using transport: {args.transport}")

    if args.transport == "sse":
        try:
            # Configure MCP settings
            mcp.settings.log_level = args.log_level
            mcp.settings.host = args.mcp_host or "127.0.0.1"
            mcp.settings.port = args.mcp_port or 8084

            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        # stdio transport
        mcp.run()

if __name__ == "__main__":
    main()
