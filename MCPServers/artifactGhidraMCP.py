#!/usr/bin/env python3
"""
Read-only MCP server that serves precomputed Ghidra analysis artifacts.

This is intended for batch/offline testing where the normal live Ghidra plugin
would otherwise require manually opening each sample in the GUI.
"""

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "artifact_ghidra_mcp",
    instructions=(
        "Read-only Ghidra artifact server backed by a structured analysis bundle "
        "produced from headless Ghidra export."
    ),
)

_BUNDLE: "ArtifactBundle | None" = None
_FUNCTION_SELECTOR_WITH_ADDRESS_RE = re.compile(
    r"^\s*(?P<name>.+?)\s*@\s*(?P<address>(?:0x)?[0-9A-Fa-f]+)\s*$"
)


def _paginate(items: List[Any], offset: int = 0, limit: int = 100) -> List[Any]:
    start = max(0, int(offset or 0))
    size = max(0, int(limit or 0))
    if size <= 0:
        return []
    return list(items[start : start + size])


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class ArtifactBundle:
    def __init__(self, bundle_dir: Path):
        self.bundle_dir = bundle_dir.resolve()
        analysis_path = self.bundle_dir / "ghidra_analysis.json"
        if not analysis_path.exists():
            raise FileNotFoundError(f"ghidra artifact not found: {analysis_path}")

        self.analysis_path = analysis_path
        self.data = _read_json(analysis_path)
        self.program = self.data.get("program") if isinstance(self.data.get("program"), dict) else {}
        self.counts = self.data.get("counts") if isinstance(self.data.get("counts"), dict) else {}
        self.sections = list(self.data.get("sections") or [])
        self.imports = list(self.data.get("imports") or [])
        self.exports = list(self.data.get("exports") or [])
        self.strings = list(self.data.get("strings") or [])
        self.functions = list(self.data.get("functions") or [])
        self.call_graph = list(self.data.get("call_graph") or [])
        self.refs_to = self.data.get("refs_to") if isinstance(self.data.get("refs_to"), dict) else {}
        self.refs_from = self.data.get("refs_from") if isinstance(self.data.get("refs_from"), dict) else {}
        self.data_items = list(self.data.get("data_items") or [])
        self.root_functions = list(self.data.get("root_functions") or [])

        self.functions_by_address: Dict[str, Dict[str, Any]] = {}
        self.functions_by_name: Dict[str, Dict[str, Any]] = {}
        for function in self.functions:
            if not isinstance(function, dict):
                continue
            address = str(function.get("address") or function.get("entry") or "").strip()
            name = str(function.get("name") or "").strip()
            if address:
                self.functions_by_address[address.lower()] = function
            if name:
                self.functions_by_name[name] = function

    def function_by_address(self, address: str) -> Dict[str, Any] | None:
        return self.functions_by_address.get(str(address or "").strip().lower())

    def function_by_name(self, name: str) -> Dict[str, Any] | None:
        return self.functions_by_name.get(str(name or "").strip())


def _bundle() -> ArtifactBundle:
    if _BUNDLE is None:
        raise RuntimeError("artifact bundle not initialized")
    return _BUNDLE


def _read_only_error(tool_name: str) -> str:
    return (
        f"Error: {tool_name} is unavailable because artifact-backed Ghidra MCP is read-only. "
        "Use a live Ghidra session if you need to mutate names, comments, or types."
    )


def _canonicalize_function_selector(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    match = _FUNCTION_SELECTOR_WITH_ADDRESS_RE.match(candidate)
    if match:
        return match.group("name").strip()
    return candidate


def _normalize_pagination_aliases(
    *,
    offset: int = 0,
    limit: int = 100,
    pageOffset: int | None = None,
    maxResults: int | None = None,
) -> tuple[int, int]:
    resolved_offset = int(pageOffset) if pageOffset is not None else int(offset or 0)
    resolved_limit = int(maxResults) if maxResults is not None else int(limit or 0)
    return resolved_offset, resolved_limit


@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list[str]:
    return _paginate([str(item.get("name") or "") for item in _bundle().functions if item.get("name")], offset, limit)


@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    return _paginate([], offset, limit)


@mcp.tool()
def decompile_function(name: str) -> str:
    canonical_name = _canonicalize_function_selector(name)
    function = _bundle().function_by_name(canonical_name)
    if not function:
        return f"Error: function not found: {canonical_name or name}"
    return str(function.get("decompilation") or function.get("decompiled") or "")


@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    return _read_only_error("rename_function")


@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    return _read_only_error("rename_data")


@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    return _paginate(_bundle().sections, offset, limit)


@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    return _paginate(_bundle().imports, offset, limit)


@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    return _paginate(_bundle().exports, offset, limit)


@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    return _paginate([], offset, limit)


@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    items = _bundle().data_items or _bundle().strings
    return _paginate(items, offset, limit)


@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    canonical_query = _canonicalize_function_selector(query)
    needle = str(canonical_query or "").strip().lower()
    if not needle:
        return ["Error: query string is required"]
    matches = [item for item in _bundle().functions if needle in str(item.get("name") or "").lower()]
    return _paginate(matches, offset, limit)


@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    return _read_only_error("rename_variable")


@mcp.tool()
def get_function_by_address(address: str) -> dict[str, Any] | str:
    function = _bundle().function_by_address(address)
    if not function:
        return f"Error: function not found at address: {address}"
    return function


@mcp.tool()
def get_current_address() -> str:
    return "Error: no current GUI selection in artifact-backed mode"


@mcp.tool()
def get_current_function() -> str:
    return "Error: no current GUI selection in artifact-backed mode"


@mcp.tool()
def list_functions() -> list:
    return list(_bundle().functions)


@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    function = _bundle().function_by_address(address)
    if not function:
        return f"Error: function not found at address: {address}"
    return str(function.get("decompilation") or function.get("decompiled") or "")


@mcp.tool()
def disassemble_function(address: str) -> list:
    function = _bundle().function_by_address(address)
    if not function:
        return [f"Error: function not found at address: {address}"]
    return list(function.get("disassembly") or [])


@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    return _read_only_error("set_decompiler_comment")


@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    return _read_only_error("set_disassembly_comment")


@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    return _read_only_error("rename_function_by_address")


@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    return _read_only_error("set_function_prototype")


@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    return _read_only_error("set_local_variable_type")


@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, pageOffset: int | None = None, maxResults: int | None = None) -> list:
    offset, limit = _normalize_pagination_aliases(
        offset=offset,
        limit=limit,
        pageOffset=pageOffset,
        maxResults=maxResults,
    )
    refs = _bundle().refs_to.get(str(address or "").strip(), [])
    return _paginate(list(refs), offset, limit)


@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, pageOffset: int | None = None, maxResults: int | None = None) -> list:
    offset, limit = _normalize_pagination_aliases(
        offset=offset,
        limit=limit,
        pageOffset=pageOffset,
        maxResults=maxResults,
    )
    refs = _bundle().refs_from.get(str(address or "").strip(), [])
    return _paginate(list(refs), offset, limit)


@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, pageOffset: int | None = None, maxResults: int | None = None) -> list:
    offset, limit = _normalize_pagination_aliases(
        offset=offset,
        limit=limit,
        pageOffset=pageOffset,
        maxResults=maxResults,
    )
    canonical_name = _canonicalize_function_selector(name)
    function = _bundle().function_by_name(canonical_name)
    if not function:
        return [f"Error: function not found: {canonical_name or name}"]
    address = str(function.get("address") or function.get("entry") or "").strip()
    refs = _bundle().refs_to.get(address, [])
    return _paginate(list(refs), offset, limit)


@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    strings = list(_bundle().strings)
    if filter:
        needle = str(filter).lower()
        strings = [item for item in strings if needle in str(item.get("value") or item.get("text") or "").lower()]
    return _paginate(strings, offset, limit)


@mcp.tool()
def get_program_info() -> dict[str, Any]:
    bundle = _bundle()
    return {
        "program": bundle.program,
        "counts": bundle.counts,
        "sections": bundle.sections,
        "root_functions": bundle.root_functions,
        "source": "artifact_bundle",
        "bundle_dir": str(bundle.bundle_dir),
    }


@mcp.tool()
def get_call_graph(maxDepth: int, maxNodes: int = 3) -> list:
    max_depth = max(1, int(maxDepth or 1))
    max_nodes = max(1, int(maxNodes or 1))
    budget = max_nodes * max_depth
    return list(_bundle().call_graph[:budget])


def main() -> None:
    parser = argparse.ArgumentParser(description="Artifact-backed Ghidra MCP server")
    parser.add_argument("--bundle-dir", required=True, help="Path to a sample artifact bundle directory")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8094)
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    global _BUNDLE
    _BUNDLE = ArtifactBundle(Path(args.bundle_dir))
    logger.info("Loaded artifact bundle from %s", _BUNDLE.analysis_path)

    if args.transport == "stdio":
        mcp.run(show_banner=False)
    else:
        mcp.run(transport="sse", host=args.mcp_host, port=args.mcp_port, show_banner=False)


if __name__ == "__main__":
    main()
