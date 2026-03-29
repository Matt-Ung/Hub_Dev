# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import argparse
import logging
import os
import sys
from pathlib import Path
from urllib.parse import urljoin

import requests
from fastmcp import FastMCP
import artifactGhidraMCP as artifact_mcp

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_FALLBACK_MODE = "live_only"
FALLBACK_MODES = {"live_only", "artifact_if_unavailable", "artifact_only"}
UNAVAILABLE_MARKERS = (
    "request failed:",
    "no program loaded",
    "error: no current gui selection",
)

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER
ghidra_fallback_mode = str(os.environ.get("GHIDRA_MCP_FALLBACK_MODE") or DEFAULT_FALLBACK_MODE).strip().lower()
ghidra_artifact_bundle_dir = str(os.environ.get("GHIDRA_ARTIFACT_BUNDLE_DIR") or "").strip()
_artifact_bundle_loaded = False


def _normalize_fallback_mode(raw_mode: str) -> str:
    candidate = str(raw_mode or DEFAULT_FALLBACK_MODE).strip().lower()
    if candidate not in FALLBACK_MODES:
        return DEFAULT_FALLBACK_MODE
    return candidate


def _artifact_fallback_enabled() -> bool:
    return bool(ghidra_artifact_bundle_dir) and ghidra_fallback_mode in {"artifact_if_unavailable", "artifact_only"}


def _ensure_artifact_bundle_loaded() -> bool:
    global _artifact_bundle_loaded
    if _artifact_bundle_loaded:
        return True
    bundle_dir = str(ghidra_artifact_bundle_dir or "").strip()
    if not bundle_dir:
        return False
    try:
        artifact_mcp._BUNDLE = artifact_mcp.ArtifactBundle(Path(bundle_dir))
        _artifact_bundle_loaded = True
        logger.info("Using artifact-backed Ghidra fallback bundle at %s", artifact_mcp._BUNDLE.analysis_path)
        return True
    except Exception as exc:
        logger.warning("Failed to initialize artifact-backed Ghidra fallback from %s: %s", bundle_dir, exc)
        return False


def _result_text(result) -> str:
    if isinstance(result, str):
        return result.lower()
    if isinstance(result, list):
        return "\n".join(str(item) for item in result).lower()
    if isinstance(result, dict):
        return str(result).lower()
    return str(result).lower()


def _live_result_unavailable(result) -> bool:
    text = _result_text(result)
    if not text:
        return False
    return any(marker in text for marker in UNAVAILABLE_MARKERS)


def _call_with_fallback(tool_name: str, live_callable, *artifact_args, **artifact_kwargs):
    if ghidra_fallback_mode == "artifact_only":
        if _ensure_artifact_bundle_loaded():
            return getattr(artifact_mcp, tool_name)(*artifact_args, **artifact_kwargs)
        return "Error: artifact-only mode requested, but GHIDRA_ARTIFACT_BUNDLE_DIR is not configured or failed to load."

    live_result = live_callable()
    if _artifact_fallback_enabled() and _live_result_unavailable(live_result) and _ensure_artifact_bundle_loaded():
        return getattr(artifact_mcp, tool_name)(*artifact_args, **artifact_kwargs)
    return live_result


def _read_only_mutation_error(tool_name: str) -> str:
    return (
        f"Error: {tool_name} is unavailable because live Ghidra is not available and the "
        "artifact/headless fallback path is read-only. Use a live Ghidra session for renames, "
        "comments, prototypes, or local type edits."
    )


def _call_mutating_with_fallback(tool_name: str, live_callable, *artifact_args, **artifact_kwargs):
    if ghidra_fallback_mode == "artifact_only":
        return _read_only_mutation_error(tool_name)

    live_result = live_callable()
    if _live_result_unavailable(live_result) and ghidra_fallback_mode == "artifact_if_unavailable":
        if _artifact_fallback_enabled():
            return _read_only_mutation_error(tool_name)
    return live_result

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return _call_with_fallback("list_methods", lambda: safe_get("methods", {"offset": offset, "limit": limit}), offset, limit)

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return _call_with_fallback("list_classes", lambda: safe_get("classes", {"offset": offset, "limit": limit}), offset, limit)

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return _call_with_fallback("decompile_function", lambda: safe_post("decompile", name), name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return _call_mutating_with_fallback(
        "rename_function",
        lambda: safe_post("renameFunction", {"oldName": old_name, "newName": new_name}),
        old_name,
        new_name,
    )

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return _call_mutating_with_fallback(
        "rename_data",
        lambda: safe_post("renameData", {"address": address, "newName": new_name}),
        address,
        new_name,
    )

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return _call_with_fallback("list_segments", lambda: safe_get("segments", {"offset": offset, "limit": limit}), offset, limit)

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return _call_with_fallback("list_imports", lambda: safe_get("imports", {"offset": offset, "limit": limit}), offset, limit)

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return _call_with_fallback("list_exports", lambda: safe_get("exports", {"offset": offset, "limit": limit}), offset, limit)

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return _call_with_fallback("list_namespaces", lambda: safe_get("namespaces", {"offset": offset, "limit": limit}), offset, limit)

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return _call_with_fallback("list_data_items", lambda: safe_get("data", {"offset": offset, "limit": limit}), offset, limit)

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return _call_with_fallback(
        "search_functions_by_name",
        lambda: safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit}),
        query,
        offset,
        limit,
    )

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return _call_mutating_with_fallback(
        "rename_variable",
        lambda: safe_post("renameVariable", {
            "functionName": function_name,
            "oldName": old_name,
            "newName": new_name
        }),
        function_name,
        old_name,
        new_name,
    )

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return _call_with_fallback(
        "get_function_by_address",
        lambda: "\n".join(safe_get("get_function_by_address", {"address": address})),
        address,
    )

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return _call_with_fallback("get_current_address", lambda: "\n".join(safe_get("get_current_address")))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return _call_with_fallback("get_current_function", lambda: "\n".join(safe_get("get_current_function")))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return _call_with_fallback("list_functions", lambda: safe_get("list_functions"))

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return _call_with_fallback(
        "decompile_function_by_address",
        lambda: "\n".join(safe_get("decompile_function", {"address": address})),
        address,
    )

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return _call_with_fallback("disassemble_function", lambda: safe_get("disassemble_function", {"address": address}), address)

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return _call_mutating_with_fallback(
        "set_decompiler_comment",
        lambda: safe_post("set_decompiler_comment", {"address": address, "comment": comment}),
        address,
        comment,
    )

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return _call_mutating_with_fallback(
        "set_disassembly_comment",
        lambda: safe_post("set_disassembly_comment", {"address": address, "comment": comment}),
        address,
        comment,
    )

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return _call_mutating_with_fallback(
        "rename_function_by_address",
        lambda: safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name}),
        function_address,
        new_name,
    )

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return _call_mutating_with_fallback(
        "set_function_prototype",
        lambda: safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype}),
        function_address,
        prototype,
    )

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return _call_mutating_with_fallback(
        "set_local_variable_type",
        lambda: safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type}),
        function_address,
        variable_name,
        new_type,
    )

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return _call_with_fallback(
        "get_xrefs_to",
        lambda: safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit}),
        address,
        offset,
        limit,
    )

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return _call_with_fallback(
        "get_xrefs_from",
        lambda: safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit}),
        address,
        offset,
        limit,
    )

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return _call_with_fallback(
        "get_function_xrefs",
        lambda: safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit}),
        name,
        offset,
        limit,
    )

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return _call_with_fallback("list_strings", lambda: safe_get("strings", params), offset, limit, filter)

@mcp.tool()
def get_program_info() -> list:
    """
    Retrieve basic metadata about the currently loaded program including file hashes.

    Args: None

    Returns:
        A list containing a single human-readable multi-line string. The string is
        exactly the Java `getProgramInfo()` output and includes these lines in order:

        - "No program loaded\\n"                                  (if no program)

        Otherwise:

        - "Program Information:\\n"
        - "---------------------\\n"
        - "Name: <program name>\\n"
        - "Ghidra Project Path: <domain file pathname or ''>\\n"
        - "Executable Path: <program.getExecutablePath() or ''>\\n"
        - "Executable MD5: <program.getExecutableMD5() or ''>\\n"
        - "Executable SHA256: <program.getExecutableSHA256() or ''>\\n"
        - "Language: <program.getLanguageID().getIdAsString() or ''>\\n"
        - "Compiler: <program.getCompilerSpec().getCompilerSpecID().getIdAsString() or ''>\\n"
        - "Endianness: big|little\\n"
        - "Image Base: <program.getImageBase().toString() or ''>\\n"
    """
    return _call_with_fallback("get_program_info", lambda: safe_get("program_info"))

@mcp.tool()
def get_call_graph(maxDepth: int, maxNodes: int = 3) -> list:
    """
    Get the call graph for a given function up to a specified depth.

    Args:
        maxDepth: The maximum depth of the call graph (default: 3).
        maxNodes: The maximum number of nodes to include in the call graph (default: 3).

    Returns:
        A list of strings representing the call graph, where each string is formatted as:
        "caller_function -> callee_function"
    """
    return _call_with_fallback(
        "get_call_graph",
        lambda: safe_get("callgraph_json", {"maxDepth": maxDepth, "maxNodes": maxNodes}),
        maxDepth,
        maxNodes,
    )

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--artifact-bundle-dir", type=str, default=os.environ.get("GHIDRA_ARTIFACT_BUNDLE_DIR", ""),
                        help="Optional artifact bundle dir for fallback when live Ghidra is unavailable")
    parser.add_argument("--fallback-mode", type=str, default=os.environ.get("GHIDRA_MCP_FALLBACK_MODE", DEFAULT_FALLBACK_MODE),
                        choices=sorted(FALLBACK_MODES),
                        help="Fallback behavior: live_only, artifact_if_unavailable, or artifact_only")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url, ghidra_artifact_bundle_dir, ghidra_fallback_mode
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    ghidra_artifact_bundle_dir = str(args.artifact_bundle_dir or "").strip()
    ghidra_fallback_mode = _normalize_fallback_mode(args.fallback_mode)

    if _artifact_fallback_enabled():
        logger.info("Artifact fallback enabled in %s mode with bundle dir %s", ghidra_fallback_mode, ghidra_artifact_bundle_dir)
    elif ghidra_fallback_mode == "artifact_only":
        logger.warning("artifact_only mode selected but no artifact bundle directory is configured")

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()
