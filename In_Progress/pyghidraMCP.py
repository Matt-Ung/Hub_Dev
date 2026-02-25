"""
pyghidra_mcp_server.py

MCP server exposing a tool that:
- receives a Python script as a string (script_source)
- optionally loads/opens a Program in a Ghidra project
- executes the script via pyghidra.ghidra_script(...)
- returns stdout/stderr + some metadata
"""

from __future__ import annotations

import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any

import pyghidra

# If you're using FastMCP (common pattern):
from mcp.server.fastmcp import FastMCP  # adjust if your MCP package layout differs

mcp = FastMCP("pyghidra-mcp")

# --- PyGhidra lifecycle: JVM should be started exactly once per process.
_START_LOCK = threading.Lock()

def ensure_pyghidra_started(install_dir: Optional[str] = None, verbose: bool = False) -> None:
    """
    Start PyGhidra once. PyGhidra provides pyghidra.started() to check if already started. 
    """
    with _START_LOCK:
        if pyghidra.started():  # :contentReference[oaicite:7]{index=7}
            return
        # install_dir can be passed explicitly or via GHIDRA_INSTALL_DIR env var
        if install_dir:
            pyghidra.start(verbose=verbose, install_dir=Path(install_dir))  # :contentReference[oaicite:8]{index=8}
        else:
            pyghidra.start(verbose=verbose)  # :contentReference[oaicite:9]{index=9}


def _import_binary_if_needed(
    project,
    binary_path: Path,
    project_folder: str,
    program_name: Optional[str],
    monitor_timeout_s: Optional[int],
) -> str:
    """
    Import binary into the project if it doesn't already exist at /<project_folder>/<name>.
    Returns the project path (starting with "/") where the Program should live.
    """
    # Decide the name used in the project
    name = program_name or binary_path.name
    ghidra_project_path = f"/{project_folder.strip('/')}/{name}" if project_folder else f"/{name}"

    # Try to see if it already exists
    try:
        # pyghidra.program_context will raise if missing. :contentReference[oaicite:10]{index=10}
        with pyghidra.program_context(project, ghidra_project_path):
            return ghidra_project_path
    except Exception:
        pass

    # Import it
    loader = pyghidra.program_loader().project(project).source(str(binary_path))  # :contentReference[oaicite:11]{index=11}
    if project_folder:
        loader = loader.projectFolderPath("/" + project_folder.strip("/"))

    if program_name:
        loader = loader.name(program_name)

    with loader.load() as load_results:
        mon = pyghidra.task_monitor(monitor_timeout_s) if monitor_timeout_s else pyghidra.task_monitor()  # :contentReference[oaicite:12]{index=12}
        load_results.save(mon)

    return ghidra_project_path


def _write_temp_script(script_source: str) -> Path:
    """
    Write script_source to a temporary .py file and return its path.
    """
    # Keep it on disk so pyghidra.ghidra_script can load it by path. :contentReference[oaicite:13]{index=13}
    fd, p = tempfile.mkstemp(prefix="mcp_pyghidra_", suffix=".py")
    os.close(fd)
    path = Path(p)
    path.write_text(script_source, encoding="utf-8")
    return path


@mcp.tool()
def run_pyghidra_script(
    script_source: str,
    *,
    ghidra_install_dir: Optional[str] = None,
    verbose_startup: bool = False,

    project_dir: str,
    project_name: str,
    create_project: bool = True,  # open_project supports create flag :contentReference[oaicite:14]{index=14}

    # Provide ONE of:
    # - binary_path: import/open a binary
    # - program_project_path: open an existing Program already in the project (e.g. "/foo/bar.exe")
    binary_path: Optional[str] = None,
    program_project_path: Optional[str] = None,

    # Import settings if binary_path is provided
    import_project_folder: str = "",
    program_name: Optional[str] = None,

    # Execution settings
    analyze: bool = False,
    monitor_timeout_s: Optional[int] = None,

    echo_stdout: bool = True,
    echo_stderr: bool = True,
) -> Dict[str, Any]:
    """
    Execute a transmitted PyGhidra (GhidraScript-style) python script.

    Returns:
      {
        "ok": bool,
        "stdout": str,
        "stderr": str,
        "program_path": str | null,
        "script_temp_path": str,
      }
    """
    ensure_pyghidra_started(install_dir=ghidra_install_dir, verbose=verbose_startup)

    proj_dir = Path(project_dir)
    script_path = _write_temp_script(script_source)

    # Open/create the project :contentReference[oaicite:15]{index=15}
    with pyghidra.open_project(proj_dir, project_name, create=create_project) as project:
        program_path: Optional[str] = None

        if program_project_path:
            program_path = program_project_path
        elif binary_path:
            program_path = _import_binary_if_needed(
                project=project,
                binary_path=Path(binary_path),
                project_folder=import_project_folder,
                program_name=program_name,
                monitor_timeout_s=monitor_timeout_s,
            )

        # If we have a program, open it via program_context so it can be passed as currentProgram :contentReference[oaicite:16]{index=16}
        if program_path:
            with pyghidra.program_context(project, program_path) as program:
                if analyze:
                    mon = pyghidra.task_monitor(monitor_timeout_s) if monitor_timeout_s else pyghidra.task_monitor()
                    _analysis_log = pyghidra.analyze(program, mon)  # :contentReference[oaicite:17]{index=17}

                out, err = pyghidra.ghidra_script(  # :contentReference[oaicite:18]{index=18}
                    str(script_path),
                    project,
                    program=program,
                    echo_stdout=echo_stdout,
                    echo_stderr=echo_stderr,
                )
        else:
            # Run script without a currentProgram
            out, err = pyghidra.ghidra_script(  # :contentReference[oaicite:19]{index=19}
                str(script_path),
                project,
                program=None,
                echo_stdout=echo_stdout,
                echo_stderr=echo_stderr,
            )

    ok = (err.strip() == "")
    return {
        "ok": ok,
        "stdout": out,
        "stderr": err,
        "program_path": program_path,
        "script_temp_path": str(script_path),
    }


if __name__ == "__main__":
    mcp.run()