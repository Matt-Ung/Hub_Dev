#!/usr/bin/env python3
"""
vagrant_setup_mcp.py

FastMCP server that scaffolds (and optionally runs) a Vagrant-based Windows analysis VM.

Templates are stored externally in ./templates/ (relative to this script):
- templates/Vagrantfile.tmpl
- templates/provision.ps1.tmpl

Tools:
- setupVagrantVM(...): writes vm_dir/Vagrantfile, vm_dir/provision.ps1, vm_dir/samples/
  and optionally runs `vagrant up` / `vagrant provision`.

Server CLI:
  --transport {stdio,sse}
  --mcp-host
  --mcp-port
  --log-level
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Tuple

from fastmcp import FastMCP

logger = logging.getLogger(__name__)
mcp = FastMCP("vagrant_setup_mcp", instructions="MCP server that scaffolds and optionally runs Vagrant VMs.")

# BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = Path("MCPServers/vagrantTemplates").resolve()

VAGRANTFILE_TMPL_NAME = "Vagrantfile.tmpl"
PROVISION_TMPL_NAME = "provision.ps1.tmpl"

def write_text(path: Path, content: str, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists (set overwrite_outputs=True to replace).")
    path.write_text(content, encoding="utf-8")


def run_cmd(cmd: list[str], cwd: Path, timeout_sec: int) -> subprocess.CompletedProcess:
    logger.info("Running: (cd %s) %s", cwd, " ".join(cmd))
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=max(1, int(timeout_sec)),
    )


def format_proc_result(title: str, r: subprocess.CompletedProcess) -> str:
    return "\n".join(
        [
            title,
            f"rc={r.returncode}",
            "stdout:",
            (r.stdout or "").strip(),
            "stderr:",
            (r.stderr or "").strip(),
        ]
    )


@mcp.tool(
    description=(
        "Scaffold a Vagrant Windows VM directory using templates from ./templates, "
        "write Vagrantfile + provision.ps1 + samples/, and optionally run vagrant up/provision."
    )
)
def setupVagrantVM(
    vm_dir: str,
    box: str,
    winrm_user: str = "vagrant",
    winrm_pass: str = "vagrant",
    memory_mb: int = 8192,
    cpus: int = 4,
    boot_timeout: int = 1200,
    overwrite_outputs: bool = False,
    run_up: bool = False,
    run_provision: bool = False,
    vagrant_timeout_sec: int = 3600,
) -> str:
    """
    Args:
      vm_dir: Directory to create (e.g., "./analysis-vm").
      box: Vagrant box name (Windows box with WinRM enabled).
      winrm_user/winrm_pass: WinRM credentials expected by the box.
      memory_mb/cpus/boot_timeout: VM settings written into the Vagrantfile template.
      overwrite_outputs: Overwrite vm_dir/Vagrantfile and vm_dir/provision.ps1 if they exist.
      run_up: Run `vagrant up` after writing outputs.
      run_provision: Run `vagrant provision` after `vagrant up`.
      vagrant_timeout_sec: Timeout for each vagrant command.

    Returns:
      Status string + (optional) vagrant command output.
    """
    try:
        vm_dir = (vm_dir or "").strip()
        box = (box or "").strip()

        if not vm_dir:
            return "Error: vm_dir must be a non-empty string."
        if not box:
            return "Error: box must be a non-empty string."
        if not shutil.which("vagrant"):
            return "Error: `vagrant` not found on PATH. Install Vagrant first."

        # Ensure templates exist (hard requirement)
        v_tmpl_path, p_tmpl_path = TEMPLATES_DIR / VAGRANTFILE_TMPL_NAME, TEMPLATES_DIR / PROVISION_TMPL_NAME

        vf_tmpl = v_tmpl_path.read_text(encoding="utf-8")
        ps1_tmpl = p_tmpl_path.read_text(encoding="utf-8")

        # Render templates using .format()
        # If your templates include literal braces, escape as {{ and }}.
        try:
            vagrantfile_text = vf_tmpl.format(
                box=box,
                winrm_user=winrm_user,
                winrm_pass=winrm_pass,
                boot_timeout=int(boot_timeout),
                memory_mb=int(memory_mb),
                cpus=int(cpus),
            )
        except KeyError as e:
            return f"Error: Vagrantfile template missing placeholder: {e}"

        try:
            provision_text = ps1_tmpl.format()
        except KeyError as e:
            return f"Error: provision template missing placeholder: {e}"

        base = Path(vm_dir).expanduser().resolve()
        samples = base / "samples"
        vagrantfile_out = base / "Vagrantfile"
        provision_out = base / "provision.ps1"

        samples.mkdir(parents=True, exist_ok=True)

        write_text(vagrantfile_out, vagrantfile_text, overwrite=overwrite_outputs)
        write_text(provision_out, provision_text, overwrite=overwrite_outputs)

        result_parts = [
            "Created Vagrant VM scaffold:",
            f"- vm_dir: {base}",
            f"- samples: {samples} (guest sees C:\\samples)",
            f"- Vagrantfile: {vagrantfile_out}",
            f"- provision.ps1: {provision_out}",
            "",
            "Templates used:",
            f"- {v_tmpl_path}",
            f"- {p_tmpl_path}",
        ]

        if run_up:
            r_up = run_cmd(["vagrant", "up"], cwd=base, timeout_sec=vagrant_timeout_sec)
            result_parts += ["", format_proc_result("vagrant up:", r_up)]
            if r_up.returncode != 0:
                return "\n".join(result_parts)

            if run_provision:
                r_prov = run_cmd(["vagrant", "provision"], cwd=base, timeout_sec=vagrant_timeout_sec)
                result_parts += ["", format_proc_result("vagrant provision:", r_prov)]

        return "\n".join(result_parts)

    except subprocess.TimeoutExpired:
        return f"Error: vagrant command timed out after {vagrant_timeout_sec} seconds."
    except FileExistsError as e:
        return f"Error: {e}"
    except FileNotFoundError as e:
        return f"Error: {e}"
    except Exception as e:
        logger.exception("setupVagrantVM failed")
        return f"Error: {e}"


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP server: Vagrant VM scaffolder")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8091)
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"])
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level, logging.INFO)
    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    if args.transport == "sse":
        mcp.settings.log_level = args.log_level
        mcp.settings.host = args.mcp_host
        mcp.settings.port = args.mcp_port
        logger.info("Starting SSE MCP server on http://%s:%s/sse", mcp.settings.host, mcp.settings.port)
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()