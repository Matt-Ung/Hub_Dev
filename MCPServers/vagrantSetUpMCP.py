"""
vagrant_mcp_templates.py

FastMCP server that uses user-provided template files:
- Vagrantfile.tmpl
- provision.ps1.tmpl

Behavior:
- Renders Vagrantfile from template placeholders
- Copies provision.ps1 from template
- Copies a payload file into ./samples so Vagrant synced_folder moves it into the guest
- Runs `vagrant up --provider=virtualbox`
- Supports later uploads via `vagrant upload`

Designed around a Windows guest template (WinRM + PowerShell provisioning).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
import hashlib

from fastmcp import FastMCP

mcp = FastMCP("VagrantMCP")

MAX_CAPTURE = 12000
# vagrantfile_template = "vagrantTemplates/Vagrantfile.tmpl",
# provision_template = "vagrantTemplates/provision.ps1.tmpl",
box_default = "stromweld/windows-11"

# ----------------------------
# Helpers
# ----------------------------

def _trim(s: str, n: int = MAX_CAPTURE) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + f"\n...[truncated {len(s)-n} chars]..."


def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 1800) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "stdout": _trim(p.stdout),
            "stderr": _trim(p.stderr),
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "returncode": None,
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "stdout": "",
            "stderr": "",
            "error": f"Executable not found: {cmd[0]}",
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "returncode": None,
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "stdout": _trim(e.stdout or ""),
            "stderr": _trim(e.stderr or ""),
            "error": f"Timed out after {timeout}s",
        }
    except Exception as e:
        return {
            "ok": False,
            "returncode": None,
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "stdout": "",
            "stderr": "",
            "error": str(e),
        }


def _check_prereqs() -> Dict[str, Any]:
    vagrant = _run(["vagrant", "--version"], timeout=20)
    if not vagrant.get("ok"):
        return {"ok": False, "error": "Vagrant not found on PATH", "details": vagrant}
    vbox = _run(["VBoxManage", "--version"], timeout=20)
    return {
        "ok": True,
        "vagrant_version": vagrant.get("stdout", "").strip(),
        "virtualbox_detected": bool(vbox.get("ok")),
        "virtualbox_check": vbox,
    }


def _safe_replace_tokens(template_text: str, values: Dict[str, Any]) -> str:
    """
    Replace only explicit {token} placeholders from a whitelist.
    This avoids breaking other braces in template content.
    """
    out = template_text
    for k, v in values.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _project_info(project_dir: Path) -> Dict[str, Any]:
    return {
        "project_dir": str(project_dir),
        "vagrantfile": str(project_dir / "Vagrantfile"),
        "provision_script": str(project_dir / "provision.ps1"),
        "samples_dir": str(project_dir / "samples"),
    }


def _copy_payload_into_samples(project_dir: Path, payload_path: Path) -> Dict[str, Any]:
    samples = project_dir / "samples"
    samples.mkdir(parents=True, exist_ok=True)

    unique_name = f"{uuid.uuid4().hex[:8]}_{payload_path.name}"
    dest = samples / unique_name

    if payload_path.is_file():
        shutil.copy2(payload_path, dest)
    elif payload_path.is_dir():
        shutil.copytree(payload_path, dest)
    else:
        return {"ok": False, "error": f"Payload path is neither file nor directory: {payload_path}"}

    return {
        "ok": True,
        "host_payload": str(payload_path),
        "staged_payload": str(dest),
        # Your template syncs ./samples -> C:/samples
        "guest_path_via_synced_folder": f"C:/samples/{dest.name}",
    }


# ----------------------------
# MCP Tools
# ----------------------------
@mcp.tool
def create_vagrant_project_from_templates(
    executable_path: str,
    winrm_user: str = "vagrant",
    winrm_pass: str = "vagrant",
    boot_timeout: int = 1200,
    memory_mb: int = 4096,
    cpus: int = 2,
    overwrite: bool = True,
    run_up: bool = True,
) -> Dict[str, Any]:
    """
    Create a Vagrant project using local sibling templates and optionally run `vagrant up`.

    Expected folder layout (example):
      <repo_root>/
        MCPServers/
          vagrantSetUpMCP.py   (this script)
        vagrantTemplates/
          Vagrantfile.tmpl
          provision.ps1.tmpl
        vagrantProjects/             (auto-created)

    Tool input:
    - executable_path: path from Ghidra (host path to the executable)

    Behavior:
    - Derives a stable project_dir automatically from the executable path
    - Renders Vagrantfile from vagrantTemplates/Vagrantfile.tmpl
    - Copies provision.ps1.tmpl as-is to provision.ps1
    - Copies executable into ./samples (synced to C:/samples in guest)
    """
    prereq = _check_prereqs()
    if not prereq.get("ok"):
        return prereq

    # Resolve payload from Ghidra path
    payload = Path(executable_path).expanduser().resolve()
    if not payload.exists():
        return {"ok": False, "error": f"executable_path not found: {payload}"}

    # Resolve template + project roots relative to this script
    # Assumes: MCPServers and vagrantTemplates are sibling folders
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    # templates_dir = repo_root / "vagrantTemplates"
    projects_root = repo_root / "vagrantProjects"

    vagrant_tpl =  Path("./MCPServers/vagrantTemplates/Vagrantfile.tmpl").resolve()
    prov_tpl = Path("./MCPServers/vagrantTemplates/provision.ps1.tmpl").resolve()

    if not vagrant_tpl.exists():
        return {"ok": False, "error": f"Vagrantfile template not found: {vagrant_tpl}"}
    if not prov_tpl.exists():
        return {"ok": False, "error": f"Provision template not found: {prov_tpl}"}

    # Build deterministic project directory from executable path
    # (stable name so repeated runs for same binary reuse the same workspace)
    exe_stem = payload.stem or "payload"
    safe_stem = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in exe_stem).strip("_")
    if not safe_stem:
        safe_stem = "payload"

    path_hash = hashlib.sha256(str(payload).encode("utf-8")).hexdigest()[:10]
    project = (projects_root / f"{safe_stem}-{path_hash}").resolve()
    project.mkdir(parents=True, exist_ok=True)

    vf_out = project / "Vagrantfile"
    ps_out = project / "provision.ps1"

    if not overwrite and (vf_out.exists() or ps_out.exists()):
        return {
            "ok": False,
            "error": "Project files already exist and overwrite=False",
            **_project_info(project),
            "derived_from_executable": str(payload),
        }

    # Render Vagrantfile template
    try:
        vf_template_text = vagrant_tpl.read_text(encoding="utf-8")
        rendered_vf = _safe_replace_tokens(
            vf_template_text,
            {
                "box": box_default,
                "winrm_user": winrm_user,
                "winrm_pass": winrm_pass,
                "boot_timeout": int(boot_timeout),
                "memory_mb": int(memory_mb),
                "cpus": int(cpus),
            },
        )
        vf_out.write_text(rendered_vf, encoding="utf-8")
    except Exception as e:
        return {"ok": False, "error": f"Failed to render/write Vagrantfile: {e}"}

    # Copy provision script template AS-IS (important: PowerShell braces)
    try:
        shutil.copy2(prov_tpl, ps_out)
    except Exception as e:
        return {"ok": False, "error": f"Failed to copy provision template: {e}"}

    # Stage payload into ./samples (synced into guest by your Vagrantfile)
    try:
        staged = _copy_payload_into_samples(project, payload)
        if not staged.get("ok"):
            return staged
    except Exception as e:
        return {"ok": False, "error": f"Failed to stage payload: {e}"}

    result: Dict[str, Any] = {
        "ok": True,
        "message": "Vagrant project created from templates.",
        **_project_info(project),
        "derived_from_executable": str(payload),
        "templates": {
            # "templates_dir": str(templates_dir),
            "vagrantfile_template": str(vagrant_tpl),
            "provision_template": str(prov_tpl),
        },
        "rendered_values": {
            "box": box_default,
            "winrm_user": winrm_user,
            "boot_timeout": boot_timeout,
            "memory_mb": memory_mb,
            "cpus": cpus,
        },
        "payload": staged,
        "vagrantfile_preview": _trim(rendered_vf, 4000),
        "prereq": {
            "vagrant_version": prereq.get("vagrant_version"),
            "virtualbox_detected": prereq.get("virtualbox_detected"),
        },
    }

    if run_up:
        up = _run(["vagrant", "up", "--provider=virtualbox"], cwd=project, timeout=7200)
        result["vagrant_up"] = up
        result["ok"] = bool(up.get("ok"))

    return result

@mcp.tool
def vagrant_upload_file(
    project_dir: str,
    host_path: str,
    guest_destination: str,
    compress: bool = False,
) -> Dict[str, Any]:
    """
    Upload a file after the VM is already running using `vagrant upload`.
    Useful for iterative testing without reprovisioning.
    """
    project = Path(project_dir).expanduser().resolve()
    host = Path(host_path).expanduser().resolve()

    if not (project / "Vagrantfile").exists():
        return {"ok": False, "error": f"No Vagrantfile in {project}"}
    if not host.exists():
        return {"ok": False, "error": f"host_path not found: {host}"}

    cmd = ["vagrant", "upload", str(host), guest_destination]
    if compress:
        cmd.append("--compress")

    res = _run(cmd, cwd=project, timeout=1800)
    return {
        "ok": res.get("ok", False),
        "project_dir": str(project),
        "host_path": str(host),
        "guest_destination": guest_destination,
        "upload": res,
    }


@mcp.tool
def vagrant_status(project_dir: str) -> Dict[str, Any]:
    project = Path(project_dir).expanduser().resolve()
    if not (project / "Vagrantfile").exists():
        return {"ok": False, "error": f"No Vagrantfile in {project}"}
    res = _run(["vagrant", "status"], cwd=project, timeout=60)
    return {"ok": res.get("ok", False), "project_dir": str(project), "status": res}


@mcp.tool
def vagrant_halt(project_dir: str, force: bool = False) -> Dict[str, Any]:
    project = Path(project_dir).expanduser().resolve()
    if not (project / "Vagrantfile").exists():
        return {"ok": False, "error": f"No Vagrantfile in {project}"}
    cmd = ["vagrant", "halt"]
    if force:
        cmd.append("--force")
    res = _run(cmd, cwd=project, timeout=1200)
    return {"ok": res.get("ok", False), "project_dir": str(project), "halt": res}


@mcp.tool
def vagrant_destroy(project_dir: str, force: bool = True) -> Dict[str, Any]:
    project = Path(project_dir).expanduser().resolve()
    if not (project / "Vagrantfile").exists():
        return {"ok": False, "error": f"No Vagrantfile in {project}"}
    cmd = ["vagrant", "destroy"]
    if force:
        cmd.append("-f")
    res = _run(cmd, cwd=project, timeout=2400)
    return {"ok": res.get("ok", False), "project_dir": str(project), "destroy": res}


def main() -> None:
    parser = argparse.ArgumentParser(description="FastMCP Vagrant template server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8099)
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="http", host=args.mcp_host, port=args.mcp_port)


if __name__ == "__main__":
    main()