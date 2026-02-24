"""
virtualBoxMCP.py

FastMCP server that exposes VirtualBox VM automation tools:
- `list_virtualbox_vms()`
- `spawn_virtualbox_vm(vm_name, start_type, snapshot, wait, wait_timeout_s)`
- `copy_file_to_virtualbox_guest(vm_name, host_src_path, guest_dst_dir, username, password, password_env)`
- `run_command_in_virtualbox_guest(vm_name, command, username, password, password_env, timeout_s)` (optional but useful)

Key features:
- Cross-platform `VBoxManage` discovery (PATH + common Windows install paths)
- Structured JSON returns for agents (`ok: true/false`, error objects with diagnostics)
- Optional snapshot restore + “is running” checks
- Best-effort wait for guest readiness (uses guest properties; typically requires Guest Additions)
- Host→guest file copy using `VBoxManage guestcontrol copyto` (requires Guest Additions + guest creds)
- Preserves a simple CLI:
    --transport {stdio,sse}
    --mcp-host
    --mcp-port
    --vboxmanage-path (optional)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

mcp = FastMCP("virtualBoxMCP")


# ----------------------------
# Helpers
# ----------------------------
def _find_vboxmanage(explicit: Optional[str] = None) -> str:
    """Find VBoxManage executable (Windows/macOS/Linux)."""
    if explicit:
        return explicit

    env = os.getenv("VBOXMANAGE_PATH")
    if env:
        return env

    exe = shutil.which("VBoxManage")
    if exe:
        return exe

    # Common Windows install paths
    candidates = [
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c

    raise FileNotFoundError(
        "VBoxManage not found. Install VirtualBox or set VBOXMANAGE_PATH / pass --vboxmanage-path."
    )


def _run(cmd: List[str], timeout_s: int = 60) -> subprocess.CompletedProcess:
    """Run a command, capture output, raise on error."""
    return subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        check=True,
        timeout=timeout_s,
    )


def _vm_exists(vboxmanage: str, vm_name: str) -> bool:
    cp = _run([vboxmanage, "list", "vms"], timeout_s=30)
    return any(f"\"{vm_name}\"" in line for line in cp.stdout.splitlines())


def _vm_running(vboxmanage: str, vm_name: str) -> bool:
    cp = _run([vboxmanage, "list", "runningvms"], timeout_s=30)
    return any(f"\"{vm_name}\"" in line for line in cp.stdout.splitlines())


def _restore_snapshot(vboxmanage: str, vm_name: str, snapshot: str) -> None:
    # If running, poweroff first (hard poweroff)
    if _vm_running(vboxmanage, vm_name):
        _run([vboxmanage, "controlvm", vm_name, "poweroff"], timeout_s=90)
    _run([vboxmanage, "snapshot", vm_name, "restore", snapshot], timeout_s=180)


def _start_vm(vboxmanage: str, vm_name: str, start_type: str) -> None:
    if _vm_running(vboxmanage, vm_name):
        return
    _run([vboxmanage, "startvm", vm_name, "--type", start_type], timeout_s=90)


def _wait_for_guest_property(
    vboxmanage: str,
    vm_name: str,
    prop: str = "/VirtualBox/GuestInfo/OS/Product",
    timeout_s: int = 180,
    poll_s: float = 2.0,
) -> Dict[str, Any]:
    """
    Best-effort readiness wait: checks guestproperty.
    This often requires Guest Additions installed inside the guest.
    """
    deadline = time.time() + timeout_s
    last_out = ""
    while time.time() < deadline:
        try:
            cp = _run([vboxmanage, "guestproperty", "get", vm_name, prop], timeout_s=15)
            out = (cp.stdout or "").strip()
            last_out = out
            # Typical output: "Value: Windows 7"
            if out and "No value set!" not in out:
                return {"ok": True, "property": prop, "value": out}
        except Exception as e:
            last_out = str(e)
        time.sleep(poll_s)

    return {
        "ok": False,
        "property": prop,
        "message": "Timed out waiting for guest property. VM may still be booting or Guest Additions not installed.",
        "last": last_out[:1000],
    }


def _password_from_args(password: Optional[str], password_env: Optional[str]) -> Optional[str]:
    if password:
        return password
    if password_env:
        return os.getenv(password_env)
    return None


def _format_subprocess_error(e: subprocess.CalledProcessError) -> Dict[str, Any]:
    return {
        "type": "subprocess_error",
        "cmd": e.cmd,
        "returncode": e.returncode,
        "stdout": (e.stdout or "")[:4000],
        "stderr": (e.stderr or "")[:4000],
    }


# ----------------------------
# MCP Tools
# ----------------------------
@mcp.tool(
    name="list_virtualbox_vms",
    description="List all VirtualBox VMs visible to VBoxManage (name + uuid).",
)
def list_virtualbox_vms() -> Dict[str, Any]:
    try:
        vboxmanage = _find_vboxmanage()
        cp = _run([vboxmanage, "list", "vms"], timeout_s=30)

        vms = []
        for line in cp.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "Name" {uuid}
            name, uuid = None, None
            if line.startswith('"') and '" {' in line:
                name = line.split('"', 2)[1]
                uuid = line.split("{", 1)[1].split("}", 1)[0]
            vms.append({"raw": line, "name": name, "uuid": uuid})

        return {"ok": True, "vms": vms}

    except Exception as e:
        return {"ok": False, "error": {"type": "exception", "message": str(e)}}


@mcp.tool(
    name="spawn_virtualbox_vm",
    description=(
        "Start an existing VirtualBox VM via VBoxManage. "
        "Optionally restore a snapshot first and/or wait for guest readiness."
    ),
)
def spawn_virtualbox_vm(
    vm_name: str,
    start_type: str = "headless",            # headless|gui|separate
    snapshot: Optional[str] = None,
    wait: bool = False,
    wait_timeout_s: int = 180,
) -> Dict[str, Any]:
    try:
        vboxmanage = _find_vboxmanage()
    except Exception as e:
        return {"ok": False, "error": {"type": "missing_dependency", "message": str(e)}}

    if start_type not in {"headless", "gui", "separate"}:
        return {
            "ok": False,
            "error": {
                "type": "invalid_argument",
                "message": "start_type must be one of: headless, gui, separate",
            },
        }

    try:
        if not _vm_exists(vboxmanage, vm_name):
            return {"ok": False, "error": {"type": "not_found", "message": f"VM '{vm_name}' not found"}}

        if snapshot:
            _restore_snapshot(vboxmanage, vm_name, snapshot)

        _start_vm(vboxmanage, vm_name, start_type)

        result: Dict[str, Any] = {
            "ok": True,
            "vm_name": vm_name,
            "start_type": start_type,
            "snapshot_restored": snapshot or None,
            "running": _vm_running(vboxmanage, vm_name),
        }

        if wait:
            result["wait"] = _wait_for_guest_property(vboxmanage, vm_name, timeout_s=wait_timeout_s)

        return result

    except subprocess.CalledProcessError as e:
        err = _format_subprocess_error(e)
        err["hint"] = "VBoxManage failed; verify VM name and VirtualBox installation."
        return {"ok": False, "error": err}
    except Exception as e:
        return {"ok": False, "error": {"type": "exception", "message": str(e)}}


@mcp.tool(
    name="copy_file_to_virtualbox_guest",
    description=(
        "Copy a file from host -> guest using VBoxManage guestcontrol copyto. "
        "Requires Guest Additions installed in the guest and valid guest credentials."
    ),
)
def copy_file_to_virtualbox_guest(
    vm_name: str,
    host_src_path: str,
    guest_dst_dir: str,
    username: str,
    password: Optional[str] = None,
    password_env: Optional[str] = "VBOX_GUEST_PASSWORD",
    timeout_s: int = 180,
) -> Dict[str, Any]:
    try:
        vboxmanage = _find_vboxmanage()
    except Exception as e:
        return {"ok": False, "error": {"type": "missing_dependency", "message": str(e)}}

    if not os.path.exists(host_src_path):
        return {"ok": False, "error": {"type": "not_found", "message": f"Host path not found: {host_src_path}"}}

    pw = _password_from_args(password, password_env)
    if not pw:
        return {
            "ok": False,
            "error": {
                "type": "invalid_argument",
                "message": "No password provided. Pass password=... or set env var (default VBOX_GUEST_PASSWORD).",
            },
        }

    cmd = [
        vboxmanage,
        "guestcontrol", vm_name,
        "copyto",
        "--username", username,
        "--password", pw,
        "--target-directory", guest_dst_dir,
        host_src_path,
    ]

    try:
        cp = _run(cmd, timeout_s=timeout_s)
        return {
            "ok": True,
            "vm_name": vm_name,
            "host_src_path": host_src_path,
            "guest_dst_dir": guest_dst_dir,
            "stdout": (cp.stdout or "")[:2000],
            "stderr": (cp.stderr or "")[:2000],
            "hint": "If this fails, confirm Guest Additions are installed and credentials are correct.",
        }
    except subprocess.CalledProcessError as e:
        err = _format_subprocess_error(e)
        err["hint"] = "guestcontrol copyto requires Guest Additions installed + valid credentials."
        return {"ok": False, "error": err}
    except Exception as e:
        return {"ok": False, "error": {"type": "exception", "message": str(e)}}


@mcp.tool(
    name="run_command_in_virtualbox_guest",
    description=(
        "Run a command inside the guest using VBoxManage guestcontrol run. "
        "Requires Guest Additions installed in the guest and valid guest credentials."
    ),
)
def run_command_in_virtualbox_guest(
    vm_name: str,
    command: str,
    username: str,
    password: Optional[str] = None,
    password_env: Optional[str] = "VBOX_GUEST_PASSWORD",
    timeout_s: int = 180,
) -> Dict[str, Any]:
    """
    Runs `command` through `cmd.exe /c` (Windows guest assumption).
    If you need Linux guests later, we can add a `shell` parameter.
    """
    try:
        vboxmanage = _find_vboxmanage()
    except Exception as e:
        return {"ok": False, "error": {"type": "missing_dependency", "message": str(e)}}

    pw = _password_from_args(password, password_env)
    if not pw:
        return {
            "ok": False,
            "error": {
                "type": "invalid_argument",
                "message": "No password provided. Pass password=... or set env var (default VBOX_GUEST_PASSWORD).",
            },
        }

    # Windows guest default: cmd.exe /c <command>
    cmd = [
        vboxmanage,
        "guestcontrol", vm_name,
        "run",
        "--username", username,
        "--password", pw,
        "--exe", r"C:\Windows\System32\cmd.exe",
        "--",
        "cmd.exe", "/c", command,
    ]

    try:
        cp = _run(cmd, timeout_s=timeout_s)
        return {
            "ok": True,
            "vm_name": vm_name,
            "command": command,
            "stdout": (cp.stdout or "")[:4000],
            "stderr": (cp.stderr or "")[:4000],
        }
    except subprocess.CalledProcessError as e:
        err = _format_subprocess_error(e)
        err["hint"] = "guestcontrol run requires Guest Additions installed + valid credentials."
        return {"ok": False, "error": err}
    except Exception as e:
        return {"ok": False, "error": {"type": "exception", "message": str(e)}}

# ----------------------------
# CLI
# ----------------------------
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="VirtualBox VM FastMCP server")
    p.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    p.add_argument("--mcp-host", default="127.0.0.1")
    p.add_argument("--mcp-port", type=int, default=8090)
    p.add_argument("--vboxmanage-path", default=None, help="Override path to VBoxManage executable.")
    return p.parse_args()

if __name__ == "__main__":
    args = _parse_args()

    # Make VBoxManage discovery deterministic if provided
    if args.vboxmanage_path:
        os.environ["VBOXMANAGE_PATH"] = args.vboxmanage_path

    if args.transport == "stdio":
        # STDIO ignores host/port
        mcp.run()
    else:
        # SSE uses host/port (legacy but widely used)
        mcp.run(transport="sse", host=args.mcp_host, port=args.mcp_port)
