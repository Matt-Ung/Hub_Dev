from __future__ import annotations

import queue
import shutil
import subprocess
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List


def tool_available(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(
    argv: List[str],
    *,
    cwd: Path | None = None,
    timeout_sec: int = 300,
    env: Dict[str, str] | None = None,
    stream_output: bool = False,
    stream_prefix: str = "",
    stream_heartbeat_sec: int = 30,
) -> Dict[str, Any]:
    merged_env = {**os.environ, **(env or {})}
    if stream_output:
        return _run_command_streaming(
            argv,
            cwd=cwd,
            timeout_sec=timeout_sec,
            env=merged_env,
            stream_prefix=stream_prefix,
            stream_heartbeat_sec=stream_heartbeat_sec,
        )
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, int(timeout_sec)),
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "command": argv,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "returncode": None,
            "command": argv,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": f"timeout after {timeout_sec}s",
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "command": argv,
            "stdout": "",
            "stderr": "",
            "error": f"{type(exc).__name__}: {exc}",
        }


def _run_command_streaming(
    argv: List[str],
    *,
    cwd: Path | None,
    timeout_sec: int,
    env: Dict[str, str],
    stream_prefix: str,
    stream_heartbeat_sec: int,
) -> Dict[str, Any]:
    prefix = str(stream_prefix or "")
    heartbeat_sec = max(1, int(stream_heartbeat_sec or 0))
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
        )
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "command": argv,
            "stdout": "",
            "stderr": "",
            "error": f"{type(exc).__name__}: {exc}",
        }

    stdout_queue: "queue.Queue[str | None]" = queue.Queue()
    stdout_chunks: List[str] = []
    start = time.monotonic()
    last_output_at = start
    last_heartbeat_at = start

    def _reader() -> None:
        try:
            if process.stdout is None:
                return
            for line in process.stdout:
                stdout_queue.put(line)
        finally:
            stdout_queue.put(None)

    reader = threading.Thread(target=_reader, name="run-command-reader", daemon=True)
    reader.start()

    timed_out = False
    saw_sentinel = False
    while True:
        elapsed = time.monotonic() - start
        remaining = max(0.0, float(timeout_sec) - elapsed)
        if remaining <= 0:
            timed_out = True
            break
        wait_timeout = min(1.0, remaining)
        try:
            item = stdout_queue.get(timeout=wait_timeout)
            if item is None:
                saw_sentinel = True
                if process.poll() is not None:
                    break
                continue
            stdout_chunks.append(item)
            last_output_at = time.monotonic()
            if prefix:
                text = prefix + item
                print(text, file=sys.stderr, end="" if text.endswith("\n") else "\n", flush=True)
            else:
                print(item, file=sys.stderr, end="" if item.endswith("\n") else "\n", flush=True)
        except queue.Empty:
            if process.poll() is not None and saw_sentinel:
                break
            now = time.monotonic()
            if heartbeat_sec > 0 and (now - last_output_at) >= heartbeat_sec and (now - last_heartbeat_at) >= heartbeat_sec:
                heartbeat = f"{prefix}[still running: {int(now - start)}s elapsed]"
                print(heartbeat, file=sys.stderr, flush=True)
                last_heartbeat_at = now

    if timed_out:
        process.kill()
        try:
            tail, _ = process.communicate(timeout=5)
        except Exception:
            tail = ""
        if tail:
            stdout_chunks.append(tail)
            if prefix:
                text = prefix + tail
                print(text, file=sys.stderr, end="" if text.endswith("\n") else "\n", flush=True)
            else:
                print(tail, file=sys.stderr, end="" if tail.endswith("\n") else "\n", flush=True)
        reader.join(timeout=1)
        return {
            "ok": False,
            "returncode": None,
            "command": argv,
            "stdout": "".join(stdout_chunks),
            "stderr": "",
            "error": f"timeout after {timeout_sec}s",
        }

    process.wait()
    reader.join(timeout=1)
    while True:
        try:
            item = stdout_queue.get_nowait()
        except queue.Empty:
            break
        if item is None:
            continue
        stdout_chunks.append(item)
        if prefix:
            text = prefix + item
            print(text, file=sys.stderr, end="" if text.endswith("\n") else "\n", flush=True)
        else:
            print(item, file=sys.stderr, end="" if item.endswith("\n") else "\n", flush=True)
    return {
        "ok": process.returncode == 0,
        "returncode": process.returncode,
        "command": argv,
        "stdout": "".join(stdout_chunks),
        "stderr": "",
    }


def shorten_text(value: str, max_chars: int = 16000) -> str:
    text = value or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]..."
