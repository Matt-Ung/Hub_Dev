"""
File: subprocess_utils.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Provide the shared subprocess execution helpers used by testing scripts and
  harness modules.

Summary:
  This module standardizes command execution, timeout handling, optional
  streaming capture, and heartbeat output so the maintained harness launches
  child tools and wrapper scripts consistently.
"""

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


def normalize_timeout_sec(timeout_sec: int | None) -> int | None:
    try:
        if timeout_sec is None:
            return None
        normalized = int(timeout_sec)
    except Exception:
        return None
    if normalized <= 0:
        return None
    return normalized


"""
Function: run_command
Inputs:
  - argv: subprocess command as an argument vector.
  - cwd / timeout_sec / env / stream_output / stream_prefix /
    stream_heartbeat_sec / stream_capture_path: execution controls.
Description:
  Run one child process either in buffered mode or in streaming mode with
  optional log capture and heartbeat output.
Outputs:
  Returns a structured dictionary containing return code, captured stdout,
  stderr, and any execution error details.
Side Effects:
  Launches a subprocess, may stream output to stderr, and may write captured
  output to `stream_capture_path`.
"""
def run_command(
    argv: List[str],
    *,
    cwd: Path | None = None,
    timeout_sec: int | None = None,
    env: Dict[str, str] | None = None,
    stream_output: bool = False,
    stream_prefix: str = "",
    stream_heartbeat_sec: int = 30,
    stream_capture_path: Path | None = None,
) -> Dict[str, Any]:
    merged_env = {**os.environ, **(env or {})}
    normalized_timeout = normalize_timeout_sec(timeout_sec)
    if stream_output or stream_capture_path is not None:
        return _run_command_streaming(
            argv,
            cwd=cwd,
            timeout_sec=normalized_timeout,
            env=merged_env,
            echo_output=stream_output,
            stream_prefix=stream_prefix,
            stream_heartbeat_sec=stream_heartbeat_sec,
            stream_capture_path=stream_capture_path,
        )
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=normalized_timeout,
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
            "error": f"timeout after {normalized_timeout}s",
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
    timeout_sec: int | None,
    env: Dict[str, str],
    echo_output: bool,
    stream_prefix: str,
    stream_heartbeat_sec: int,
    stream_capture_path: Path | None,
) -> Dict[str, Any]:
    prefix = str(stream_prefix or "")
    heartbeat_sec = max(1, int(stream_heartbeat_sec or 0))
    capture_handle = None
    if stream_capture_path is not None:
        stream_capture_path.parent.mkdir(parents=True, exist_ok=True)
        capture_handle = stream_capture_path.open("w", encoding="utf-8")

    def _emit_line(text: str) -> None:
        if capture_handle is not None:
            capture_handle.write(text)
            capture_handle.flush()
        if echo_output:
            if prefix:
                rendered = prefix + text
                print(rendered, file=sys.stderr, end="" if rendered.endswith("\n") else "\n", flush=True)
            else:
                print(text, file=sys.stderr, end="" if text.endswith("\n") else "\n", flush=True)

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
        if capture_handle is not None:
            capture_handle.close()
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
        wait_timeout = 1.0
        if timeout_sec is not None:
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
            _emit_line(item)
        except queue.Empty:
            if process.poll() is not None and saw_sentinel:
                break
            now = time.monotonic()
            if heartbeat_sec > 0 and (now - last_output_at) >= heartbeat_sec and (now - last_heartbeat_at) >= heartbeat_sec:
                heartbeat = f"{prefix}[still running: {int(now - start)}s elapsed]"
                heartbeat_line = heartbeat if heartbeat.endswith("\n") else heartbeat + "\n"
                if capture_handle is not None:
                    capture_handle.write(heartbeat_line)
                    capture_handle.flush()
                if echo_output:
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
            _emit_line(tail)
        reader.join(timeout=1)
        if capture_handle is not None:
            capture_handle.close()
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
        _emit_line(item)
    if capture_handle is not None:
        capture_handle.close()
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
