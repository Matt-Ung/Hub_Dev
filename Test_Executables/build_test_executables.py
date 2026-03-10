#!/usr/bin/env python3
"""
Build benign Windows test executables for MCP malware-analysis workflows.

Usage:
  python3 build_test_executables.py
  python3 build_test_executables.py --compiler x86_64-w64-mingw32-gcc
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class BuildSpec:
    source: str
    output: str
    cflags: List[str]


SPECS: List[BuildSpec] = [
    BuildSpec("test.c", "test.exe", ["-O2"]),
    BuildSpec("floss_test.c", "floss_test.exe", ["-O0"]),
    BuildSpec("floss_test.c", "floss_test_02.exe", ["-O2", "-fno-inline"]),
    BuildSpec("floss_test.c", "floss_test_stripped.exe", ["-O2", "-s"]),
    BuildSpec("anti_debug_test.c", "anti_debug_test.exe", ["-O2"]),
    BuildSpec("winapi_behavior_test.c", "winapi_behavior_test.exe", ["-O2"]),
]


def compiler_works(cmd: List[str]) -> bool:
    probe_src = "#include <stdio.h>\nint main(void){return 0;}\n"
    with tempfile.TemporaryDirectory(prefix="exe_build_probe_") as td:
        out = Path(td) / "probe.exe"
        proc = subprocess.run(
            [*cmd, "-x", "c", "-", "-o", str(out)],
            input=probe_src,
            text=True,
            capture_output=True,
        )
        return proc.returncode == 0


def pick_compiler(cli_value: str | None) -> List[str]:
    if cli_value:
        first = cli_value.split(" ", 1)[0]
        if shutil.which(first) is None:
            raise FileNotFoundError(f"Compiler not found on PATH: {first}")
        chosen = cli_value.split()
        if not compiler_works(chosen):
            raise FileNotFoundError(
                f"Compiler exists but cannot build Windows targets in this environment: {' '.join(chosen)}"
            )
        return chosen

    candidates = [
        ["x86_64-w64-mingw32-gcc"],
        ["i686-w64-mingw32-gcc"],
        ["clang", "--target=x86_64-w64-windows-gnu"],
    ]
    for candidate in candidates:
        if shutil.which(candidate[0]) and compiler_works(candidate):
            return candidate
    raise FileNotFoundError(
        "No working Windows cross-compiler found. Install one of: "
        "x86_64-w64-mingw32-gcc, i686-w64-mingw32-gcc, or clang with a MinGW target runtime+headers."
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_one(root: Path, compiler: List[str], spec: BuildSpec) -> dict:
    src = root / spec.source
    out = root / spec.output
    if not src.exists():
        return {
            "source": spec.source,
            "output": spec.output,
            "ok": False,
            "error": f"missing source file: {src}",
        }

    cmd = [*compiler, "-Wall", "-Wextra", *spec.cflags, str(src), "-o", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            "source": spec.source,
            "output": spec.output,
            "ok": False,
            "command": cmd,
            "stderr": proc.stderr.strip(),
            "stdout": proc.stdout.strip(),
        }

    return {
        "source": spec.source,
        "output": spec.output,
        "ok": True,
        "size_bytes": out.stat().st_size,
        "sha256": sha256_file(out),
        "command": cmd,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Windows test executables.")
    parser.add_argument("--compiler", help="Compiler command (e.g., x86_64-w64-mingw32-gcc)")
    parser.add_argument(
        "--manifest",
        default="build_manifest.json",
        help="Where to write JSON build manifest (default: build_manifest.json)",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    try:
        compiler = pick_compiler(args.compiler)
    except FileNotFoundError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    results = [build_one(root, compiler, spec) for spec in SPECS]
    manifest = {
        "compiler": compiler,
        "root": str(root),
        "results": results,
    }
    (root / args.manifest).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    ok_count = sum(1 for r in results if r.get("ok"))
    print(f"Built {ok_count}/{len(results)} executable(s).")
    print(f"Manifest: {root / args.manifest}")
    for r in results:
        status = "OK" if r.get("ok") else "FAIL"
        print(f"- {status}: {r['output']}")

    return 0 if ok_count == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
