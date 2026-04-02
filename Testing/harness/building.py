from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from .paths import ensure_dir
from .samples import CorpusConfig, get_corpus_config
from .subprocess_utils import run_command


def _makefile_has_target(source_root: Path, target: str) -> bool:
    makefile = source_root / "Makefile"
    if not makefile.exists():
        return False
    try:
        text = makefile.read_text(encoding="utf-8")
    except Exception:
        return False
    needle = f"{target}:"
    return any(line.strip().startswith(needle) for line in text.splitlines())


def build_corpus(
    corpus_name: str,
    *,
    clean_first: bool = False,
    include_gcc: bool = True,
    timeout_sec: int | None = None,
) -> Dict[str, Any]:
    config = get_corpus_config(corpus_name)
    ensure_dir(config.build_root)
    records: List[Dict[str, Any]] = []
    make_env = {"OUT_DIR": os.path.relpath(config.build_root, config.source_root)}

    if clean_first:
        records.append(
            {
                "step": "clean",
                **run_command(
                    ["make", "clean"],
                    cwd=config.source_root,
                    timeout_sec=timeout_sec,
                    env=make_env,
                ),
            }
        )

    target = "all-with-gcc" if include_gcc else "all"
    records.append(
        {
            "step": target,
            **run_command(
                ["make", target],
                cwd=config.source_root,
                timeout_sec=timeout_sec,
                env=make_env,
            ),
        }
    )

    if _makefile_has_target(config.source_root, "upx"):
        upx_record = {
            "step": "upx",
            "optional": True,
            **run_command(
                ["make", "upx"],
                cwd=config.source_root,
                timeout_sec=timeout_sec,
                env=make_env,
            ),
        }
        records.append(upx_record)

    outputs = sorted(path.name for path in config.build_root.glob("*.exe") if path.is_file())
    required_records = [record for record in records if record.get("step") not in {"clean", "upx"}]
    optional_failures = [
        {
            "step": record.get("step"),
            "stderr": record.get("stderr"),
            "stdout": record.get("stdout"),
        }
        for record in records
        if record.get("optional") and not bool(record.get("ok"))
    ]
    return {
        "corpus": corpus_name,
        "source_root": str(config.source_root),
        "build_root": str(config.build_root),
        "outputs": outputs,
        "steps": records,
        "optional_step_failures": optional_failures,
        "ok": all(bool(record.get("ok")) for record in required_records),
    }
