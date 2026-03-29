#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from experimental_batch_utils import (
    DEFAULT_MANIFEST_PATH,
    EXPERIMENTAL_ANALYSIS_ROOT,
    EXPERIMENTAL_REPORTS_ROOT,
    ensure_dir,
    list_experimental_samples,
    load_sample_manifest,
    read_json,
    repo_python_executable,
    run_command,
    sample_slug,
    write_json,
)


def _maybe_prepare_artifacts(args: argparse.Namespace) -> None:
    if not args.prepare_if_missing:
        return
    output_root = Path(args.artifacts_root).resolve()
    missing = []
    for sample_path in list_experimental_samples(Path(args.samples_dir).resolve()):
        bundle_dir = output_root / sample_slug(sample_path)
        if not (bundle_dir / "ghidra_analysis.json").exists():
            missing.append(sample_path.name)
    if not missing:
        return

    prepare_script = Path(__file__).resolve().parent / "batch_prepare_experimental_samples.py"
    command = [
        repo_python_executable(),
        str(prepare_script),
        "--samples-dir",
        str(Path(args.samples_dir).resolve()),
        "--output-root",
        str(output_root),
        "--manifest",
        str(Path(args.manifest).resolve()),
    ]
    for sample_name in missing:
        command.extend(["--sample", sample_name])
    completed = run_command(command, timeout_sec=max(300, int(args.timeout_sec) * max(1, len(missing))))
    if not completed.get("ok"):
        raise RuntimeError("Artifact preparation failed: %s" % (completed.get("stderr") or completed.get("error") or "unknown error"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch-run the existing agent workflow over experimental executable bundles")
    parser.add_argument("--samples-dir", default=str((Path(__file__).resolve().parents[1] / "Testing" / "Experimental_Test_Executables").resolve()))
    parser.add_argument("--artifacts-root", default=str(EXPERIMENTAL_ANALYSIS_ROOT))
    parser.add_argument("--results-root", default=str(EXPERIMENTAL_REPORTS_ROOT))
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST_PATH))
    parser.add_argument("--pipeline", default="auto_triage")
    parser.add_argument("--architecture", default="balanced")
    parser.add_argument("--query", default="", help="Optional fixed query. Otherwise the sample manifest default is used.")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample filename(s) to restrict to.")
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument("--prepare-if-missing", action="store_true", help="Prepare missing bundles before running agent cases")
    args = parser.parse_args()

    samples_dir = Path(args.samples_dir).resolve()
    artifacts_root = ensure_dir(Path(args.artifacts_root).resolve())
    results_root = ensure_dir(Path(args.results_root).resolve())
    manifest = load_sample_manifest(Path(args.manifest).resolve())
    requested = {name.strip() for name in args.sample if str(name).strip()}

    _maybe_prepare_artifacts(args)

    run_script = Path(__file__).resolve().parent / "run_single_agent_case.py"
    aggregate: Dict[str, Any] = {
        "samples_dir": str(samples_dir),
        "artifacts_root": str(artifacts_root),
        "results_root": str(results_root),
        "pipeline": args.pipeline,
        "architecture": args.architecture,
        "results": [],
    }

    for sample_path in list_experimental_samples(samples_dir):
        if requested and sample_path.name not in requested:
            continue
        bundle_dir = artifacts_root / sample_slug(sample_path)
        if not bundle_dir.exists():
            aggregate["results"].append(
                {
                    "sample": sample_path.name,
                    "ok": False,
                    "error": "bundle directory not found",
                    "bundle_dir": str(bundle_dir),
                }
            )
            continue

        output_json = results_root / ("%s.result.json" % sample_slug(sample_path))
        query = str(args.query or "").strip() or str(manifest["samples"].get(sample_path.name, {}).get("default_query") or "")
        command = [
            repo_python_executable(),
            str(run_script),
            "--bundle-dir",
            str(bundle_dir),
            "--pipeline",
            args.pipeline,
            "--architecture",
            args.architecture,
            "--output-json",
            str(output_json),
        ]
        if query:
            command.extend(["--query", query])
        completed = run_command(command, timeout_sec=args.timeout_sec)
        if output_json.exists():
            sample_result = read_json(output_json)
        else:
            sample_result = {
                "sample": sample_path.name,
                "ok": False,
                "error": completed.get("stderr") or completed.get("error") or "run script failed without output",
            }
        sample_result["sample"] = sample_path.name
        sample_result["difficulty"] = manifest["samples"].get(sample_path.name, {}).get("difficulty", "")
        sample_result["target_tools"] = manifest["samples"].get(sample_path.name, {}).get("target_tools", [])
        sample_result["runner_ok"] = bool(completed.get("ok"))
        aggregate["results"].append(sample_result)

    difficulty_summary: Dict[str, Dict[str, Any]] = {}
    for item in aggregate["results"]:
        difficulty = str(item.get("difficulty") or "unknown")
        bucket = difficulty_summary.setdefault(difficulty, {"samples": 0, "ok": 0})
        bucket["samples"] += 1
        if item.get("ok"):
            bucket["ok"] += 1
    aggregate["difficulty_summary"] = difficulty_summary
    write_json(results_root / "batch_summary.json", aggregate)
    print(json.dumps({"results_root": str(results_root), "sample_runs": len(aggregate["results"])}, indent=2))


if __name__ == "__main__":
    main()
