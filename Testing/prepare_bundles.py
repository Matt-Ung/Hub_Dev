#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness.artifacts import inspect_corpus_bundles, prepare_corpus_bundles
from harness.building import build_corpus
from harness.paths import BUNDLE_ROOT, build_run_id, ensure_dir, write_json
from harness.samples import get_corpus_config, list_sample_binaries, load_sample_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build sample binaries if needed and prepare artifact bundles for the binary testing harness.")
    parser.add_argument("--corpus", choices=["prototype", "experimental"], default="experimental")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample filename(s) to restrict to")
    parser.add_argument("--skip-build", action="store_true", help="Reuse existing binaries in Testing/build")
    parser.add_argument("--clean-build", action="store_true", help="Run make clean before rebuilding")
    parser.add_argument("--skip-cli-tools", action="store_true", help="Skip optional CLI tool collection while preparing bundles")
    parser.add_argument("--keep-project", action="store_true", help="Preserve temporary Ghidra headless projects")
    parser.add_argument("--ghidra-install-dir", default="", help="Optional GHIDRA_INSTALL_DIR override")
    parser.add_argument("--ghidra-headless", default="", help="Optional analyzeHeadless override")
    parser.add_argument("--timeout-sec", type=int, default=900)
    args = parser.parse_args()

    config = get_corpus_config(args.corpus)
    manifest = load_sample_manifest(args.corpus)
    prep_id = build_run_id("prepare", args.corpus)
    output_root = ensure_dir(BUNDLE_ROOT / args.corpus)
    prep_root = ensure_dir(output_root / "_prepare_runs" / prep_id)

    build_record = {"skipped": True}
    if not args.skip_build:
        build_record = build_corpus(
            args.corpus,
            clean_first=args.clean_build,
            include_gcc=True,
            timeout_sec=args.timeout_sec,
        )

    sample_paths = list_sample_binaries(args.corpus, selected=args.sample)
    if not sample_paths:
        raise SystemExit(f"No built sample binaries found for corpus={args.corpus} under {config.build_root}")

    prepare_record = prepare_corpus_bundles(
        args.corpus,
        sample_paths,
        manifest.get("samples") or {},
        output_root=output_root,
        timeout_sec=args.timeout_sec,
        ghidra_install_dir=args.ghidra_install_dir,
        ghidra_headless=args.ghidra_headless,
        skip_cli_tools=args.skip_cli_tools,
        keep_project=args.keep_project,
    )
    bundle_readiness = inspect_corpus_bundles(args.corpus, sample_paths, output_root=output_root)

    write_json(prep_root / "build_record.json", build_record)
    write_json(prep_root / "prepare_record.json", prepare_record)
    write_json(prep_root / "bundle_readiness.json", bundle_readiness)

    payload = {
        "prepare_id": prep_id,
        "corpus": args.corpus,
        "bundle_root": str(output_root),
        "ready_for_analysis": bool(bundle_readiness.get("ready_for_analysis")),
        "ready_count": int(bundle_readiness.get("ready_count") or 0),
        "sample_count": int(bundle_readiness.get("sample_count") or 0),
        "report_dir": str(prep_root),
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
