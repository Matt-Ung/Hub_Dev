#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List

from experimental_batch_utils import (
    DEFAULT_MANIFEST_PATH,
    EXPERIMENTAL_ANALYSIS_ROOT,
    EXPERIMENTAL_SAMPLES_ROOT,
    compute_file_identity,
    ensure_dir,
    list_experimental_samples,
    load_sample_manifest,
    read_json,
    repo_python_executable,
    resolve_analyze_headless,
    run_command,
    shorten_text,
    tool_available,
    write_json,
)


def _build_automation_payload(identity: Dict[str, Any], ghidra_analysis: Dict[str, Any], sample_meta: Dict[str, Any]) -> Dict[str, Any]:
    program = ghidra_analysis.get("program") if isinstance(ghidra_analysis.get("program"), dict) else {}
    counts = ghidra_analysis.get("counts") if isinstance(ghidra_analysis.get("counts"), dict) else {}
    sections = list(ghidra_analysis.get("sections") or [])
    imports = list(ghidra_analysis.get("imports") or [])
    exports = list(ghidra_analysis.get("exports") or [])
    roots = list(ghidra_analysis.get("root_functions") or [])
    warnings = list(ghidra_analysis.get("autoAnalysisWarnings") or [])
    failures = list(ghidra_analysis.get("autoAnalysisFailures") or [])
    return {
        "source": "headless_batch",
        "program_name": str(program.get("name") or identity.get("name") or ""),
        "ghidra_project_path": str(program.get("ghidraProjectPath") or ""),
        "executable_path": str(program.get("executablePath") or identity.get("path") or ""),
        "executable_md5": str(program.get("executableMD5") or identity.get("md5") or ""),
        "executable_sha256": str(program.get("executableSHA256") or identity.get("sha256") or ""),
        "language": str(program.get("language") or ""),
        "compiler": str(program.get("compiler") or ""),
        "image_base": str(program.get("imageBase") or ""),
        "entry_point": str(program.get("entryPoint") or ""),
        "section_summary": sections[:32],
        "import_summary": imports[:128],
        "export_summary": exports[:64],
        "root_functions": roots[:32],
        "counts": counts,
        "auto_analysis_warnings": warnings[:64],
        "auto_analysis_failures": failures[:64],
        "analysis_token": "%s:%s" % (identity.get("sha256") or "", ghidra_analysis.get("generated_at_epoch") or ""),
        "program_info": {
            "program": program,
            "counts": counts,
        },
        "sample_manifest": sample_meta,
    }


def _collect_optional_cli_outputs(sample_path: Path, bundle_dir: Path, timeout_sec: int) -> Dict[str, Any]:
    outputs_dir = ensure_dir(bundle_dir / "tool_outputs")
    tool_results: Dict[str, Any] = {}
    jobs: List[tuple[str, list[str], str]] = [
        ("strings", ["strings", "-a", "-n", "4", str(sample_path)], "strings.txt"),
        ("floss", ["floss", str(sample_path)], "floss.txt"),
        ("capa", ["capa", "--json", str(sample_path)], "capa.json"),
        ("binwalk", ["binwalk", str(sample_path)], "binwalk.txt"),
        ("upx", ["upx", "-t", str(sample_path)], "upx_test.txt"),
    ]
    for label, argv, filename in jobs:
        available = tool_available(argv[0])
        result: Dict[str, Any] = {
            "available": available,
            "command": argv,
        }
        if not available:
            result["skipped"] = "command not found on PATH"
            tool_results[label] = result
            continue
        completed = run_command(argv, timeout_sec=timeout_sec)
        result.update(completed)
        output_path = outputs_dir / filename
        combined = ""
        if filename.endswith(".json"):
            combined = completed.get("stdout") or completed.get("stderr") or ""
            output_path.write_text(combined, encoding="utf-8")
        else:
            combined = (completed.get("stdout") or "") + ("\n" + completed.get("stderr") if completed.get("stderr") else "")
            output_path.write_text(combined, encoding="utf-8")
        result["output_path"] = str(output_path)
        result["stdout"] = shorten_text(str(completed.get("stdout") or ""))
        result["stderr"] = shorten_text(str(completed.get("stderr") or ""))
        tool_results[label] = result
    return tool_results


def _run_headless_export(
    analyze_headless: Path,
    sample_path: Path,
    bundle_dir: Path,
    timeout_sec: int,
    keep_project: bool,
) -> Dict[str, Any]:
    project_parent = ensure_dir(bundle_dir / "_ghidra_project")
    project_name = sample_path.stem + "_batch"
    output_json = bundle_dir / "ghidra_analysis.json"
    log_path = bundle_dir / "ghidra_headless.log"
    script_path = (Path(__file__).resolve().parent / "ghidra_headless_export.py").resolve()
    command = [
        str(analyze_headless),
        str(project_parent),
        project_name,
        "-import",
        str(sample_path),
        "-overwrite",
        "-analysisTimeoutPerFile",
        str(max(30, int(timeout_sec))),
        "-scriptPath",
        str(script_path.parent),
        "-postScript",
        script_path.name,
        str(output_json),
    ]
    if not keep_project:
        command.append("-deleteProject")
    result = run_command(command, timeout_sec=max(timeout_sec, timeout_sec + 60))
    combined_log = (result.get("stdout") or "") + ("\n" + result.get("stderr") if result.get("stderr") else "")
    log_path.write_text(combined_log, encoding="utf-8")
    result["log_path"] = str(log_path)
    result["analysis_path"] = str(output_json)
    result["analysis_exists"] = output_json.exists()
    result["stdout"] = shorten_text(str(result.get("stdout") or ""))
    result["stderr"] = shorten_text(str(result.get("stderr") or ""))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare structured analysis bundles for experimental test executables")
    parser.add_argument("--samples-dir", default=str(EXPERIMENTAL_SAMPLES_ROOT), help="Directory containing experimental .exe samples")
    parser.add_argument("--output-root", default=str(EXPERIMENTAL_ANALYSIS_ROOT), help="Directory to write per-sample bundles")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST_PATH), help="Sample manifest JSON path")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample filename(s) to restrict to")
    parser.add_argument("--ghidra-install-dir", default="", help="Optional GHIDRA_INSTALL_DIR override")
    parser.add_argument("--ghidra-headless", default="", help="Optional direct analyzeHeadless path")
    parser.add_argument("--timeout-sec", type=int, default=180, help="Timeout per tool/headless step")
    parser.add_argument("--skip-cli-tools", action="store_true", help="Skip optional local CLI tool collection")
    parser.add_argument("--keep-project", action="store_true", help="Preserve temporary headless Ghidra project directories")
    args = parser.parse_args()

    samples_dir = Path(args.samples_dir).resolve()
    output_root = ensure_dir(Path(args.output_root).resolve())
    manifest = load_sample_manifest(Path(args.manifest).resolve())
    requested = {name.strip() for name in args.sample if str(name).strip()}
    samples = [sample for sample in list_experimental_samples(samples_dir) if not requested or sample.name in requested]

    analyze_headless = resolve_analyze_headless(args.ghidra_install_dir, args.ghidra_headless)
    summary: Dict[str, Any] = {
        "generated_with": Path(__file__).name,
        "python": repo_python_executable(),
        "samples_dir": str(samples_dir),
        "output_root": str(output_root),
        "analyze_headless": str(analyze_headless) if analyze_headless else "",
        "ghidra_headless_available": bool(analyze_headless),
        "results": [],
    }

    for sample_path in samples:
        sample_meta = manifest["samples"].get(sample_path.name, {})
        bundle_dir = ensure_dir(output_root / sample_path.stem)
        identity = compute_file_identity(sample_path)
        write_json(bundle_dir / "file_identity.json", identity)

        result_record: Dict[str, Any] = {
            "sample": sample_path.name,
            "bundle_dir": str(bundle_dir),
            "identity": identity,
            "manifest": sample_meta,
        }

        if analyze_headless:
            headless_result = _run_headless_export(analyze_headless, sample_path, bundle_dir, args.timeout_sec, args.keep_project)
            result_record["ghidra_headless"] = headless_result
            ghidra_analysis: Dict[str, Any] = {}
            if headless_result.get("analysis_exists"):
                try:
                    ghidra_analysis = read_json(bundle_dir / "ghidra_analysis.json")
                except Exception as exc:
                    ghidra_analysis = {"error": "%s: %s" % (type(exc).__name__, exc)}
            result_record["ghidra_analysis_summary"] = {
                "ok": bool(headless_result.get("ok")) and isinstance(ghidra_analysis, dict) and not ghidra_analysis.get("error"),
                "functions": (((ghidra_analysis.get("counts") or {}) if isinstance(ghidra_analysis, dict) else {}) or {}).get("functions", 0),
                "strings": (((ghidra_analysis.get("counts") or {}) if isinstance(ghidra_analysis, dict) else {}) or {}).get("strings", 0),
                "imports": (((ghidra_analysis.get("counts") or {}) if isinstance(ghidra_analysis, dict) else {}) or {}).get("imports", 0),
                "exports": (((ghidra_analysis.get("counts") or {}) if isinstance(ghidra_analysis, dict) else {}) or {}).get("exports", 0),
            }
            if isinstance(ghidra_analysis, dict) and ghidra_analysis.get("program"):
                automation_payload = _build_automation_payload(identity, ghidra_analysis, sample_meta)
                write_json(bundle_dir / "automation_payload.json", automation_payload)
                result_record["automation_payload_path"] = str((bundle_dir / "automation_payload.json").resolve())
        else:
            result_record["ghidra_headless"] = {"ok": False, "error": "analyzeHeadless not found"}

        if args.skip_cli_tools:
            result_record["cli_tool_outputs"] = {"skipped": True}
        else:
            result_record["cli_tool_outputs"] = _collect_optional_cli_outputs(sample_path, bundle_dir, args.timeout_sec)

        write_json(bundle_dir / "bundle_manifest.json", result_record)
        summary["results"].append(result_record)

    write_json(output_root / "index.json", summary)
    print(json.dumps({"output_root": str(output_root), "samples": len(summary["results"])}, indent=2))


if __name__ == "__main__":
    main()
