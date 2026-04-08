from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from .paths import BUNDLE_ROOT, CONFIG_ROOT, DEFAULT_SERVERS_MANIFEST, REPO_ROOT, ensure_dir, read_json, write_json
from .samples import get_corpus_config, sample_slug
from .subprocess_utils import normalize_timeout_sec, run_command, shorten_text, tool_available


REQUIRED_BUNDLE_FILES = ("bundle_manifest.json", "ghidra_analysis.json")
OPTIONAL_BUNDLE_FILES = ("automation_payload.json", "file_identity.json")
BUNDLE_INPUT_FINGERPRINT_VERSION = "bundle_inputs_v1"
BUNDLE_PREPARER_VERSION = "bundle_preparer_v1"
UPX_DERIVED_BUNDLE_LABEL = "upx_unpacked"
UPX_DERIVED_LOCK_WAIT_TIMEOUT_SEC = 1800
UPX_DERIVED_LOCK_STALE_AFTER_SEC = 3600


@contextmanager
def _bundle_materialization_lock(
    bundle_dir: Path,
    *,
    wait_timeout_sec: int = UPX_DERIVED_LOCK_WAIT_TIMEOUT_SEC,
    stale_after_sec: int = UPX_DERIVED_LOCK_STALE_AFTER_SEC,
):
    lock_dir = (bundle_dir.resolve() / "derived" / ".upx_unpacked_build.lock").resolve()
    ensure_dir(lock_dir.parent)
    deadline = time.monotonic() + max(1, int(wait_timeout_sec or 1))
    acquired = False
    while True:
        try:
            lock_dir.mkdir(parents=False, exist_ok=False)
            write_json(
                lock_dir / "owner.json",
                {
                    "pid": os.getpid(),
                    "started_at_epoch": time.time(),
                    "bundle_dir": str(bundle_dir.resolve()),
                },
            )
            acquired = True
            break
        except FileExistsError:
            if stale_after_sec > 0:
                try:
                    age_sec = time.time() - lock_dir.stat().st_mtime
                    if age_sec >= float(stale_after_sec):
                        shutil.rmtree(lock_dir, ignore_errors=True)
                        continue
                except FileNotFoundError:
                    continue
                except Exception:
                    pass
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Timed out waiting for the shared UPX-derived bundle lock at {lock_dir}"
                )
            time.sleep(1.0)
    try:
        yield lock_dir
    finally:
        if acquired:
            shutil.rmtree(lock_dir, ignore_errors=True)


def compute_file_identity(path: Path, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size_bytes = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            size_bytes += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "name": path.name,
        "size_bytes": size_bytes,
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "mtime_epoch": int(stat.st_mtime),
    }


def _compute_text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_bundle_executable_path(bundle_dir: Path, bundle_manifest: Dict[str, Any], automation_payload: Dict[str, Any]) -> Path | None:
    candidates = [
        str(automation_payload.get("executable_path") or "").strip(),
        str((((bundle_manifest.get("identity") or {}) if isinstance(bundle_manifest.get("identity"), dict) else {}) or {}).get("path") or "").strip(),
    ]
    for value in candidates:
        if not value:
            continue
        candidate = Path(value).expanduser()
        if candidate.exists():
            return candidate.resolve()
    return None


def _upx_recognized(stdout: str, stderr: str) -> bool:
    combined = f"{stdout or ''}\n{stderr or ''}".lower()
    return "not packed by upx" not in combined and "not packed" not in combined


def _run_upx_test(sample_path: Path, timeout_sec: int | None) -> Dict[str, Any]:
    if not tool_available("upx"):
        return {
            "available": False,
            "ok": False,
            "recognized": False,
            "command": ["upx", "-t", str(sample_path.resolve())],
            "file_path": str(sample_path.resolve()),
            "error": "upx not found on PATH",
        }
    completed = run_command(["upx", "-t", str(sample_path.resolve())], timeout_sec=timeout_sec or 30)
    stdout = shorten_text(str(completed.get("stdout") or ""))
    stderr = shorten_text(str(completed.get("stderr") or ""))
    return {
        "available": True,
        "ok": bool(completed.get("ok")),
        "recognized": _upx_recognized(stdout, stderr),
        "returncode": completed.get("returncode"),
        "command": completed.get("command") or ["upx", "-t", str(sample_path.resolve())],
        "file_path": str(sample_path.resolve()),
        "stdout": stdout,
        "stderr": stderr,
        "error": str(completed.get("error") or "").strip(),
    }


def _run_upx_unpack(sample_path: Path, output_path: Path, timeout_sec: int | None, *, force: bool = True) -> Dict[str, Any]:
    if not tool_available("upx"):
        return {
            "available": False,
            "ok": False,
            "file_path": str(sample_path.resolve()),
            "output_path": str(output_path.resolve()),
            "output_exists": output_path.exists(),
            "command": ["upx", "-d", "-o", str(output_path.resolve()), str(sample_path.resolve())],
            "error": "upx not found on PATH",
        }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if force and output_path.exists():
        output_path.unlink()
    command = ["upx", "-d", "-o", str(output_path.resolve()), str(sample_path.resolve())]
    completed = run_command(command, timeout_sec=timeout_sec or 180)
    stdout = shorten_text(str(completed.get("stdout") or ""))
    stderr = shorten_text(str(completed.get("stderr") or ""))
    output_exists = output_path.exists()
    return {
        "available": True,
        "ok": bool(completed.get("ok")) and output_exists,
        "returncode": completed.get("returncode"),
        "command": completed.get("command") or command,
        "file_path": str(sample_path.resolve()),
        "output_path": str(output_path.resolve()),
        "output_exists": output_exists,
        "stdout": stdout,
        "stderr": stderr,
        "error": str(completed.get("error") or ("" if (bool(completed.get("ok")) and output_exists) else (stderr or stdout))).strip(),
    }


def _bundle_identity(bundle_manifest: Dict[str, Any], sample_path: Path | None = None) -> Dict[str, Any]:
    identity = bundle_manifest.get("identity") if isinstance(bundle_manifest.get("identity"), dict) else {}
    if identity:
        return dict(identity)
    if sample_path is not None and sample_path.exists():
        return compute_file_identity(sample_path)
    return {}


def _write_analysis_target_metadata(
    bundle_dir: Path,
    *,
    analysis_target: Dict[str, Any],
    original_identity: Dict[str, Any],
    original_bundle_dir: Path,
    upx_detection: Dict[str, Any],
    upx_unpack: Dict[str, Any],
) -> None:
    manifest_path = bundle_dir / "bundle_manifest.json"
    manifest = read_json(manifest_path) if manifest_path.exists() else {}
    manifest["analysis_target"] = analysis_target
    manifest["original_identity"] = dict(original_identity)
    manifest["derived_from_bundle_dir"] = str(original_bundle_dir.resolve())
    manifest["upx_detection"] = dict(upx_detection)
    manifest["upx_unpack"] = dict(upx_unpack)
    write_json(manifest_path, manifest)

    payload_path = bundle_dir / "automation_payload.json"
    payload = read_json(payload_path) if payload_path.exists() else {}
    payload["analysis_target"] = analysis_target
    payload["original_sample"] = {
        "path": str(original_identity.get("path") or ""),
        "md5": str(original_identity.get("md5") or ""),
        "sha256": str(original_identity.get("sha256") or ""),
        "name": str(original_identity.get("name") or ""),
    }
    payload["upx_detection"] = dict(upx_detection)
    payload["upx_unpack"] = dict(upx_unpack)
    write_json(payload_path, payload)

    write_json(
        bundle_dir / "upx_unpack.json",
        {
            "analysis_target": analysis_target,
            "original_identity": dict(original_identity),
            "original_bundle_dir": str(original_bundle_dir.resolve()),
            "upx_detection": dict(upx_detection),
            "upx_unpack": dict(upx_unpack),
        },
    )


def compute_bundle_inputs(sample_path: Path, analyze_headless: Path | None = None) -> Dict[str, Any]:
    export_script = (REPO_ROOT / "Testing" / "harness" / "GhidraHeadlessExport.java").resolve()
    sample_identity = compute_file_identity(sample_path)
    return {
        "fingerprint_version": BUNDLE_INPUT_FINGERPRINT_VERSION,
        "bundle_preparer_version": BUNDLE_PREPARER_VERSION,
        "sample_identity": {
            "path": sample_identity.get("path"),
            "name": sample_identity.get("name"),
            "size_bytes": sample_identity.get("size_bytes"),
            "sha256": sample_identity.get("sha256"),
            "mtime_epoch": sample_identity.get("mtime_epoch"),
        },
        "required_bundle_files": list(REQUIRED_BUNDLE_FILES),
        "ghidra_export_script": {
            "path": str(export_script),
            "sha256": _compute_text_sha256(export_script),
        },
        "resolved_analyze_headless": str(analyze_headless.resolve()) if analyze_headless and analyze_headless.exists() else "",
    }


def _bundle_freshness(bundle_dir: Path, sample_path: Path, analyze_headless: Path | None = None) -> Dict[str, Any]:
    manifest_path = bundle_dir / "bundle_manifest.json"
    current_inputs = compute_bundle_inputs(sample_path, analyze_headless=analyze_headless)
    if not manifest_path.exists():
        return {
            "fresh_for_analysis": False,
            "status": "missing_manifest",
            "stale_reasons": ["bundle_manifest.json is missing"],
            "current_bundle_inputs": current_inputs,
        }

    try:
        manifest = read_json(manifest_path)
    except Exception as exc:
        return {
            "fresh_for_analysis": False,
            "status": "invalid_manifest",
            "stale_reasons": [f"bundle_manifest.json is unreadable: {type(exc).__name__}: {exc}"],
            "current_bundle_inputs": current_inputs,
        }

    recorded = manifest.get("bundle_inputs") if isinstance(manifest.get("bundle_inputs"), dict) else {}
    reasons: List[str] = []
    if not recorded:
        reasons.append("bundle freshness fingerprint is missing from bundle_manifest.json")
    else:
        if str(recorded.get("fingerprint_version") or "") != BUNDLE_INPUT_FINGERPRINT_VERSION:
            reasons.append("bundle fingerprint version differs from the current harness")
        if str(recorded.get("bundle_preparer_version") or "") != BUNDLE_PREPARER_VERSION:
            reasons.append("bundle preparer version differs from the current harness")
        recorded_identity = recorded.get("sample_identity") if isinstance(recorded.get("sample_identity"), dict) else {}
        current_identity = current_inputs.get("sample_identity") if isinstance(current_inputs.get("sample_identity"), dict) else {}
        if str(recorded_identity.get("sha256") or "") != str(current_identity.get("sha256") or ""):
            reasons.append("sample binary sha256 changed since the bundle was generated")
        if str(recorded_identity.get("size_bytes") or "") != str(current_identity.get("size_bytes") or ""):
            reasons.append("sample binary size changed since the bundle was generated")
        recorded_script = recorded.get("ghidra_export_script") if isinstance(recorded.get("ghidra_export_script"), dict) else {}
        current_script = current_inputs.get("ghidra_export_script") if isinstance(current_inputs.get("ghidra_export_script"), dict) else {}
        if str(recorded_script.get("sha256") or "") != str(current_script.get("sha256") or ""):
            reasons.append("Ghidra headless export script changed since the bundle was generated")

    return {
        "fresh_for_analysis": not reasons,
        "status": "fresh" if not reasons else "stale",
        "stale_reasons": reasons,
        "recorded_bundle_inputs": recorded,
        "current_bundle_inputs": current_inputs,
    }


def resolve_analyze_headless(ghidra_install_dir: str = "", ghidra_headless: str = "") -> Path | None:
    explicit = str(ghidra_headless or os.environ.get("GHIDRA_HEADLESS") or "").strip()
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.exists():
            return candidate.resolve()

    install_dir = str(ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR") or "").strip()
    if install_dir:
        candidate = Path(install_dir).expanduser() / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        if candidate.exists():
            return candidate.resolve()

    discovered = shutil.which("analyzeHeadless")
    if discovered:
        return Path(discovered).resolve()
    return None


def _build_automation_payload(identity: Dict[str, Any], ghidra_analysis: Dict[str, Any], sample_meta: Dict[str, Any], corpus_name: str) -> Dict[str, Any]:
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
        "corpus": corpus_name,
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
        "program_info": {"program": program, "counts": counts},
        "sample_manifest": sample_meta,
    }


def _collect_optional_cli_outputs(sample_path: Path, bundle_dir: Path, timeout_sec: int | None) -> Dict[str, Any]:
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
        result: Dict[str, Any] = {"available": available, "command": argv}
        if not available:
            result["skipped"] = "command not found on PATH"
            tool_results[label] = result
            continue
        completed = run_command(argv, timeout_sec=timeout_sec)
        result.update(completed)
        output_path = outputs_dir / filename
        combined = completed.get("stdout") or completed.get("stderr") or ""
        if filename.endswith(".json"):
            output_path.write_text(combined, encoding="utf-8")
        else:
            merged = (completed.get("stdout") or "") + ("\n" + completed.get("stderr") if completed.get("stderr") else "")
            output_path.write_text(merged, encoding="utf-8")
        result["output_path"] = str(output_path)
        result["stdout"] = shorten_text(str(completed.get("stdout") or ""))
        result["stderr"] = shorten_text(str(completed.get("stderr") or ""))
        tool_results[label] = result
    return tool_results


def _run_headless_export(
    analyze_headless: Path,
    sample_path: Path,
    bundle_dir: Path,
    timeout_sec: int | None,
    keep_project: bool,
) -> Dict[str, Any]:
    project_parent = ensure_dir(bundle_dir / "_ghidra_project")
    project_name = sample_path.stem + "_batch"
    output_json = bundle_dir / "ghidra_analysis.json"
    log_path = bundle_dir / "ghidra_headless.log"
    script_path = (REPO_ROOT / "Testing" / "harness" / "GhidraHeadlessExport.java").resolve()
    normalized_timeout = normalize_timeout_sec(timeout_sec)
    command = [
        str(analyze_headless),
        str(project_parent),
        project_name,
        "-import",
        str(sample_path),
        "-overwrite",
        "-scriptPath",
        str(script_path.parent),
        "-postScript",
        script_path.name,
        str(output_json),
    ]
    if normalized_timeout is not None:
        command[6:6] = ["-analysisTimeoutPerFile", str(max(30, normalized_timeout))]
    if not keep_project:
        command.append("-deleteProject")
    launch_env: Dict[str, str] = {}
    ghidra_java_home = str(os.environ.get("GHIDRA_JAVA_HOME") or os.environ.get("JAVA_HOME") or "").strip()
    if ghidra_java_home:
        launch_env["JAVA_HOME"] = ghidra_java_home
    command_timeout = normalized_timeout + 60 if normalized_timeout is not None else None
    result = run_command(command, timeout_sec=command_timeout, env=launch_env or None)
    combined_log = (result.get("stdout") or "") + ("\n" + result.get("stderr") if result.get("stderr") else "")
    log_path.write_text(combined_log, encoding="utf-8")
    result["log_path"] = str(log_path)
    result["analysis_path"] = str(output_json)
    result["analysis_exists"] = output_json.exists()
    result["java_home"] = ghidra_java_home
    result["ok"] = bool(result.get("ok")) and output_json.exists()
    if not result["analysis_exists"] and not result.get("error"):
        result["error"] = "ghidra_analysis.json was not generated by the headless export script"
    result["stdout"] = shorten_text(str(result.get("stdout") or ""))
    result["stderr"] = shorten_text(str(result.get("stderr") or ""))
    return result


def prepare_bundle(
    corpus_name: str,
    sample_path: Path,
    sample_meta: Dict[str, Any],
    *,
    output_root: Path | None = None,
    timeout_sec: int | None = None,
    analyze_headless: Path | None = None,
    skip_cli_tools: bool = False,
    keep_project: bool = False,
) -> Dict[str, Any]:
    bundle_root = output_root or ensure_dir(BUNDLE_ROOT / corpus_name)
    bundle_dir = ensure_dir(bundle_root / sample_slug(sample_path))
    existing_readiness = inspect_bundle_dir(bundle_dir, sample_path=sample_path, analyze_headless=analyze_headless)
    if bool(existing_readiness.get("fresh_for_analysis")):
        existing_manifest = read_json(bundle_dir / "bundle_manifest.json")
        result_record = dict(existing_manifest)
        result_record["sample"] = sample_path.name
        result_record["corpus"] = corpus_name
        result_record["bundle_dir"] = str(bundle_dir)
        result_record["skipped"] = True
        result_record["skip_reason"] = "fresh_bundle"
        result_record["bundle_readiness"] = existing_readiness
        return result_record

    identity = compute_file_identity(sample_path)
    write_json(bundle_dir / "file_identity.json", identity)

    result_record: Dict[str, Any] = {
        "sample": sample_path.name,
        "corpus": corpus_name,
        "bundle_dir": str(bundle_dir),
        "identity": identity,
        "manifest": sample_meta,
        "bundle_inputs": compute_bundle_inputs(sample_path, analyze_headless=analyze_headless),
    }

    if analyze_headless:
        headless_result = _run_headless_export(analyze_headless, sample_path, bundle_dir, timeout_sec, keep_project)
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
            automation_payload = _build_automation_payload(identity, ghidra_analysis, sample_meta, corpus_name)
            write_json(bundle_dir / "automation_payload.json", automation_payload)
            result_record["automation_payload_path"] = str((bundle_dir / "automation_payload.json").resolve())
    else:
        result_record["ghidra_headless"] = {"ok": False, "error": "analyzeHeadless not found"}

    result_record["cli_tool_outputs"] = {"skipped": True} if skip_cli_tools else _collect_optional_cli_outputs(sample_path, bundle_dir, timeout_sec)
    write_json(bundle_dir / "bundle_manifest.json", result_record)
    result_record["bundle_readiness"] = inspect_bundle_dir(bundle_dir)
    write_json(bundle_dir / "bundle_manifest.json", result_record)
    return result_record


def resolve_analysis_bundle(
    bundle_dir: Path,
    *,
    prefer_upx_unpacked: bool = False,
    timeout_sec: int | None = None,
    ghidra_install_dir: str = "",
    ghidra_headless: str = "",
    skip_cli_tools: bool = False,
    keep_project: bool = False,
) -> Dict[str, Any]:
    """
    Function: resolve_analysis_bundle
    Inputs:
      - bundle_dir: original prepared bundle directory for the packed-or-plain sample.
      - prefer_upx_unpacked: when true, attempt UPX detect -> unpack -> derived bundle.
      - timeout_sec / ghidra_install_dir / ghidra_headless / skip_cli_tools / keep_project:
        preparation knobs reused when materializing a derived unpacked bundle.
    Description:
      Resolve the effective analysis bundle for one run. By default this is the
      original prepared bundle. When `prefer_upx_unpacked` is enabled and the
      original executable is recognized by UPX, this helper materializes a
      derived unpacked bundle and returns it as the effective target.
    Outputs:
      Returns a dictionary containing the effective bundle dir, manifest,
      automation payload, and structured analysis-target provenance.
    Side Effects:
      May run `upx -t`, `upx -d`, `analyzeHeadless`, and optional CLI tools to
      create a derived unpacked bundle under `<bundle_dir>/derived/`.
    """
    bundle_dir = bundle_dir.resolve()
    bundle_manifest_path = bundle_dir / "bundle_manifest.json"
    automation_payload_path = bundle_dir / "automation_payload.json"
    bundle_manifest = read_json(bundle_manifest_path) if bundle_manifest_path.exists() else {}
    automation_payload = read_json(automation_payload_path) if automation_payload_path.exists() else {}
    original_sample_path = _resolve_bundle_executable_path(bundle_dir, bundle_manifest, automation_payload)
    original_identity = _bundle_identity(bundle_manifest, sample_path=original_sample_path)
    analysis_target: Dict[str, Any] = {
        "requested_mode": "prefer_upx_unpacked" if prefer_upx_unpacked else "original_only",
        "kind": "original",
        "selection_reason": (
            "UPX-unpacked analysis was not requested."
            if not prefer_upx_unpacked
            else "Falling back to the original prepared bundle."
        ),
        "effective_bundle_dir": str(bundle_dir),
        "effective_executable_path": str(original_sample_path.resolve()) if original_sample_path is not None else "",
        "effective_executable_md5": str(original_identity.get("md5") or ""),
        "effective_executable_sha256": str(original_identity.get("sha256") or ""),
        "original_bundle_dir": str(bundle_dir),
        "original_executable_path": str(original_identity.get("path") or ""),
        "original_executable_md5": str(original_identity.get("md5") or ""),
        "original_executable_sha256": str(original_identity.get("sha256") or ""),
        "packer": "",
        "packed_detected": False,
        "derived_bundle_ready": False,
        "upx_detection": {},
        "upx_unpack": {},
    }
    result = {
        "bundle_dir": bundle_dir,
        "bundle_manifest": bundle_manifest,
        "automation_payload": automation_payload,
        "analysis_target": analysis_target,
    }
    if not prefer_upx_unpacked:
        return result
    if original_sample_path is None:
        analysis_target["selection_reason"] = "Unable to resolve the original executable path from the prepared bundle."
        return result

    upx_detection = _run_upx_test(original_sample_path, timeout_sec=timeout_sec)
    analysis_target["upx_detection"] = dict(upx_detection)
    analysis_target["packer"] = "upx" if bool(upx_detection.get("recognized")) else ""
    analysis_target["packed_detected"] = bool(upx_detection.get("recognized"))
    if not bool(upx_detection.get("available")):
        analysis_target["selection_reason"] = "UPX was requested but the `upx` executable is not available on PATH."
        return result
    if not bool(upx_detection.get("recognized")):
        analysis_target["selection_reason"] = "UPX did not recognize the original sample as packed."
        return result

    analyze_headless = resolve_analyze_headless(ghidra_install_dir, ghidra_headless)
    if analyze_headless is None:
        analysis_target["selection_reason"] = (
            "UPX was detected, but analyzeHeadless is unavailable so the derived unpacked bundle could not be built."
        )
        return result

    derived_output_path = (
        bundle_dir
        / "derived"
        / "upx_unpacked_binary"
        / f"{original_sample_path.stem}_upx_unpacked{(original_sample_path.suffix or '.bin')}"
    ).resolve()
    derived_root = ensure_dir(bundle_dir / "derived" / UPX_DERIVED_BUNDLE_LABEL)
    derived_bundle_dir = derived_root / sample_slug(derived_output_path)
    try:
        with _bundle_materialization_lock(bundle_dir):
            derived_readiness = (
                inspect_bundle_dir(derived_bundle_dir, sample_path=derived_output_path, analyze_headless=analyze_headless)
                if derived_output_path.exists()
                else {"ready_for_analysis": False, "fresh_for_analysis": False}
            )
            if not (bool(derived_readiness.get("ready_for_analysis")) and bool(derived_readiness.get("fresh_for_analysis"))):
                upx_unpack = _run_upx_unpack(original_sample_path, derived_output_path, timeout_sec=timeout_sec, force=True)
                analysis_target["upx_unpack"] = dict(upx_unpack)
                if not bool(upx_unpack.get("ok")):
                    analysis_target["selection_reason"] = (
                        "UPX detected the sample, but unpacking failed. Continuing with the original prepared bundle."
                    )
                    return result

                derived_corpus_name = str(bundle_manifest.get("corpus") or automation_payload.get("corpus") or "experimental").strip() or "experimental"
                derived_prepare = prepare_bundle(
                    derived_corpus_name,
                    derived_output_path,
                    ((bundle_manifest.get("manifest") or {}) if isinstance(bundle_manifest.get("manifest"), dict) else {}),
                    output_root=derived_root,
                    timeout_sec=timeout_sec,
                    analyze_headless=analyze_headless,
                    skip_cli_tools=skip_cli_tools,
                    keep_project=keep_project,
                )
                derived_bundle_dir = Path(str(derived_prepare.get("bundle_dir") or derived_bundle_dir)).resolve()
                derived_readiness = inspect_bundle_dir(
                    derived_bundle_dir,
                    sample_path=derived_output_path,
                    analyze_headless=analyze_headless,
                )
                if not bool(derived_readiness.get("ready_for_analysis")):
                    analysis_target["selection_reason"] = (
                        "UPX unpacking succeeded, but the derived unpacked bundle is incomplete. Continuing with the original prepared bundle."
                    )
                    return result
            else:
                analysis_target["upx_unpack"] = {
                    "available": True,
                    "ok": True,
                    "output_path": str(derived_output_path),
                    "output_exists": True,
                    "skipped": True,
                    "reason": "fresh_derived_bundle",
                }

            derived_manifest_path = derived_bundle_dir / "bundle_manifest.json"
            derived_payload_path = derived_bundle_dir / "automation_payload.json"
            derived_manifest = read_json(derived_manifest_path) if derived_manifest_path.exists() else {}
            derived_payload = read_json(derived_payload_path) if derived_payload_path.exists() else {}
            derived_identity = _bundle_identity(derived_manifest, sample_path=derived_output_path)
            analysis_target.update(
                {
                    "kind": UPX_DERIVED_BUNDLE_LABEL,
                    "selection_reason": "UPX packing was detected; downstream analysis is using a derived unpacked bundle.",
                    "effective_bundle_dir": str(derived_bundle_dir),
                    "effective_executable_path": str(derived_identity.get("path") or derived_output_path),
                    "effective_executable_md5": str(derived_identity.get("md5") or ""),
                    "effective_executable_sha256": str(derived_identity.get("sha256") or ""),
                    "derived_bundle_ready": True,
                }
            )
            _write_analysis_target_metadata(
                derived_bundle_dir,
                analysis_target=analysis_target,
                original_identity=original_identity,
                original_bundle_dir=bundle_dir,
                upx_detection=upx_detection,
                upx_unpack=analysis_target["upx_unpack"],
            )
            result.update(
                {
                    "bundle_dir": derived_bundle_dir,
                    "bundle_manifest": read_json(derived_manifest_path) if derived_manifest_path.exists() else derived_manifest,
                    "automation_payload": read_json(derived_payload_path) if derived_payload_path.exists() else derived_payload,
                    "analysis_target": analysis_target,
                }
            )
            return result
    except TimeoutError as exc:
        analysis_target["selection_reason"] = (
            f"{exc}. Continuing with the original prepared bundle."
        )
        return result


def prepare_corpus_bundles(
    corpus_name: str,
    sample_paths: List[Path],
    manifest_lookup: Dict[str, Dict[str, Any]],
    *,
    output_root: Path | None = None,
    timeout_sec: int | None = None,
    ghidra_install_dir: str = "",
    ghidra_headless: str = "",
    skip_cli_tools: bool = False,
    keep_project: bool = False,
) -> Dict[str, Any]:
    bundle_root = output_root or ensure_dir(BUNDLE_ROOT / corpus_name)
    analyze_headless = resolve_analyze_headless(ghidra_install_dir, ghidra_headless)
    summary: Dict[str, Any] = {
        "corpus": corpus_name,
        "output_root": str(bundle_root),
        "analyze_headless": str(analyze_headless) if analyze_headless else "",
        "ghidra_headless_available": bool(analyze_headless),
        "results": [],
    }
    skipped_fresh = 0
    regenerated = 0
    for sample_path in sample_paths:
        bundle_result = prepare_bundle(
            corpus_name,
            sample_path,
            manifest_lookup.get(sample_path.name) or {},
            output_root=bundle_root,
            timeout_sec=timeout_sec,
            analyze_headless=analyze_headless,
            skip_cli_tools=skip_cli_tools,
            keep_project=keep_project,
        )
        if bundle_result.get("skip_reason") == "fresh_bundle":
            skipped_fresh += 1
        else:
            regenerated += 1
        summary["results"].append(bundle_result)
    readiness = inspect_corpus_bundles(
        corpus_name,
        sample_paths,
        output_root=bundle_root,
        ghidra_install_dir=ghidra_install_dir,
        ghidra_headless=ghidra_headless,
    )
    summary["bundle_readiness"] = readiness
    summary["ready_for_analysis"] = bool(readiness.get("ready_for_analysis"))
    summary["fresh_for_analysis"] = bool(readiness.get("fresh_for_analysis"))
    summary["skipped_fresh_count"] = skipped_fresh
    summary["regenerated_count"] = regenerated
    write_json(bundle_root / "index.json", summary)
    return summary


def inspect_bundle_dir(bundle_dir: Path, *, sample_path: Path | None = None, analyze_headless: Path | None = None) -> Dict[str, Any]:
    bundle_dir = bundle_dir.resolve()
    required = {name: (bundle_dir / name).is_file() for name in REQUIRED_BUNDLE_FILES}
    optional = {name: (bundle_dir / name).is_file() for name in OPTIONAL_BUNDLE_FILES}
    missing_required = [name for name, present in required.items() if not present]
    missing_optional = [name for name, present in optional.items() if not present]
    freshness: Dict[str, Any] | None = None
    if sample_path is not None and sample_path.exists():
        freshness = _bundle_freshness(bundle_dir, sample_path, analyze_headless=analyze_headless)
    fresh_for_analysis = bool(freshness.get("fresh_for_analysis")) if isinstance(freshness, dict) else None
    result = {
        "bundle_dir": str(bundle_dir),
        "required_files": required,
        "optional_files": optional,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "ready_for_analysis": not missing_required,
        "fresh_for_analysis": fresh_for_analysis,
    }
    if isinstance(freshness, dict):
        result["freshness_status"] = freshness.get("status")
        result["stale_reasons"] = list(freshness.get("stale_reasons") or [])
    return result


def inspect_corpus_bundles(
    corpus_name: str,
    sample_paths: List[Path],
    *,
    output_root: Path | None = None,
    ghidra_install_dir: str = "",
    ghidra_headless: str = "",
) -> Dict[str, Any]:
    bundle_root = output_root or ensure_dir(BUNDLE_ROOT / corpus_name)
    analyze_headless = resolve_analyze_headless(ghidra_install_dir, ghidra_headless)
    results: List[Dict[str, Any]] = []
    for sample_path in sample_paths:
        slug = sample_slug(sample_path)
        bundle_dir = bundle_root / slug
        inspection = inspect_bundle_dir(bundle_dir, sample_path=sample_path, analyze_headless=analyze_headless)
        inspection["sample"] = sample_path.name
        results.append(inspection)

    ready_count = sum(1 for item in results if item.get("ready_for_analysis"))
    fresh_count = sum(1 for item in results if item.get("fresh_for_analysis"))
    return {
        "corpus": corpus_name,
        "bundle_root": str(bundle_root),
        "ready_count": ready_count,
        "fresh_count": fresh_count,
        "sample_count": len(results),
        "ready_for_analysis": ready_count == len(results),
        "fresh_for_analysis": fresh_count == len(results) if results else True,
        "results": results,
    }


def absolutize_server_manifest(raw_manifest: Dict[str, Any], manifest_path: Path) -> Dict[str, Any]:
    materialized = json.loads(json.dumps(raw_manifest))
    for cfg in materialized.values():
        if not isinstance(cfg, dict):
            continue
        command = str(cfg.get("command") or "").strip().lower()
        if command in {"python", "python3"}:
            cfg["command"] = sys.executable
        args = cfg.get("args")
        if not isinstance(args, list) or not args:
            continue
        if isinstance(args[0], str) and args[0].endswith(".py"):
            args[0] = str((manifest_path.parent / args[0]).resolve())
    return materialized


def load_tool_profiles() -> Dict[str, Any]:
    path = CONFIG_ROOT / "tool_profiles.json"
    if not path.exists():
        return {"version": "tool_profiles_v1", "profiles": {"full": {"description": "All default MCP servers enabled."}}}
    return read_json(path)


def resolve_tool_profile(profile_name: str = "") -> Dict[str, Any]:
    requested = str(profile_name or "full").strip() or "full"
    config = load_tool_profiles()
    profiles = config.get("profiles") if isinstance(config.get("profiles"), dict) else {}
    profile = profiles.get(requested)
    if isinstance(profile, dict):
        cleaned = dict(profile)
        cleaned["name"] = requested
        return cleaned
    fallback = profiles.get("full")
    if isinstance(fallback, dict):
        cleaned = dict(fallback)
        cleaned["name"] = "full"
        return cleaned
    return {"name": "full", "description": "All default MCP servers enabled."}


def _filtered_server_manifest(manifest: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
    disabled = {str(item).strip() for item in (profile.get("disabled_servers") or []) if str(item).strip()}
    if not disabled:
        return manifest
    filtered: Dict[str, Any] = {}
    for server_id, cfg in manifest.items():
        if server_id in disabled and server_id != "ghidramcp":
            continue
        filtered[server_id] = cfg
    return filtered


def build_artifact_servers_manifest(
    bundle_dir: Path,
    output_path: Path,
    *,
    tool_profile: str = "full",
    analysis_target_kind: str = "",
) -> Path:
    raw_manifest = read_json(DEFAULT_SERVERS_MANIFEST)
    manifest = absolutize_server_manifest(raw_manifest, DEFAULT_SERVERS_MANIFEST)
    profile = resolve_tool_profile(tool_profile)
    manifest = _filtered_server_manifest(manifest, profile)
    normalized_analysis_target_kind = str(analysis_target_kind or "").strip().lower().replace("-", "_")
    if normalized_analysis_target_kind == "upx_unpacked":
        # The harness already resolved and selected a derived unpacked sample for
        # this case. Leaving the UPX MCP server available encourages redundant
        # `upxUnpack` calls against a target that is no longer the canonical
        # analysis executable for the run.
        manifest.pop("upxmcp", None)
    artifact_server = REPO_ROOT / "MCPServers" / "artifactGhidraMCP.py"
    manifest["ghidramcp"] = {
        "transport": "stdio",
        "command": sys.executable,
        "args": [str(artifact_server.resolve()), "--transport", "stdio", "--bundle-dir", str(bundle_dir.resolve())],
    }
    write_json(output_path, manifest)
    return output_path


def tool_name_to_server_guess(tool_name: str) -> str:
    name = str(tool_name or "").strip().lower()
    if name in {
        "list_methods",
        "list_classes",
        "decompile_function",
        "rename_function",
        "rename_data",
        "list_segments",
        "list_imports",
        "list_exports",
        "list_namespaces",
        "list_data_items",
        "search_functions_by_name",
        "rename_variable",
        "get_function_by_address",
        "get_current_address",
        "get_current_function",
        "list_functions",
        "decompile_function_by_address",
        "disassemble_function",
        "set_decompiler_comment",
        "set_disassembly_comment",
        "rename_function_by_address",
        "set_function_prototype",
        "set_local_variable_type",
        "get_xrefs_to",
        "get_callers",
        "get_callees",
        "get_program_info",
    }:
        return "ghidramcp"
    if "yara" in name:
        return "yaramcp"
    if "capa" in name:
        return "CapaMCP"
    if "floss" in name:
        return "flareflossmcp"
    if "hash" in name:
        return "hashdbmcp"
    if "string" in name:
        return "stringmcp"
    if "binwalk" in name:
        return "binwalkmcp"
    if "upx" in name:
        return "upxmcp"
    return "unknown"


def parse_tool_log_sections(sections: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for stage_name, raw_text in (sections or {}).items():
        text = str(raw_text or "").strip()
        if not text:
            continue
        decoder = json.JSONDecoder()
        idx = 0
        length = len(text)
        while idx < length:
            while idx < length and text[idx].isspace():
                idx += 1
            if idx >= length:
                break
            try:
                obj, end = decoder.raw_decode(text, idx)
            except json.JSONDecodeError:
                next_obj = text.find("\n{", idx + 1)
                if next_obj == -1:
                    break
                idx = next_obj + 1
                continue
            if isinstance(obj, dict):
                if "stage" not in obj:
                    obj["stage"] = stage_name
                entries.append(obj)
            idx = end
    return entries


def summarize_tool_usage(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_tool: Dict[str, int] = {}
    by_server: Dict[str, int] = {}
    for entry in entries:
        if str(entry.get("kind") or "") != "tool_call":
            continue
        tool_name = str(entry.get("tool_name") or "").strip()
        if not tool_name:
            continue
        server_id = str(entry.get("server_id") or "").strip() or tool_name_to_server_guess(tool_name)
        by_tool[tool_name] = int(by_tool.get(tool_name, 0)) + 1
        by_server[server_id] = int(by_server.get(server_id, 0)) + 1
    return {
        "by_tool_name": dict(sorted(by_tool.items(), key=lambda item: (-item[1], item[0]))),
        "by_server": dict(sorted(by_server.items(), key=lambda item: (-item[1], item[0]))),
    }
