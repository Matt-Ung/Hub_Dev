"""
File: archive_results_browser.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Serve a dedicated browser for archived legacy experiment outputs.

Summary:
  This module reads the pre-refactor results layout after it has been moved to
  `Testing/archive/results_legacy/`. It is intentionally separate from the
  active results browser so the maintained UI can assume the new canonical
  structure without carrying legacy branching logic.
"""

from __future__ import annotations

import json
import mimetypes
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .paths import TESTING_ROOT, ensure_dir


ARCHIVE_RESULTS_ROOT = TESTING_ROOT / "archive" / "results_legacy"


_ARCHIVE_BROWSER_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Legacy Results Archive Browser</title>
  <style>
    body { font-family: "Inter", "Segoe UI", sans-serif; margin: 0; background: #eef3fb; color: #10213a; }
    .wrap { max-width: 1440px; margin: 0 auto; padding: 24px; }
    .hero { background: linear-gradient(135deg, #183b8d, #4a8fff); color: #fff; border-radius: 20px; padding: 20px 22px; box-shadow: 0 18px 42px rgba(16,33,58,0.10); }
    .hero h1 { margin: 0 0 8px 0; font-size: 30px; }
    .hero p { margin: 0; opacity: 0.9; line-height: 1.5; }
    .toolbar { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 16px; }
    select { min-width: 360px; padding: 10px 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.3); background: rgba(255,255,255,0.12); color: #fff; }
    .grid { display: grid; grid-template-columns: minmax(320px, 1fr) minmax(320px, 2fr); gap: 18px; margin-top: 18px; }
    .panel { background: rgba(255,255,255,0.94); border: 1px solid rgba(16,33,58,0.12); border-radius: 18px; box-shadow: 0 12px 28px rgba(16,33,58,0.08); overflow: hidden; }
    .panel h2 { margin: 0; font-size: 20px; }
    .head { padding: 16px 18px; border-bottom: 1px solid rgba(16,33,58,0.10); background: rgba(248,251,255,0.96); }
    .body { padding: 14px; }
    .muted { color: #5e6b7e; font-size: 13px; line-height: 1.5; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-top: 16px; }
    .card { background: rgba(255,255,255,0.94); border: 1px solid rgba(16,33,58,0.10); border-radius: 16px; padding: 14px; }
    .card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; }
    .card .value { font-size: 24px; font-weight: 800; margin-top: 8px; }
    .run-list { display: flex; flex-direction: column; gap: 10px; max-height: 70vh; overflow: auto; }
    button.run { all: unset; display: block; cursor: pointer; border: 1px solid rgba(16,33,58,0.10); border-radius: 14px; padding: 12px 14px; background: rgba(255,255,255,0.94); }
    button.run.sel { border-color: rgba(36,89,209,0.35); background: rgba(231,240,255,0.95); }
    .title { font-weight: 700; line-height: 1.35; }
    .meta { margin-top: 6px; font-size: 13px; color: #5e6b7e; line-height: 1.5; }
    .detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
    .detail-card { border: 1px solid rgba(16,33,58,0.10); border-radius: 14px; padding: 12px; background: rgba(255,255,255,0.92); }
    .detail-card h3 { margin: 0 0 8px 0; font-size: 15px; }
    pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-family: "SFMono-Regular", "Consolas", monospace; font-size: 12px; line-height: 1.5; color: #11233f; }
    .gallery { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 14px; }
    .gallery a { display: inline-flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: 12px; border: 1px solid rgba(16,33,58,0.10); background: rgba(255,255,255,0.94); color: #183b8d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>Legacy Results Archive Browser</h1>
      <p>This browser is for archived pre-refactor experiments only. The active monitor and active results browser no longer support the legacy `results/runs` plus `samples/` layout.</p>
      <div class="toolbar">
        <select id="experimentSelect"></select>
      </div>
    </div>
    <div class="summary" id="summary"></div>
    <div class="grid">
      <div class="panel">
        <div class="head">
          <h2>Archived Runs</h2>
          <div class="muted" id="runsMeta"></div>
        </div>
        <div class="body">
          <div class="run-list" id="runList"></div>
        </div>
      </div>
      <div class="panel">
        <div class="head">
          <h2 id="detailTitle">Run Detail</h2>
          <div class="muted" id="detailMeta"></div>
        </div>
        <div class="body">
          <div class="detail-grid">
            <div class="detail-card"><h3>Selected Task</h3><pre id="selectedTask"></pre></div>
            <div class="detail-card"><h3>Run Summary</h3><pre id="runSummary"></pre></div>
            <div class="detail-card"><h3>Agent Output</h3><pre id="agentOutput"></pre></div>
            <div class="detail-card"><h3>Judge Output</h3><pre id="judgeOutput"></pre></div>
            <div class="detail-card"><h3>Legacy Log</h3><pre id="serverLog"></pre></div>
            <div class="detail-card"><h3>Files</h3><pre id="artifactPaths"></pre></div>
          </div>
          <div class="gallery" id="gallery"></div>
        </div>
      </div>
    </div>
  </div>
<script>
const state = { catalog: null, experimentId: "", runId: "" };

function esc(value) {
  return String(value == null ? "" : value).replace(/[&<>]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[ch]));
}

async function loadCatalog() {
  const res = await fetch('/api/catalog');
  state.catalog = await res.json();
  const select = document.getElementById('experimentSelect');
  const experiments = state.catalog.experiments || [];
  select.innerHTML = experiments.map(exp => `<option value="${esc(exp.experiment_id)}">${esc(exp.experiment_id)} (${esc(exp.corpus || 'unknown')})</option>`).join('');
  if (!state.experimentId && experiments.length) state.experimentId = experiments[0].experiment_id;
  select.value = state.experimentId;
  select.onchange = () => { state.experimentId = select.value; state.runId = ""; loadState(); };
  renderSummary();
  await loadState();
}

function renderSummary() {
  const experiments = (state.catalog && state.catalog.experiments) || [];
  const selected = experiments.find(exp => exp.experiment_id === state.experimentId) || {};
  document.getElementById('summary').innerHTML = [
    ['Archive Root', state.catalog ? state.catalog.archive_root : ''],
    ['Experiments', experiments.length],
    ['Selected Corpus', selected.corpus || ''],
    ['Archived Runs', selected.run_count || 0],
  ].map(([label, value]) => `<div class="card"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div></div>`).join('');
}

async function loadState() {
  if (!state.experimentId) return;
  renderSummary();
  const res = await fetch(`/api/state?experiment_id=${encodeURIComponent(state.experimentId)}`);
  const payload = await res.json();
  const runs = payload.runs || [];
  if (!state.runId && runs.length) state.runId = runs[0].run_id;
  document.getElementById('runsMeta').textContent = `${runs.length} archived run(s)`;
  document.getElementById('runList').innerHTML = runs.map(run => `
    <button class="run ${run.run_id === state.runId ? 'sel' : ''}" data-run-id="${esc(run.run_id)}">
      <div class="title">${esc(run.display_label || run.run_id)}</div>
      <div class="meta">status=${esc(run.status || 'unknown')} | variable=${esc(run.changed_variable || 'baseline')}</div>
      <div class="meta">${esc(run.run_dir || '')}</div>
    </button>
  `).join('');
  document.querySelectorAll('button.run').forEach(btn => {
    btn.onclick = () => { state.runId = btn.getAttribute('data-run-id') || ''; loadDetail(); };
  });
  await loadDetail();
}

async function loadDetail() {
  if (!state.experimentId || !state.runId) return;
  const res = await fetch(`/api/detail?experiment_id=${encodeURIComponent(state.experimentId)}&run_id=${encodeURIComponent(state.runId)}`);
  const payload = await res.json();
  document.getElementById('detailTitle').textContent = payload.display_label || payload.run_id || 'Run Detail';
  document.getElementById('detailMeta').textContent = payload.run_dir || '';
  document.getElementById('selectedTask').textContent = payload.selected_task_text || 'No task records found.';
  document.getElementById('runSummary').textContent = payload.run_summary || 'No run summary found.';
  document.getElementById('agentOutput').textContent = payload.agent_output || 'No agent output found.';
  document.getElementById('judgeOutput').textContent = payload.judge_output || 'No judge output found.';
  document.getElementById('serverLog').textContent = payload.server_log || 'No log found.';
  document.getElementById('artifactPaths').textContent = payload.artifact_paths || 'No artifact paths recorded.';
  const gallery = payload.visual_gallery || [];
  document.getElementById('gallery').innerHTML = gallery.map(item => `<a href="/artifact?experiment_id=${encodeURIComponent(state.experimentId)}&path=${encodeURIComponent(item.path)}" target="_blank" rel="noreferrer">${esc(item.title || item.path)}</a>`).join('');
}

loadCatalog();
</script>
</body>
</html>
"""


def _safe_json(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {}


def _safe_text(path: Path) -> str:
    try:
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    return ""


def _safe_stat_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except Exception:
        return 0.0


def _list_archive_experiment_roots(archive_root: Path) -> List[Path]:
    experiments_root = archive_root / "experiments"
    if not experiments_root.exists():
        return []
    return sorted(
        [path for path in experiments_root.iterdir() if path.is_dir()],
        key=lambda path: max(_safe_stat_mtime(path / "run_catalog.json"), _safe_stat_mtime(path)),
        reverse=True,
    )


def _resolve_archive_experiment_root(archive_root: Path, experiment_id: str) -> Path | None:
    candidate = archive_root / "experiments" / str(experiment_id or "").strip()
    return candidate if candidate.exists() else None


def _resolve_legacy_run_dir(archive_root: Path, experiment_root: Path, entry: Dict[str, Any]) -> Path:
    run_id = str(entry.get("run_id") or "").strip()
    run_dir_raw = str(entry.get("run_dir") or "").strip()
    if run_dir_raw:
        run_dir = Path(run_dir_raw).expanduser()
        if run_dir.exists():
            return run_dir.resolve()
        candidate = archive_root / "runs" / run_dir.name
        if candidate.exists():
            return candidate.resolve()
    if run_id:
        rebuilt = experiment_root / "rebuilt_runs" / run_id
        if rebuilt.exists():
            return rebuilt.resolve()
        candidate = archive_root / "runs" / run_id
        if candidate.exists():
            return candidate.resolve()
        return candidate.resolve()
    return Path()


def _resolve_legacy_log_path(experiment_root: Path, entry: Dict[str, Any]) -> Path:
    run_id = str(entry.get("run_id") or "").strip()
    log_path_raw = str(entry.get("log_path") or "").strip()
    if log_path_raw:
        path = Path(log_path_raw).expanduser()
        if path.exists():
            return path.resolve()
        candidate = experiment_root / "live_view" / "logs" / path.name
        if candidate.exists():
            return candidate.resolve()
    fallback = experiment_root / "live_view" / "logs" / f"{run_id}.log"
    return fallback.resolve()


def _iter_legacy_record_paths(run_dir: Path) -> List[Path]:
    root = Path(run_dir) / "samples"
    if not root.exists():
        return []
    return sorted(root.glob("*/record.json"))


def _load_legacy_task_bundle(run_dir: Path, sample_task_id: str = "") -> Dict[str, Any]:
    record_paths = _iter_legacy_record_paths(run_dir)
    chosen: Path | None = None
    if sample_task_id:
        for path in record_paths:
            record = _safe_json(path)
            if str(record.get("sample_task_id") or "").strip() == sample_task_id:
                chosen = path
                break
    if chosen is None and record_paths:
        chosen = max(record_paths, key=_safe_stat_mtime)
    if chosen is None:
        return {"record": {}, "agent": {}, "judge": {}, "record_path": None, "sample_dir": None}
    sample_dir = chosen.parent
    return {
        "sample_dir": sample_dir,
        "record": _safe_json(chosen),
        "agent": _safe_json(sample_dir / "agent_result.json"),
        "judge": _safe_json(sample_dir / "judge_result.json"),
        "record_path": chosen,
        "agent_path": sample_dir / "agent_result.json",
        "judge_path": sample_dir / "judge_result.json",
    }


def _legacy_visual_gallery(experiment_root: Path) -> List[Dict[str, str]]:
    outputs_root = experiment_root / "outputs"
    if not outputs_root.exists():
        return []
    items: List[Dict[str, str]] = []
    for path in sorted(outputs_root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in {".png", ".jpg", ".jpeg", ".svg", ".html"}:
            continue
        items.append(
            {
                "title": path.name,
                "path": str(path.relative_to(experiment_root)),
            }
        )
    return items[:16]


def load_archive_results_browser_catalog(archive_root: Path = ARCHIVE_RESULTS_ROOT) -> Dict[str, Any]:
    experiments: List[Dict[str, Any]] = []
    for experiment_root in _list_archive_experiment_roots(archive_root):
        manifest = _safe_json(experiment_root / "experiment_manifest.json")
        run_catalog = _safe_json(experiment_root / "run_catalog.json")
        runs = run_catalog.get("runs") if isinstance(run_catalog.get("runs"), list) else []
        experiments.append(
            {
                "experiment_id": experiment_root.name,
                "corpus": str(manifest.get("corpus") or ""),
                "run_count": len(runs),
                "path": str(experiment_root.resolve()),
                "updated_at_epoch": max(_safe_stat_mtime(experiment_root / "run_catalog.json"), _safe_stat_mtime(experiment_root)),
            }
        )
    return {"archive_root": str(archive_root.resolve()), "experiments": experiments}


def load_archive_results_browser_state(archive_root: Path, experiment_id: str) -> Dict[str, Any]:
    experiment_root = _resolve_archive_experiment_root(archive_root, experiment_id)
    if experiment_root is None:
        return {"summary": {"total_runs": 0}, "runs": []}
    manifest = _safe_json(experiment_root / "experiment_manifest.json")
    run_catalog = _safe_json(experiment_root / "run_catalog.json")
    runs: List[Dict[str, Any]] = []
    counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "other": 0}
    for raw_entry in (run_catalog.get("runs") or []):
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        run_dir = _resolve_legacy_run_dir(archive_root, experiment_root, entry)
        live_status = _safe_json(run_dir / "live_status.json") if run_dir.exists() else {}
        status = str(live_status.get("status") or entry.get("status") or "unknown").strip() or "unknown"
        bucket = status if status in counts else "other"
        counts[bucket] = counts.get(bucket, 0) + 1
        entry["status"] = status
        entry["run_dir"] = str(run_dir)
        runs.append(entry)
    return {
        "experiment_id": experiment_root.name,
        "experiment_root": str(experiment_root.resolve()),
        "corpus": str(manifest.get("corpus") or ""),
        "summary": {"total_runs": len(runs), **counts},
        "runs": runs,
    }


def load_archive_results_browser_detail(
    archive_root: Path,
    experiment_id: str,
    run_id: str,
    *,
    sample_task_id: str = "",
) -> Dict[str, Any]:
    experiment_root = _resolve_archive_experiment_root(archive_root, experiment_id)
    if experiment_root is None:
        return {}
    state = load_archive_results_browser_state(archive_root, experiment_id)
    run_entry = next((row for row in (state.get("runs") or []) if str(row.get("run_id") or "") == str(run_id or "")), {})
    run_dir = _resolve_legacy_run_dir(archive_root, experiment_root, run_entry)
    task_bundle = _load_legacy_task_bundle(run_dir, sample_task_id=sample_task_id) if run_dir.exists() else {
        "record": {},
        "agent": {},
        "judge": {},
        "record_path": None,
        "sample_dir": None,
    }
    record = task_bundle.get("record") if isinstance(task_bundle.get("record"), dict) else {}
    agent = task_bundle.get("agent") if isinstance(task_bundle.get("agent"), dict) else {}
    judge = task_bundle.get("judge") if isinstance(task_bundle.get("judge"), dict) else {}
    log_path = _resolve_legacy_log_path(experiment_root, run_entry)
    run_manifest = _safe_json(run_dir / "run_manifest.json") if run_dir.exists() else {}

    selected_task_lines = [
        f"sample_task_id: {str(record.get('sample_task_id') or '').strip()}",
        f"sample: {str(record.get('sample') or '').strip()}",
        f"task_id: {str(record.get('task_id') or '').strip()}",
        f"task_name: {str(record.get('task_name') or '').strip()}",
    ]
    run_summary_lines = [
        f"status: {str(run_entry.get('status') or '').strip()}",
        f"pipeline: {str(run_entry.get('pipeline') or run_manifest.get('pipeline') or '').strip()}",
        f"architecture: {str(run_entry.get('architecture') or run_manifest.get('architecture') or '').strip()}",
        f"changed_variable: {str(run_entry.get('changed_variable') or '').strip()}",
    ]
    return {
        "experiment_id": experiment_root.name,
        "run_id": str(run_entry.get("run_id") or ""),
        "display_label": str(run_entry.get("display_label") or run_entry.get("run_id") or ""),
        "run_dir": str(run_dir),
        "selected_task_text": "\n".join(line for line in selected_task_lines if line.split(": ", 1)[1]).strip() or "No task selected.",
        "run_summary": "\n".join(line for line in run_summary_lines if line.split(": ", 1)[1]).strip() or "No run summary found.",
        "agent_output": str(agent.get("final_report") or agent.get("status_log") or record.get("agent_result", {}).get("final_report") or "").strip(),
        "judge_output": str(judge.get("technical_summary") or judge.get("writing_summary") or "").strip(),
        "server_log": _safe_text(log_path),
        "artifact_paths": "\n".join(
            [
                f"record: {task_bundle.get('record_path')}" if task_bundle.get("record_path") else "",
                f"agent: {task_bundle.get('agent_path')}" if task_bundle.get("agent_path") and Path(str(task_bundle.get('agent_path'))).exists() else "",
                f"judge: {task_bundle.get('judge_path')}" if task_bundle.get("judge_path") and Path(str(task_bundle.get('judge_path'))).exists() else "",
                f"log: {log_path}" if log_path.exists() else "",
            ]
        ).strip(),
        "visual_gallery": _legacy_visual_gallery(experiment_root),
    }


class _ArchiveResultsBrowserHandler(BaseHTTPRequestHandler):
    archive_root: Path
    browser_dir: Path

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, *, content_type: str = "text/html; charset=utf-8", status: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_artifact(self, experiment_id: str, relative_path: str) -> None:
        experiment_root = _resolve_archive_experiment_root(self.archive_root, experiment_id)
        if experiment_root is None:
            self._send_text("Unknown experiment\n", content_type="text/plain; charset=utf-8", status=404)
            return
        artifact_path = (experiment_root / str(relative_path or "").lstrip("/")).resolve()
        if not str(artifact_path).startswith(str(experiment_root.resolve())) or not artifact_path.exists() or not artifact_path.is_file():
            self._send_text("Artifact not found\n", content_type="text/plain; charset=utf-8", status=404)
            return
        content_type = mimetypes.guess_type(str(artifact_path))[0] or "application/octet-stream"
        body = artifact_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._send_text(_ARCHIVE_BROWSER_HTML)
            return
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/api/catalog":
            self._send_json(load_archive_results_browser_catalog(self.archive_root))
            return
        if parsed.path == "/api/state":
            experiment_id = str((params.get("experiment_id") or [""])[0] or "")
            self._send_json(load_archive_results_browser_state(self.archive_root, experiment_id))
            return
        if parsed.path == "/api/detail":
            experiment_id = str((params.get("experiment_id") or [""])[0] or "")
            run_id = str((params.get("run_id") or [""])[0] or "")
            sample_task_id = str((params.get("sample_task_id") or [""])[0] or "")
            self._send_json(load_archive_results_browser_detail(self.archive_root, experiment_id, run_id, sample_task_id=sample_task_id))
            return
        if parsed.path == "/artifact":
            experiment_id = str((params.get("experiment_id") or [""])[0] or "")
            relative_path = str((params.get("path") or [""])[0] or "")
            self._send_artifact(experiment_id, relative_path)
            return
        self._send_text("Not found\n", content_type="text/plain; charset=utf-8", status=404)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return


def start_archive_results_browser_server(
    archive_root: Path = ARCHIVE_RESULTS_ROOT,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> Tuple[ThreadingHTTPServer, threading.Thread, str]:
    browser_dir = ensure_dir(archive_root / "browser")
    (browser_dir / "index.html").write_text(_ARCHIVE_BROWSER_HTML, encoding="utf-8")
    handler = type(
        "TestingArchiveResultsBrowserHandler",
        (_ArchiveResultsBrowserHandler,),
        {"archive_root": archive_root, "browser_dir": browser_dir},
    )
    server = ThreadingHTTPServer((host, int(port)), handler)
    thread = threading.Thread(target=server.serve_forever, name="testing-archive-results-browser", daemon=True)
    thread.start()
    url = f"http://{server.server_address[0]}:{server.server_address[1]}/"
    (browser_dir / "archive_results_browser_url.txt").write_text(url + "\n", encoding="utf-8")
    return server, thread, url
