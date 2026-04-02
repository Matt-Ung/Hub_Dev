"""
File: live_progress.py
Author: Matt-Ung
Last Updated: 2026-04-01
Purpose:
  Serve the lightweight live progress monitor for active experiment sweeps.

Summary:
  This module reads the experiment run catalog, per-run live-status files, and
  streamed child logs to power the developer-facing monitor UI. It exists to
  make sweep execution understandable in real time without requiring a heavier
  dashboard service or post-run artifact inspection.
"""

from __future__ import annotations

import json
import re
import threading
import urllib.parse
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .paths import REPO_ROOT, ensure_dir, read_json


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Testing Live Progress</title>
  <style>
    :root {
      --bg: #f4f7fb;
      --panel: rgba(255, 255, 255, 0.9);
      --panel-strong: #ffffff;
      --line: rgba(19, 32, 54, 0.12);
      --line-strong: rgba(19, 32, 54, 0.18);
      --ink: #0f172a;
      --muted: #5b6475;
      --muted-soft: #7c879a;
      --shadow: 0 18px 40px rgba(17, 24, 39, 0.08);
      --ok: #157f5e;
      --run: #2459d1;
      --wait: #9a6412;
      --fail: #b42318;
      --pending-bg: #fff4d6;
      --running-bg: #dce9ff;
      --completed-bg: #dff5eb;
      --failed-bg: #fbe2df;
      --skipped-bg: #eceff4;
      --accent: linear-gradient(135deg, #2459d1 0%, #48a6ff 100%);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(72, 166, 255, 0.16), transparent 28%),
        linear-gradient(180deg, #f8fbff 0%, var(--bg) 42%, #eef3fb 100%);
      color: var(--ink);
    }
    .wrap { padding: 24px; max-width: 1680px; margin: 0 auto; }
    h1, h2, h3 { margin: 0; }
    .topbar {
      display: flex;
      flex-direction: column;
      gap: 18px;
      margin-bottom: 18px;
    }
    .hero {
      padding: 18px 20px;
      border-radius: 22px;
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid rgba(255, 255, 255, 0.7);
      backdrop-filter: blur(10px);
      box-shadow: var(--shadow);
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
      font-size: 12px;
      font-weight: 700;
      color: var(--run);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .hero h1 { font-size: 34px; letter-spacing: -0.03em; margin-bottom: 8px; }
    .hero p { margin: 0; color: var(--muted); line-height: 1.6; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      align-items: stretch;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 16px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
      min-width: 0;
    }
    .card .label { font-size: 12px; color: var(--muted-soft); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
    .card .value {
      font-size: clamp(22px, 2.1vw, 30px);
      line-height: 1.08;
      margin-top: 10px;
      font-weight: 700;
      letter-spacing: -0.03em;
      min-width: 0;
    }
    .card .subvalue {
      margin-top: 10px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    .summary-card-wide { grid-column: span 2; min-width: 0; }
    .summary-card-experiment .value {
      font-size: clamp(18px, 1.8vw, 28px);
      line-height: 1.15;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    .layout { display: grid; grid-template-columns: 360px minmax(0, 1fr); gap: 18px; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      overflow: hidden;
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }
    .panel .head {
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(248,251,255,0.92));
    }
    .panel .body { padding: 18px 20px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 9px 6px; border-bottom: 1px solid var(--line); vertical-align: top; text-align: left; }
    th { font-size: 11px; color: var(--muted-soft); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
    tr.sel { background: rgba(36, 89, 209, 0.06); }
    button.run-link {
      all: unset;
      cursor: pointer;
      display: block;
      width: 100%;
      color: inherit;
    }
    .queue-list { display: flex; flex-direction: column; gap: 10px; }
    .queue-item {
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.82);
      transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
    }
    .queue-item:hover { transform: translateY(-1px); border-color: var(--line-strong); box-shadow: 0 14px 28px rgba(15, 23, 42, 0.08); }
    .queue-item.sel { border-color: rgba(36, 89, 209, 0.32); box-shadow: 0 18px 36px rgba(36, 89, 209, 0.10); }
    .queue-item button { padding: 14px 16px; }
    .queue-top { display: flex; justify-content: flex-start; gap: 12px; align-items: center; margin-bottom: 8px; min-width: 0; }
    .queue-title { font-weight: 700; letter-spacing: -0.01em; }
    .queue-meta { color: var(--muted); font-size: 13px; line-height: 1.5; }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.01em;
    }
    .status-pending { background: var(--pending-bg); color: var(--wait); }
    .status-running { background: var(--running-bg); color: var(--run); }
    .status-completed { background: var(--completed-bg); color: var(--ok); }
    .status-failed { background: var(--failed-bg); color: var(--fail); }
    .status-skipped { background: var(--skipped-bg); color: var(--muted); }
    .detail-shell { display: flex; flex-direction: column; gap: 18px; }
    .detail-head { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
    .detail-head h2 { font-size: 28px; letter-spacing: -0.03em; }
    .detail-meta { margin-top: 6px; color: var(--muted); line-height: 1.6; font-size: 14px; }
    .pipeline-box {
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 16px 18px 18px;
      background: linear-gradient(180deg, rgba(248,251,255,0.95), rgba(255,255,255,0.92));
    }
    .pipeline-head { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; margin-bottom: 14px; }
    .pipeline-head h3 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted-soft); }
    .pipeline-summary { color: var(--ink); font-weight: 600; }
    .pipeline-track {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 12px;
      align-items: stretch;
    }
    .pipeline-stage {
      position: relative;
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 12px 12px 14px;
      background: rgba(255,255,255,0.78);
      min-height: 88px;
      transition: transform 180ms ease, border-color 180ms ease, background 180ms ease;
    }
    .pipeline-stage.running { border-color: rgba(36, 89, 209, 0.34); background: rgba(220, 233, 255, 0.8); transform: translateY(-1px); }
    .pipeline-stage.completed { border-color: rgba(21, 127, 94, 0.26); background: rgba(223, 245, 235, 0.82); }
    .pipeline-stage.failed { border-color: rgba(180, 35, 24, 0.28); background: rgba(251, 226, 223, 0.84); }
    .pipeline-stage .step { font-size: 11px; color: var(--muted-soft); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 10px; }
    .pipeline-stage .name { font-weight: 700; line-height: 1.3; }
    .pipeline-stage .state { margin-top: 10px; font-size: 12px; color: var(--muted); }
    .pipeline-stage.running .state { color: var(--run); font-weight: 700; }
    .pipeline-stage.completed .state { color: var(--ok); font-weight: 700; }
    .pipeline-stage.failed .state { color: var(--fail); font-weight: 700; }
    .pipeline-stage.running::after {
      content: "";
      position: absolute;
      inset: -1px;
      border-radius: 18px;
      border: 1px solid rgba(36, 89, 209, 0.22);
      animation: pulse 1.8s ease-in-out infinite;
      pointer-events: none;
    }
    .detail-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 18px;
      align-items: stretch;
    }
    .surface {
      border: 1px solid var(--line);
      border-radius: 20px;
      overflow: hidden;
      background: var(--panel-strong);
    }
    .output-panel {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }
    .surface .title {
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(248,251,255,0.96), rgba(255,255,255,0.96));
    }
    .output-panel .title {
      min-height: 84px;
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
    }
    .surface .title h3 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted-soft); margin-bottom: 6px; }
    .surface .title .sub { color: var(--muted); font-size: 13px; line-height: 1.5; }
    pre {
      margin: 0;
      padding: 16px;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      line-height: 1.55;
      overflow: auto;
    }
    .output-panel pre {
      min-height: 360px;
      max-height: 640px;
      flex: 1 1 auto;
    }
    .logs-panel pre { max-height: 340px; background: #09111f; color: #d8e3f5; }
    .tasks-panel table { margin-top: 8px; }
    .muted { color: var(--muted); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: rgba(15, 23, 42, 0.06);
      padding: 1px 6px;
      border-radius: 999px;
    }
    @keyframes pulse {
      0%, 100% { opacity: 0.35; transform: scale(0.995); }
      50% { opacity: 0.72; transform: scale(1.005); }
    }
    @media (max-width: 1200px) {
      .layout { grid-template-columns: 1fr; }
      .summary { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }
    @media (max-width: 720px) {
      .wrap { padding: 16px; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .summary-card-wide { grid-column: span 2; }
      .pipeline-track { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 560px) {
      .summary,
      .pipeline-track { grid-template-columns: 1fr; }
      .summary-card-wide { grid-column: span 1; }
      .hero h1 { font-size: 30px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="hero">
        <div class="eyebrow">Live Harness Monitor</div>
        <h1>Testing Run View</h1>
        <p id="subtitle">Loading…</p>
      </div>
      <div class="summary" id="summary"></div>
    </div>

    <div class="layout">
      <div class="panel">
        <div class="head"><h2>Run Queue</h2></div>
        <div class="body">
          <div class="queue-list" id="run-rows"></div>
        </div>
      </div>

      <div class="panel">
        <div class="head">
          <div class="detail-head">
            <div>
              <h2 id="detail-title">Run Detail</h2>
              <div class="detail-meta" id="run-meta"></div>
            </div>
            <div id="detail-status"></div>
          </div>
        </div>
        <div class="body">
          <div class="detail-shell">
            <div class="pipeline-box">
              <div class="pipeline-head">
                <h3>Pipeline Progress</h3>
                <div class="pipeline-summary" id="pipeline-summary">Waiting for state…</div>
              </div>
              <div class="pipeline-track" id="pipeline-stages"></div>
            </div>

            <div class="detail-grid">
              <div class="surface output-panel">
                <div class="title">
                  <h3>Run Output</h3>
                  <div class="sub" id="run-output-meta"></div>
                </div>
                <pre id="run-output"></pre>
              </div>

              <div class="surface output-panel">
                <div class="title">
                  <h3>Baseline Output</h3>
                  <div class="sub" id="baseline-output-meta"></div>
                </div>
                <pre id="baseline-output"></pre>
              </div>

              <div class="surface output-panel">
                <div class="title">
                  <h3>Judge Output</h3>
                  <div class="sub" id="judge-output-meta"></div>
                </div>
                <pre id="judge-output"></pre>
              </div>
            </div>

            <div class="surface tasks-panel">
              <div class="title">
                <h3>Task Progress</h3>
                <div class="sub">Per-sample task state, judge status, and latest score.</div>
              </div>
              <div style="padding: 0 16px 16px;" id="task-list"></div>
            </div>

            <div class="surface logs-panel">
              <div class="title">
                <h3>Server Status</h3>
                <div class="sub" id="server-status-meta">Live server logs and transient status messages.</div>
              </div>
              <pre id="server-log"></pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const params = new URLSearchParams(window.location.search);
    let selectedRunId = params.get("run_id") || "";

    function escapeHtml(value) {
      return String(value || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }

    function escapeAttr(value) {
      return escapeHtml(value)
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function statusClass(status) {
      const text = String(status || "pending").toLowerCase();
      if (text === "completed") return "status-completed";
      if (text === "running") return "status-running";
      if (text === "failed") return "status-failed";
      if (text === "skipped") return "status-skipped";
      return "status-pending";
    }

    function statusIcon(status) {
      const text = String(status || "pending").toLowerCase();
      if (text === "completed") return "✓";
      if (text === "running") return "…";
      if (text === "failed") return "✕";
      if (text === "skipped") return "–";
      return "○";
    }

    async function loadJson(path) {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
      }
      return await response.json();
    }

    function renderSummary(state) {
      const summary = state.summary || {};
      const cards = [
        {
          label: "Experiment",
          value: state.experiment_id || "",
          subvalue: `${state.corpus || ""} corpus`,
          extraClass: "summary-card-wide summary-card-experiment",
        },
        { label: "Planned runs", value: summary.total_runs || 0 },
        { label: "Pending", value: summary.pending || 0 },
        { label: "Running", value: summary.running || 0 },
        { label: "Completed", value: summary.completed || 0 },
        { label: "Failed", value: summary.failed || 0 },
      ];
      document.getElementById("summary").innerHTML = cards.map((card) => {
        const subvalue = card.subvalue ? `<div class="subvalue">${escapeHtml(card.subvalue)}</div>` : "";
        const className = ["card", card.extraClass || ""].filter(Boolean).join(" ");
        return `<div class="${className}" title="${escapeAttr(card.value)}"><div class="label">${escapeHtml(card.label)}</div><div class="value">${escapeHtml(card.value)}</div>${subvalue}</div>`;
      }).join("");
      document.getElementById("subtitle").textContent =
        `${state.corpus || ""} corpus • ${summary.completed || 0}/${summary.total_runs || 0} child runs finished`;
    }

    function renderRunTable(state) {
      const rows = state.runs || [];
      if (!selectedRunId) {
        const running = rows.find((row) => String(row.status) === "running");
        selectedRunId = (running || rows[0] || {}).run_id || "";
      }
      const body = rows.map((row) => {
        const selected = row.run_id === selectedRunId ? "sel" : "";
        const stage = row.current_phase || row.stage || "";
        return `<div class="queue-item ${selected}">
          <button class="run-link" data-run-id="${escapeHtml(row.run_id)}">
            <div class="queue-top">
              <span class="status-pill ${statusClass(row.status)}">${statusIcon(row.status)} ${escapeHtml(row.status)}</span>
            </div>
            <div class="queue-title">${escapeHtml(row.display_label || row.run_id)}</div>
            <div class="queue-meta">${escapeHtml(stage || "not started")} • pipeline=${escapeHtml(row.pipeline || "")}</div>
          </button>
        </div>`;
      }).join("");
      document.getElementById("run-rows").innerHTML = body || `<div class="muted">No runs yet.</div>`;
      document.querySelectorAll("button.run-link").forEach((button) => {
        button.addEventListener("click", () => {
          selectedRunId = button.getAttribute("data-run-id") || "";
          refresh();
        });
      });
    }

    function renderTasks(detail) {
      const tasks = (((detail || {}).live_status || {}).tasks) || [];
      if (!tasks.length) {
        document.getElementById("task-list").innerHTML = `<span class="muted">No task-level progress available yet.</span>`;
        return;
      }
      const rows = tasks.map((task) => `
        <tr>
          <td><span class="status-pill ${statusClass(task.status)}">${statusIcon(task.status)} ${escapeHtml(task.status || "")}</span></td>
          <td>${escapeHtml(task.sample_task_id || `${task.sample || ""}::${task.task_id || ""}`)}</td>
          <td>${escapeHtml(task.judge_status || "")}</td>
          <td>${escapeHtml(task.score ?? "")}</td>
        </tr>
      `).join("");
      document.getElementById("task-list").innerHTML = `
        <table>
          <thead><tr><th>Status</th><th>Task</th><th>Judge</th><th>Score</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;
    }

    function renderPipeline(detail) {
      const progress = (detail || {}).pipeline_progress || {};
      const stages = progress.stages || [];
      if (!stages.length) {
        document.getElementById("pipeline-summary").textContent = "Pipeline state not available yet.";
        document.getElementById("pipeline-stages").innerHTML = "";
        return;
      }
      const current = progress.current_label || "Waiting";
      const completed = progress.completed_count || 0;
      const total = progress.total_count || stages.length;
      document.getElementById("pipeline-summary").textContent =
        `${current} • ${completed}/${total} stages complete`;
      document.getElementById("pipeline-stages").innerHTML = stages.map((stage, index) => `
        <div class="pipeline-stage ${escapeHtml(stage.status || "pending")}">
          <div class="step">Step ${index + 1}</div>
          <div class="name">${escapeHtml(stage.label || stage.key || "")}</div>
          <div class="state">${escapeHtml(stage.state_text || stage.status || "")}</div>
        </div>
      `).join("");
    }

    function renderDetail(state, detail) {
      const baseline = (state.runs || []).find((row) => row.is_baseline) || null;
      const run = (state.runs || []).find((row) => row.run_id === selectedRunId) || baseline || (state.runs || [])[0] || null;
      if (!run) {
        document.getElementById("detail-title").textContent = "Run Detail";
        document.getElementById("run-meta").textContent = "No run selected.";
        document.getElementById("detail-status").innerHTML = "";
        document.getElementById("run-output").textContent = "";
        document.getElementById("baseline-output").textContent = "";
        document.getElementById("judge-output").textContent = "";
        document.getElementById("server-log").textContent = "";
        document.getElementById("run-output-meta").textContent = "";
        document.getElementById("baseline-output-meta").textContent = "";
        document.getElementById("judge-output-meta").textContent = "";
        document.getElementById("server-status-meta").textContent = "";
        document.getElementById("task-list").innerHTML = "";
        document.getElementById("pipeline-summary").textContent = "Pipeline state not available yet.";
        document.getElementById("pipeline-stages").innerHTML = "";
        return;
      }

      document.getElementById("detail-title").textContent = run.display_label || run.run_id;
      const live = (detail || {}).live_status || {};
      const currentTarget = (live.current_sample || "") + ((live.current_task_id || "") ? " :: " + live.current_task_id : "");
      document.getElementById("run-meta").innerHTML =
        `run_id=<code>${escapeHtml(run.run_id)}</code> • pipeline=<code>${escapeHtml(run.pipeline || "")}</code> • architecture=<code>${escapeHtml(run.architecture || "")}</code> • current=${escapeHtml(currentTarget || "idle")}`;
      document.getElementById("detail-status").innerHTML =
        `<span class="status-pill ${statusClass(run.status)}">${statusIcon(run.status)} ${escapeHtml(run.status)}</span>`;
      const runOutput = (detail || {}).run_output || {};
      const baselineOutput = (detail || {}).baseline_output || {};
      const judgeOutput = (detail || {}).judge_summary || {};
      const serverStatus = (detail || {}).server_status || {};
      document.getElementById("run-output").textContent = runOutput.text || "";
      document.getElementById("baseline-output").textContent = baselineOutput.text || "";
      document.getElementById("judge-output").textContent = judgeOutput.text || "";
      document.getElementById("server-log").textContent = serverStatus.text || "";
      document.getElementById("run-output-meta").textContent = runOutput.meta || "";
      document.getElementById("baseline-output-meta").textContent = baselineOutput.meta || "";
      document.getElementById("judge-output-meta").textContent = judgeOutput.path ? `latest file: ${judgeOutput.path}` : "Latest judge summary";
      document.getElementById("server-status-meta").textContent = serverStatus.meta || "Live server logs and transient status messages.";
      renderPipeline(detail);
      renderTasks(detail);
    }

    async function refresh() {
      try {
        const state = await loadJson("/api/state");
        renderSummary(state);
        renderRunTable(state);
        const runId = selectedRunId || (((state.runs || [])[0] || {}).run_id || "");
        if (runId) {
          const detail = await loadJson(`/api/detail?run_id=${encodeURIComponent(runId)}`);
          renderDetail(state, detail);
        } else {
          renderDetail(state, null);
        }
      } catch (error) {
        document.getElementById("subtitle").textContent = `Live view error: ${error}`;
      }
    }

    refresh();
    setInterval(refresh, 1500);
  </script>
</body>
</html>
"""


_STAGE_STARTED_RE = re.compile(r"Stage started:\s*([A-Za-z0-9_]+)")
_STAGE_FINISHED_RE = re.compile(r"Stage finished:\s*([A-Za-z0-9_]+)")

_HARNESS_PROGRESS_STAGES: List[Tuple[str, str]] = [
    ("build", "Build"),
    ("prepare", "Prepare Bundles"),
    ("harness_preflight", "Harness Preflight"),
]

_POST_ANALYSIS_PROGRESS_STAGES: List[Tuple[str, str]] = [
    ("judge", "Judge"),
    ("aggregate", "Aggregate"),
    ("completed", "Complete"),
]

_AGENT_STAGE_LABELS = {
    "preflight": "Agent Preflight",
    "presweeps": "Deterministic Sweeps",
    "planner": "Planner",
    "workers": "Workers",
    "validators": "Validators",
    "reporter": "Reporter",
}


def _safe_json(path: Path) -> Dict[str, Any]:
    """
    Function: _safe_json
    Inputs:
      - path: artifact path expected to contain JSON.
    Description:
      Load a JSON artifact defensively so the live monitor can tolerate
      partially written or missing files while runs are still active.
    Outputs:
      Returns the parsed JSON object, or an empty dictionary on failure.
    Side Effects:
      Reads a file from disk.
    """
    if not path.exists():
        return {}
    try:
        return read_json(path)
    except Exception:
        return {}


def _safe_text(path: Path, max_chars: int = 120000) -> str:
    """
    Function: _safe_text
    Inputs:
      - path: text file path to read.
      - max_chars: maximum trailing character count to keep in memory.
    Description:
      Read a text artifact defensively and keep only the tail so very large
      logs do not overwhelm the monitor payload.
    Outputs:
      Returns the loaded text, or an empty string on failure.
    Side Effects:
      Reads a file from disk.
    """
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


@lru_cache(maxsize=1)
def _pipeline_stage_names_by_preset() -> Dict[str, List[str]]:
    path = REPO_ROOT / "multi_agent_wf" / "workflow_config" / "pipeline_presets.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

    resolved: Dict[str, List[str]] = {}
    if not isinstance(raw, dict):
        return resolved
    for preset_name, value in raw.items():
        stages = value
        if isinstance(value, dict):
            stages = value.get("stages")
        if not isinstance(stages, list):
            continue
        names = [
            str(stage.get("name") or "").strip()
            for stage in stages
            if isinstance(stage, dict) and str(stage.get("name") or "").strip()
        ]
        resolved[str(preset_name)] = names
    return resolved


def _label_agent_stage(stage_name: str) -> str:
    normalized = str(stage_name or "").strip()
    if not normalized:
        return "Analysis"
    return _AGENT_STAGE_LABELS.get(normalized, normalized.replace("_", " ").title())


def _latest_json_by_name(root: Path, filename: str) -> Tuple[Dict[str, Any], Path | None]:
    latest_path: Path | None = None
    latest_mtime = -1.0
    for path in root.rglob(filename):
        try:
            mtime = path.stat().st_mtime
        except Exception:
            continue
        if mtime >= latest_mtime:
            latest_mtime = mtime
            latest_path = path
    if latest_path is None:
        return {}, None
    return _safe_json(latest_path), latest_path


def _build_pending_output_text(live_status: Dict[str, Any], *, label: str) -> str:
    current = str(live_status.get("current_sample") or "").strip()
    task_id = str(live_status.get("current_task_id") or "").strip()
    current_target = current + (f" :: {task_id}" if current and task_id else "")
    lines = [
        f"{label} is not available yet.",
        "",
        f"run status: {str(live_status.get('status') or 'pending')}",
        f"current stage: {str(live_status.get('stage') or 'initializing')}",
    ]
    if current_target:
        lines.append(f"current task: {current_target}")
    last_message = str(live_status.get("last_message") or "").strip()
    if last_message:
        lines.extend(["", last_message])
    return "\n".join(lines).strip() + "\n"


def _summarize_run_output(
    run_dir: Path | None,
    live_status: Dict[str, Any],
    *,
    label: str = "Run output",
    treat_as_baseline_self: bool = False,
) -> Dict[str, str]:
    if run_dir is None or not run_dir.exists():
        return {
            "text": _build_pending_output_text(live_status, label=label),
            "meta": "Waiting for run artifacts.",
            "path": "",
        }
    if treat_as_baseline_self:
        return {
            "text": "Selected run is the baseline.\n",
            "meta": "Baseline comparison target is the selected run itself.",
            "path": "",
        }

    report_path = run_dir / "report.md"
    if report_path.exists():
        return {
            "text": _safe_text(report_path),
            "meta": f"Final run report • {report_path.name}",
            "path": str(report_path),
        }

    agent_payload, agent_path = _latest_json_by_name(run_dir / "samples", "agent_result.json")
    if agent_payload:
        final_report = str(agent_payload.get("final_report") or "").strip()
        status = str(agent_payload.get("status") or "").strip()
        if final_report:
            return {
                "text": final_report + ("\n" if not final_report.endswith("\n") else ""),
                "meta": f"Latest agent result • status={status or 'completed'}",
                "path": str(agent_path) if agent_path else "",
            }
        failure_reason = str(agent_payload.get("failure_reason") or agent_payload.get("error") or "").strip()
        lines = []
        if status:
            lines.append(f"status: {status}")
        if failure_reason:
            lines.extend(["", failure_reason])
        status_log = str(agent_payload.get("status_log") or "").strip()
        if status_log:
            lines.extend(["", "status_log:", status_log])
        text = "\n".join(lines).strip() if lines else _build_pending_output_text(live_status, label=label).strip()
        return {
            "text": text + ("\n" if text and not text.endswith("\n") else ""),
            "meta": f"Latest agent result • {agent_path.name if agent_path else 'agent_result.json'}",
            "path": str(agent_path) if agent_path else "",
        }

    return {
        "text": _build_pending_output_text(live_status, label=label),
        "meta": "Agent output pending.",
        "path": "",
    }


def _parse_agent_stage_history(log_text: str) -> Tuple[List[str], List[str], str]:
    started = _STAGE_STARTED_RE.findall(log_text or "")
    finished = _STAGE_FINISHED_RE.findall(log_text or "")
    current = ""
    finished_counts: Dict[str, int] = {}
    for name in finished:
        finished_counts[name] = finished_counts.get(name, 0) + 1
    seen_started: Dict[str, int] = {}
    for name in started:
        seen_started[name] = seen_started.get(name, 0) + 1
        if seen_started[name] > finished_counts.get(name, 0):
            current = name
    return started, finished, current


def _build_pipeline_progress(
    *,
    run_entry: Dict[str, Any],
    run_manifest: Dict[str, Any],
    live_status: Dict[str, Any],
    log_text: str,
) -> Dict[str, Any]:
    """
    Function: _build_pipeline_progress
    Inputs:
      - run_entry: experiment run-catalog row for the selected child run.
      - run_manifest: canonical run manifest for that child run.
      - live_status: latest persisted live-status snapshot from the runner.
      - log_text: streamed child log text used to infer inner stage progress.
    Description:
      Merge harness-level status and inner agent-stage signals into one stage
      progress model that the live monitor can render consistently.
    Outputs:
      Returns a normalized pipeline-progress dictionary containing the ordered
      stage list, current stage label, and completion counts.
    Side Effects:
      None.
    """
    pipeline_name = str((run_manifest.get("pipeline") or run_entry.get("pipeline") or "")).strip()
    configured_agent_stages = list(_pipeline_stage_names_by_preset().get(pipeline_name) or [])
    started_agent_stages, finished_agent_stages, current_agent_stage = _parse_agent_stage_history(log_text)
    if not configured_agent_stages:
        configured_agent_stages = list(dict.fromkeys(started_agent_stages))
    if not configured_agent_stages:
        configured_agent_stages = ["analysis"]

    live_stage = str(live_status.get("stage") or "").strip().lower()
    run_status = str(live_status.get("status") or run_entry.get("status") or "pending").strip().lower()
    judge_mode = str(run_manifest.get("judge_mode") or "agent").strip().lower() or "agent"

    stages: List[Dict[str, str]] = []
    for key, label in _HARNESS_PROGRESS_STAGES:
        stages.append({"key": key, "label": label, "status": "pending", "state_text": "Pending"})
    for name in configured_agent_stages:
        stages.append({
            "key": f"agent:{name}",
            "label": _label_agent_stage(name),
            "status": "pending",
            "state_text": "Pending",
        })
    if judge_mode != "disabled":
        for key, label in _POST_ANALYSIS_PROGRESS_STAGES:
            stages.append({"key": key, "label": label, "status": "pending", "state_text": "Pending"})
    else:
        stages.extend([
            {"key": "aggregate", "label": "Aggregate", "status": "pending", "state_text": "Pending"},
            {"key": "completed", "label": "Complete", "status": "pending", "state_text": "Pending"},
        ])

    key_to_index = {stage["key"]: index for index, stage in enumerate(stages)}
    current_key = ""
    if live_stage == "build":
        current_key = "build"
    elif live_stage == "prepare":
        current_key = "prepare"
    elif live_stage in {"preflight", "preflight_failed", "preflight_only"}:
        current_key = "harness_preflight"
    elif live_stage == "analysis":
        agent_name = current_agent_stage or configured_agent_stages[0]
        current_key = f"agent:{agent_name}"
    elif live_stage == "judge" and judge_mode != "disabled":
        current_key = "judge"
    elif live_stage in {"aggregate", "budget_aborted"}:
        current_key = "aggregate"
    elif live_stage == "completed" or run_status == "completed":
        current_key = "completed"
    elif current_agent_stage:
        current_key = f"agent:{current_agent_stage}"
    elif run_status == "pending":
        current_key = "build"

    current_index = key_to_index.get(current_key, -1)
    if current_index >= 0:
        for index, stage in enumerate(stages):
            if index < current_index:
                stage["status"] = "completed"
                stage["state_text"] = "Completed"
            elif index == current_index:
                stage["status"] = "running"
                stage["state_text"] = "In progress"

    finished_set = set(finished_agent_stages)
    for name in configured_agent_stages:
        key = f"agent:{name}"
        stage_index = key_to_index.get(key)
        if stage_index is None:
            continue
        if name in finished_set:
            stages[stage_index]["status"] = "completed"
            stages[stage_index]["state_text"] = "Completed"

    if live_stage in {"judge", "aggregate", "completed"} or run_status == "completed":
        for name in configured_agent_stages:
            stage_index = key_to_index.get(f"agent:{name}")
            if stage_index is not None:
                stages[stage_index]["status"] = "completed"
                stages[stage_index]["state_text"] = "Completed"
    if live_stage in {"aggregate", "completed"} or run_status == "completed":
        judge_index = key_to_index.get("judge")
        if judge_index is not None:
            stages[judge_index]["status"] = "completed"
            stages[judge_index]["state_text"] = "Completed"
    if live_stage == "completed" or run_status == "completed":
        aggregate_index = key_to_index.get("aggregate")
        completed_index = key_to_index.get("completed")
        if aggregate_index is not None:
            stages[aggregate_index]["status"] = "completed"
            stages[aggregate_index]["state_text"] = "Completed"
        if completed_index is not None:
            stages[completed_index]["status"] = "completed"
            stages[completed_index]["state_text"] = "Completed"

    if run_status == "failed":
        failure_key = current_key or ("completed" if live_stage == "completed" else "")
        failure_index = key_to_index.get(failure_key, None)
        if failure_index is not None:
            stages[failure_index]["status"] = "failed"
            stages[failure_index]["state_text"] = "Failed"

    completed_count = sum(1 for stage in stages if stage["status"] == "completed")
    current_label = next((stage["label"] for stage in stages if stage["status"] in {"running", "failed"}), "")
    if not current_label and run_status == "completed":
        current_label = "Completed"
    if not current_label:
        current_label = "Pending"
    return {
        "pipeline_name": pipeline_name,
        "current_key": current_key,
        "current_label": current_label,
        "completed_count": completed_count,
        "total_count": len(stages),
        "stages": stages,
    }

def _summarize_judge(run_dir: Path) -> Dict[str, Any]:
    judge_payload, judge_path = _latest_json_by_name(run_dir / "samples", "judge_result.json")
    if not judge_payload:
        return {"text": "Judge output not available yet.", "path": ""}
    lines = []
    if judge_path is not None:
        lines.append(f"path: {judge_path}")
    lines.append(f"status: {judge_payload.get('status') or ''}")
    lines.append(f"pass: {judge_payload.get('pass')}")
    lines.append(f"overall_score_0_to_100: {judge_payload.get('overall_score_0_to_100')}")
    technical_summary = str(judge_payload.get("technical_summary") or "").strip()
    if technical_summary:
        lines.extend(["", "technical_summary:", technical_summary])
    writing_summary = str(judge_payload.get("writing_summary") or "").strip()
    if writing_summary:
        lines.extend(["", "writing_summary:", writing_summary])
    strongest = [str(item).strip() for item in (judge_payload.get("strongest_points") or []) if str(item).strip()]
    if strongest:
        lines.extend(["", "strongest_points:"] + [f"- {item}" for item in strongest])
    missed = [str(item).strip() for item in (judge_payload.get("missed_expected_points") or []) if str(item).strip()]
    if missed:
        lines.extend(["", "missed_expected_points:"] + [f"- {item}" for item in missed])
    return {"text": "\n".join(lines).strip() + "\n", "path": str(judge_path) if judge_path else ""}


def build_live_view_index(live_view_dir: Path) -> Path:
    """
    Function: build_live_view_index
    Inputs:
      - live_view_dir: directory where the monitor assets should live.
    Description:
      Ensure the live-view directory exists and write the static HTML index
      served by the monitor.
    Outputs:
      Returns the path to the generated `index.html` file.
    Side Effects:
      Creates the live-view directory and writes the UI HTML asset.
    """
    ensure_dir(live_view_dir)
    index_path = live_view_dir / "index.html"
    index_path.write_text(_INDEX_HTML, encoding="utf-8")
    return index_path


def load_live_view_state(experiment_root: Path) -> Dict[str, Any]:
    """
    Function: load_live_view_state
    Inputs:
      - experiment_root: root directory for one experiment sweep.
    Description:
      Load and summarize the experiment-level run catalog for the live monitor,
      including the status rollup and queue rows shown in the sidebar.
    Outputs:
      Returns the JSON-serializable state payload served to the monitor UI.
    Side Effects:
      Reads experiment artifacts from disk.
    """
    manifest = _safe_json(experiment_root / "experiment_manifest.json")
    catalog = _safe_json(experiment_root / "run_catalog.json")
    preflight = _safe_json(experiment_root / "preflight.json")
    budget = _safe_json(experiment_root / "budget_status.json")
    runs: List[Dict[str, Any]] = []
    counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "skipped": 0}
    for raw_entry in (catalog.get("runs") or []):
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        run_id = str(entry.get("run_id") or "").strip()
        run_dir = Path(str(entry.get("run_dir") or "")).expanduser() if entry.get("run_dir") else None
        live_status = _safe_json(run_dir / "live_status.json") if run_dir and run_dir.exists() else {}
        if live_status:
            entry["stage"] = str(live_status.get("stage") or entry.get("stage") or "")
            entry["current_phase"] = str(live_status.get("current_phase") or entry.get("current_phase") or "")
        status = str(entry.get("status") or ("completed" if entry.get("ok") else "pending")).strip().lower() or "pending"
        if status not in counts:
            counts[status] = 0
        counts[status] += 1
        entry["status"] = status
        entry["run_id"] = run_id
        runs.append(entry)
    return {
        "experiment_id": experiment_root.name,
        "experiment_root": str(experiment_root),
        "corpus": str(manifest.get("corpus") or ""),
        "preflight_ok": bool(preflight.get("ok")) if preflight else None,
        "budget_ok": bool(budget.get("ok")) if budget else None,
        "summary": {
            "total_runs": len(runs),
            **counts,
        },
        "runs": runs,
    }


def load_live_view_detail(experiment_root: Path, run_id: str) -> Dict[str, Any]:
    """
    Function: load_live_view_detail
    Inputs:
      - experiment_root: root directory for one experiment sweep.
      - run_id: child run identifier selected in the monitor UI.
    Description:
      Gather the richer per-run detail shown in the monitor, including live
      status, output summaries, judge summaries, logs, and pipeline progress.
    Outputs:
      Returns the JSON-serializable detail payload for the requested run.
    Side Effects:
      Reads per-run artifacts and streamed child logs from disk.
    """
    state = load_live_view_state(experiment_root)
    runs = [row for row in (state.get("runs") or []) if str(row.get("run_id") or "") == str(run_id or "")]
    run_entry = runs[0] if runs else {}
    baseline_entry = next((row for row in (state.get("runs") or []) if row.get("is_baseline")), {})
    run_dir = Path(str(run_entry.get("run_dir") or "")).expanduser() if run_entry.get("run_dir") else None
    baseline_dir = Path(str(baseline_entry.get("run_dir") or "")).expanduser() if baseline_entry.get("run_dir") else None
    log_path = Path(str(run_entry.get("log_path") or "")).expanduser() if run_entry.get("log_path") else None
    live_status = _safe_json(run_dir / "live_status.json") if run_dir and run_dir.exists() else {}
    run_manifest = _safe_json(run_dir / "run_manifest.json") if run_dir and run_dir.exists() else {}
    run_log = _safe_text(log_path) if log_path else ""
    baseline_is_self = bool(run_entry) and bool(baseline_entry) and str(run_entry.get("run_id") or "") == str(baseline_entry.get("run_id") or "")
    return {
        "run_id": str(run_entry.get("run_id") or ""),
        "run_log": run_log,
        "live_status": live_status,
        "run_manifest": run_manifest,
        "run_output": _summarize_run_output(run_dir, live_status, label="Run output"),
        "baseline_output": _summarize_run_output(
            baseline_dir,
            _safe_json(baseline_dir / "live_status.json") if baseline_dir and baseline_dir.exists() else {},
            label="Baseline output",
            treat_as_baseline_self=baseline_is_self,
        ),
        "judge_summary": _summarize_judge(run_dir) if run_dir and run_dir.exists() else {"text": "Judge output not available yet.", "path": ""},
        "server_status": {
            "text": run_log or "Server status not available yet.\n",
            "meta": f"Live log stream • {log_path.name}" if log_path and log_path.exists() else "Waiting for live log stream.",
            "path": str(log_path) if log_path else "",
        },
        "pipeline_progress": _build_pipeline_progress(
            run_entry=run_entry,
            run_manifest=run_manifest,
            live_status=live_status,
            log_text=run_log,
        ),
    }


class _LiveViewHandler(BaseHTTPRequestHandler):
    experiment_root: Path
    live_view_dir: Path

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, content_type: str = "text/html; charset=utf-8", status: int = 200) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._send_text(_INDEX_HTML)
            return
        if parsed.path == "/api/state":
            self._send_json(load_live_view_state(self.experiment_root))
            return
        if parsed.path == "/api/detail":
            params = urllib.parse.parse_qs(parsed.query)
            run_id = str((params.get("run_id") or [""])[0] or "")
            self._send_json(load_live_view_detail(self.experiment_root, run_id))
            return
        self._send_text("Not found\n", content_type="text/plain; charset=utf-8", status=404)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return


def start_live_view_server(experiment_root: Path, *, host: str = "127.0.0.1", port: int = 0) -> Tuple[ThreadingHTTPServer, threading.Thread, str]:
    """
    Function: start_live_view_server
    Inputs:
      - experiment_root: root directory for the active experiment sweep.
      - host: interface to bind for local HTTP access.
      - port: optional preferred port; `0` asks the OS to choose one.
    Description:
      Start the lightweight HTTP server that serves the polling monitor for an
      active experiment sweep.
    Outputs:
      Returns the server object, the background server thread, and the monitor
      URL that should be printed to the operator.
    Side Effects:
      Creates the live-view index, starts a background HTTP server thread, and
      writes the chosen monitor URL to `live_view_url.txt`.
    """
    live_view_dir = ensure_dir(experiment_root / "live_view")
    build_live_view_index(live_view_dir)

    handler = type(
        "TestingLiveViewHandler",
        (_LiveViewHandler,),
        {"experiment_root": experiment_root, "live_view_dir": live_view_dir},
    )
    server = ThreadingHTTPServer((host, int(port)), handler)
    thread = threading.Thread(target=server.serve_forever, name="testing-live-view", daemon=True)
    thread.start()
    url = f"http://{server.server_address[0]}:{server.server_address[1]}/"
    (live_view_dir / "live_view_url.txt").write_text(url + "\n", encoding="utf-8")
    return server, thread, url
