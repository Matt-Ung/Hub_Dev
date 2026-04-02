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
from .samples import sample_slug


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Testing Live Progress</title>
  <style>
    :root {
      --bg: #edf3fb;
      --panel: rgba(255, 255, 255, 0.9);
      --panel-strong: #ffffff;
      --line: rgba(18, 31, 53, 0.12);
      --line-strong: rgba(18, 31, 53, 0.22);
      --ink: #0f172a;
      --muted: #5a6578;
      --muted-soft: #7c8798;
      --shadow: 0 18px 42px rgba(15, 23, 42, 0.08);
      --ok: #157f5e;
      --run: #2459d1;
      --wait: #9a6412;
      --fail: #b42318;
      --pending-bg: #fff4d6;
      --running-bg: #dce9ff;
      --completed-bg: #dff5eb;
      --failed-bg: #fbe2df;
      --skipped-bg: #eceff4;
      --accent: linear-gradient(135deg, #173a8a 0%, #3f86ff 100%);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Inter", "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(63, 134, 255, 0.16), transparent 28%),
        linear-gradient(180deg, #f8fbff 0%, var(--bg) 45%, #e8eef7 100%);
      color: var(--ink);
    }
    h1, h2, h3 { margin: 0; }
    .wrap { padding: 24px; max-width: 1760px; margin: 0 auto; }
    .topbar {
      display: flex;
      flex-direction: column;
      gap: 18px;
      margin-bottom: 18px;
    }
    .hero {
      padding: 20px 22px;
      border-radius: 24px;
      border: 1px solid rgba(255, 255, 255, 0.7);
      background:
        linear-gradient(135deg, rgba(23, 58, 138, 0.96), rgba(63, 134, 255, 0.92)),
        rgba(255, 255, 255, 0.12);
      box-shadow: var(--shadow);
      color: #f8fbff;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: rgba(248, 251, 255, 0.78);
    }
    .hero h1 { font-size: 34px; letter-spacing: -0.03em; margin-bottom: 8px; }
    .hero p { margin: 0; color: rgba(248, 251, 255, 0.84); line-height: 1.6; }
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
    .card .label {
      font-size: 12px;
      color: var(--muted-soft);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
    }
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
    .workspace {
      display: grid;
      grid-template-columns: minmax(260px, 1fr) minmax(260px, 1fr) minmax(540px, 2fr);
      gap: 18px;
      align-items: start;
    }
    .panel {
      min-width: 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
      overflow: hidden;
    }
    .panel-head {
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(246,250,255,0.94));
    }
    .panel-body {
      padding: 14px;
      min-width: 0;
    }
    .queue-panel,
    .runs-panel,
    .detail-panel {
      display: flex;
      flex-direction: column;
      min-height: 760px;
    }
    .queue-panel .panel-body,
    .runs-panel .panel-body,
    .detail-panel .panel-body {
      flex: 1 1 auto;
    }
    .queue-panel .panel-body,
    .runs-panel .panel-body {
      display: flex;
      flex-direction: column;
      gap: 12px;
      max-height: calc(100vh - 250px);
      overflow: auto;
    }
    .detail-panel .panel-body {
      display: flex;
      flex-direction: column;
      gap: 18px;
      max-height: calc(100vh - 250px);
      overflow: auto;
    }
    .kicker {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--run);
    }
    .panel-head h2 {
      font-size: 25px;
      letter-spacing: -0.03em;
    }
    .sub {
      margin-top: 6px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    .column-empty {
      border: 1px dashed var(--line-strong);
      border-radius: 18px;
      padding: 18px;
      color: var(--muted);
      background: rgba(255,255,255,0.56);
      line-height: 1.6;
    }
    .queue-card,
    .run-card {
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.84);
      transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease, background 150ms ease;
      overflow: hidden;
    }
    .queue-card:hover,
    .run-card:hover {
      transform: translateY(-1px);
      border-color: var(--line-strong);
      box-shadow: 0 14px 28px rgba(15, 23, 42, 0.08);
    }
    .queue-card.sel,
    .run-card.sel {
      border-color: rgba(36, 89, 209, 0.34);
      box-shadow: 0 18px 34px rgba(36, 89, 209, 0.10);
      background: rgba(239, 246, 255, 0.96);
    }
    .run-card.active {
      border-color: rgba(36, 89, 209, 0.28);
      background: rgba(220, 233, 255, 0.56);
    }
    button.card-link {
      all: unset;
      display: block;
      width: 100%;
      cursor: pointer;
      color: inherit;
      padding: 14px 16px;
    }
    .card-top,
    .run-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      margin-bottom: 8px;
    }
    .card-eyebrow {
      font-size: 11px;
      color: var(--muted-soft);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
      margin-bottom: 6px;
    }
    .card-title,
    .run-title {
      font-weight: 800;
      letter-spacing: -0.02em;
      line-height: 1.3;
      overflow-wrap: anywhere;
    }
    .card-meta,
    .run-meta {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    .run-meta + .run-meta {
      margin-top: 6px;
      color: var(--muted-soft);
      font-size: 12px;
    }
    .count-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 12px;
    }
    .count-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid transparent;
      background: rgba(15, 23, 42, 0.04);
      color: var(--muted);
    }
    .count-chip strong { font-size: 12px; color: inherit; }
    .count-chip.status-running,
    .count-chip.status-in-progress {
      background: var(--running-bg);
      color: var(--run);
      border-color: rgba(36, 89, 209, 0.14);
    }
    .count-chip.status-pending {
      background: var(--pending-bg);
      color: var(--wait);
      border-color: rgba(154, 100, 18, 0.14);
    }
    .count-chip.status-completed {
      background: var(--completed-bg);
      color: var(--ok);
      border-color: rgba(21, 127, 94, 0.14);
    }
    .count-chip.status-failed {
      background: var(--failed-bg);
      color: var(--fail);
      border-color: rgba(180, 35, 24, 0.14);
    }
    .count-chip.neutral {
      background: rgba(15, 23, 42, 0.04);
      color: var(--muted);
      border-color: rgba(15, 23, 42, 0.08);
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.01em;
      white-space: nowrap;
    }
    .status-pending { background: var(--pending-bg); color: var(--wait); }
    .status-running,
    .status-in-progress { background: var(--running-bg); color: var(--run); }
    .status-completed { background: var(--completed-bg); color: var(--ok); }
    .status-failed { background: var(--failed-bg); color: var(--fail); }
    .status-skipped { background: var(--skipped-bg); color: var(--muted); }
    .detail-head {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
    }
    .detail-title-block h2 {
      font-size: 30px;
      letter-spacing: -0.03em;
    }
    .detail-meta {
      margin-top: 6px;
      color: var(--muted);
      line-height: 1.6;
      font-size: 14px;
    }
    .focus-strip {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }
    .focus-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.05);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    .pipeline-box {
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 16px 18px 18px;
      background: linear-gradient(180deg, rgba(248,251,255,0.95), rgba(255,255,255,0.92));
    }
    .pipeline-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: baseline;
      margin-bottom: 14px;
    }
    .pipeline-head h3 {
      font-size: 15px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted-soft);
    }
    .pipeline-summary { color: var(--ink); font-weight: 700; }
    .pipeline-track {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(108px, 1fr));
      gap: 12px;
      align-items: stretch;
    }
    .pipeline-stage {
      position: relative;
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 12px 12px 14px;
      background: rgba(255,255,255,0.8);
      min-height: 88px;
      transition: transform 180ms ease, border-color 180ms ease, background 180ms ease;
    }
    .pipeline-stage.running { border-color: rgba(36, 89, 209, 0.34); background: rgba(220, 233, 255, 0.82); transform: translateY(-1px); }
    .pipeline-stage.completed { border-color: rgba(21, 127, 94, 0.26); background: rgba(223, 245, 235, 0.82); }
    .pipeline-stage.failed { border-color: rgba(180, 35, 24, 0.28); background: rgba(251, 226, 223, 0.84); }
    .pipeline-stage .step {
      font-size: 11px;
      color: var(--muted-soft);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 10px;
    }
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
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 18px;
      align-items: stretch;
    }
    .surface {
      border: 1px solid var(--line);
      border-radius: 20px;
      overflow: hidden;
      background: var(--panel-strong);
      min-width: 0;
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
    .surface .title h3 {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted-soft);
      margin-bottom: 6px;
    }
    .surface .title .sub { margin-top: 0; }
    .output-panel .title {
      min-height: 84px;
      display: flex;
      flex-direction: column;
      justify-content: flex-start;
    }
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
      min-height: 320px;
      max-height: 620px;
      flex: 1 1 auto;
    }
    .logs-panel pre {
      max-height: 320px;
      background: #09111f;
      color: #d8e3f5;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      text-align: left;
    }
    th {
      font-size: 11px;
      color: var(--muted-soft);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
    }
    .task-row {
      cursor: pointer;
      transition: background 150ms ease;
    }
    .task-row:hover { background: rgba(36, 89, 209, 0.04); }
    .task-row.sel { background: rgba(36, 89, 209, 0.08); }
    .muted { color: var(--muted); }
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
    @media (max-width: 1380px) {
      .workspace {
        grid-template-columns: minmax(240px, 1fr) minmax(240px, 1fr) minmax(460px, 1.6fr);
      }
    }
    @media (max-width: 1100px) {
      .workspace { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .detail-panel { grid-column: 1 / -1; }
      .queue-panel .panel-body,
      .runs-panel .panel-body,
      .detail-panel .panel-body { max-height: none; }
    }
    @media (max-width: 760px) {
      .wrap { padding: 16px; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .summary-card-wide { grid-column: span 2; }
      .workspace { grid-template-columns: 1fr; }
      .detail-panel { grid-column: auto; }
      .pipeline-track { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .detail-grid { grid-template-columns: 1fr; }
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
        <h1>Testing Workflow View</h1>
        <p id="subtitle">Loading…</p>
      </div>
      <div class="summary" id="summary"></div>
    </div>

    <div class="workspace">
      <section class="panel queue-panel">
        <div class="panel-head">
          <div class="kicker">Step 1</div>
          <h2>Executable Queue</h2>
          <div class="sub" id="executables-meta">Select an executable to inspect its run sequence.</div>
        </div>
        <div class="panel-body" id="executable-rows"></div>
      </section>

      <section class="panel runs-panel">
        <div class="panel-head">
          <div class="kicker">Step 2</div>
          <h2 id="run-list-title">Runs For Executable</h2>
          <div class="sub" id="run-list-meta">Select an executable to view its baseline and variants.</div>
        </div>
        <div class="panel-body" id="run-rows"></div>
      </section>

      <section class="panel detail-panel">
        <div class="panel-head">
          <div class="kicker">Step 3</div>
          <div class="detail-head">
            <div class="detail-title-block">
              <h2 id="detail-title">Run Detail</h2>
              <div class="detail-meta" id="run-meta">No run selected.</div>
            </div>
            <div id="detail-status"></div>
          </div>
          <div class="focus-strip" id="detail-context"></div>
        </div>
        <div class="panel-body">
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
                <h3>Agent Output</h3>
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
              <div class="sub" id="task-list-meta">Per-task state for the selected executable.</div>
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
      </section>
    </div>
  </div>

  <script>
    const params = new URLSearchParams(window.location.search);
    let selectedExecutable = params.get("sample") || "";
    let selectedRunId = params.get("run_id") || "";
    let selectedSampleTaskId = params.get("sample_task_id") || "";

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
      if (text === "completed" || text === "completed_budget_exceeded" || text === "budget_exceeded") return "status-completed";
      if (text === "running" || text === "in_progress") return `status-${text.replaceAll("_", "-")}`;
      if (text === "failed") return "status-failed";
      if (text === "skipped") return "status-skipped";
      return "status-pending";
    }

    function statusIcon(status) {
      const text = String(status || "pending").toLowerCase();
      if (text === "completed" || text === "completed_budget_exceeded" || text === "budget_exceeded") return "✓";
      if (text === "running") return "…";
      if (text === "in_progress") return "◐";
      if (text === "failed") return "✕";
      if (text === "skipped") return "–";
      return "○";
    }

    function statusLabel(status) {
      const text = String(status || "pending").toLowerCase();
      if (text === "completed_budget_exceeded") return "completed (budget exceeded)";
      if (text === "budget_exceeded") return "budget exceeded";
      return text.replaceAll("_", " ");
    }

    async function loadJson(path) {
      const response = await fetch(path, { cache: "no-store" });
      if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
      }
      return await response.json();
    }

    function updateUrl() {
      const next = new URL(window.location.href);
      if (selectedExecutable) next.searchParams.set("sample", selectedExecutable);
      else next.searchParams.delete("sample");
      if (selectedRunId) next.searchParams.set("run_id", selectedRunId);
      else next.searchParams.delete("run_id");
      if (selectedSampleTaskId) next.searchParams.set("sample_task_id", selectedSampleTaskId);
      else next.searchParams.delete("sample_task_id");
      window.history.replaceState({}, "", next);
    }

    function normalizeSelection(state) {
      const executables = state.executables || [];
      if (!executables.length) {
        selectedExecutable = "";
        selectedRunId = "";
        selectedSampleTaskId = "";
        updateUrl();
        return null;
      }

      if (!selectedExecutable || !executables.some((entry) => entry.sample === selectedExecutable)) {
        const preferredExecutable =
          executables.find((entry) => String(entry.status) === "running") ||
          executables.find((entry) => String(entry.status) === "in_progress") ||
          executables[0];
        selectedExecutable = (preferredExecutable || {}).sample || "";
        selectedSampleTaskId = "";
      }

      const executable = executables.find((entry) => entry.sample === selectedExecutable) || executables[0];
      const runs = (executable || {}).runs || [];
      if (!selectedRunId || !runs.some((entry) => entry.run_id === selectedRunId)) {
        const preferredRun =
          runs.find((entry) => String(entry.status) === "running") ||
          runs.find((entry) => String(entry.status) === "pending") ||
          runs[0];
        selectedRunId = (preferredRun || {}).run_id || "";
        selectedSampleTaskId = "";
      }

      if (selectedSampleTaskId && selectedExecutable && !selectedSampleTaskId.startsWith(`${selectedExecutable}::`)) {
        selectedSampleTaskId = "";
      }
      updateUrl();
      return executable;
    }

    function renderSummary(state) {
      const summary = state.summary || {};
      const executableCount = (state.executables || []).length;
      const cards = [
        {
          label: "Experiment",
          value: state.experiment_id || "",
          subvalue: `${state.corpus || ""} corpus`,
          extraClass: "summary-card-wide summary-card-experiment",
        },
        { label: "Executables", value: executableCount },
        { label: "Planned runs", value: summary.total_runs || 0 },
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
        `${state.corpus || ""} corpus • ${summary.completed || 0}/${summary.total_runs || 0} child runs finished across ${executableCount} executable(s)`;
    }

    function renderCountChip(label, count, status) {
      if (!count) return "";
      return `<span class="count-chip ${statusClass(status)}"><strong>${escapeHtml(count)}</strong>${escapeHtml(label)}</span>`;
    }

    function renderExecutableQueue(state) {
      const executables = state.executables || [];
      document.getElementById("executables-meta").textContent =
        executables.length
          ? `${executables.length} executable(s) planned. Select one to inspect its baseline and variants.`
          : "Executable scope is not available yet.";
      if (!executables.length) {
        document.getElementById("executable-rows").innerHTML = `<div class="column-empty">No executable scope is available yet.</div>`;
        return;
      }
      document.getElementById("executable-rows").innerHTML = executables.map((entry) => {
        const selected = entry.sample === selectedExecutable ? "sel" : "";
        const counts = entry.counts || {};
        const countRow = [
          renderCountChip("running", counts.running, "running"),
          renderCountChip("pending", counts.pending, "pending"),
          renderCountChip("completed", counts.completed, "completed"),
          renderCountChip("failed", counts.failed, "failed"),
        ].filter(Boolean).join("") || `<span class="count-chip neutral"><strong>0</strong>signals</span>`;
        return `
          <div class="queue-card ${selected}">
            <button class="card-link executable-link" data-sample="${escapeAttr(entry.sample || "")}">
              <div class="card-top">
                <div>
                  <div class="card-eyebrow">Executable</div>
                  <div class="card-title">${escapeHtml(entry.sample || "")}</div>
                </div>
                <span class="status-pill ${statusClass(entry.status)}">${statusIcon(entry.status)} ${escapeHtml(statusLabel(entry.status))}</span>
              </div>
              <div class="card-meta">${escapeHtml(entry.summary || "")}</div>
              <div class="card-meta">${escapeHtml(entry.task_summary || "")}</div>
              <div class="count-row">${countRow}</div>
            </button>
          </div>
        `;
      }).join("");
      document.querySelectorAll("button.executable-link").forEach((button) => {
        button.addEventListener("click", () => {
          const nextSample = button.getAttribute("data-sample") || "";
          if (!nextSample || nextSample === selectedExecutable) return;
          selectedExecutable = nextSample;
          selectedRunId = "";
          selectedSampleTaskId = "";
          refresh();
        });
      });
    }

    function renderRunList(state) {
      const executable = (state.executables || []).find((entry) => entry.sample === selectedExecutable) || null;
      if (!executable) {
        document.getElementById("run-list-title").textContent = "Runs For Executable";
        document.getElementById("run-list-meta").textContent = "Select an executable to view related runs.";
        document.getElementById("run-rows").innerHTML = `<div class="column-empty">Select an executable in the left column.</div>`;
        return;
      }

      document.getElementById("run-list-title").textContent = executable.sample || "Runs For Executable";
      document.getElementById("run-list-meta").textContent =
        `${executable.summary || ""} • ${executable.task_summary || ""}`;
      const rows = executable.runs || [];
      if (!rows.length) {
        document.getElementById("run-rows").innerHTML = `<div class="column-empty">No runs are associated with this executable yet.</div>`;
        return;
      }
      document.getElementById("run-rows").innerHTML = rows.map((row) => {
        const selected = row.run_id === selectedRunId ? "sel" : "";
        const active = row.is_active ? "active" : "";
        const typeLabel =
          row.display_label === "baseline" || String(row.display_label || "").endsWith(":baseline")
            ? "Baseline"
            : "Variant";
        const secondaryMeta = [
          row.pipeline ? `pipeline=${row.pipeline}` : "",
          row.architecture ? `arch=${row.architecture}` : "",
          row.global_status && String(row.global_status).toLowerCase() !== String(row.status || "").toLowerCase()
            ? `run=${statusLabel(row.global_status)}`
            : "",
        ].filter(Boolean).join(" • ");
        return `
          <div class="run-card ${selected} ${active}">
            <button class="card-link run-link" data-run-id="${escapeAttr(row.run_id || "")}">
              <div class="run-top">
                <div>
                  <div class="card-eyebrow">${escapeHtml(typeLabel)}</div>
                  <div class="run-title">${escapeHtml(row.display_label || row.run_id || "")}</div>
                </div>
                <span class="status-pill ${statusClass(row.status)}">${statusIcon(row.status)} ${escapeHtml(statusLabel(row.status))}</span>
              </div>
              <div class="run-meta">${escapeHtml(row.meta || "")}</div>
              ${secondaryMeta ? `<div class="run-meta">${escapeHtml(secondaryMeta)}</div>` : ""}
            </button>
          </div>
        `;
      }).join("");
      document.querySelectorAll("button.run-link").forEach((button) => {
        button.addEventListener("click", () => {
          const nextRunId = button.getAttribute("data-run-id") || "";
          if (!nextRunId) return;
          selectedRunId = nextRunId;
          selectedSampleTaskId = "";
          refresh();
        });
      });
    }

    function renderTasks(detail) {
      const taskView = (detail || {}).task_view || {};
      const tasks = taskView.tasks || [];
      const selectedTask = (detail || {}).selected_task || {};
      document.getElementById("task-list-meta").textContent =
        taskView.meta || "Per-task state for the selected executable.";
      if (!selectedSampleTaskId && selectedTask.sample_task_id) {
        selectedSampleTaskId = selectedTask.sample_task_id;
      }
      if (!tasks.length) {
        document.getElementById("task-list").innerHTML = `<div class="column-empty">No task-level progress is available for this executable yet.</div>`;
        return;
      }
      const rows = tasks.map((task) => {
        const sampleTaskId = task.sample_task_id || `${task.sample || ""}::${task.task_id || ""}`;
        const selected = sampleTaskId === selectedSampleTaskId ? "sel" : "";
        const taskLabel = task.task_name || task.task_id || sampleTaskId;
        return `
          <tr class="task-row ${selected}" data-sample-task-id="${escapeAttr(sampleTaskId)}">
            <td>${escapeHtml(taskLabel)}</td>
            <td><span class="status-pill ${statusClass(task.status)}">${statusIcon(task.status)} ${escapeHtml(statusLabel(task.status || ""))}</span></td>
            <td>${escapeHtml(task.judge_status || "")}</td>
            <td>${escapeHtml(task.score ?? "")}</td>
          </tr>
        `;
      }).join("");
      document.getElementById("task-list").innerHTML = `
        <table>
          <thead><tr><th>Task</th><th>Status</th><th>Judge</th><th>Score</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      `;
      document.querySelectorAll("tr.task-row").forEach((row) => {
        row.addEventListener("click", () => {
          selectedSampleTaskId = row.getAttribute("data-sample-task-id") || "";
          updateUrl();
          refresh();
        });
      });
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
      const run = (state.runs || []).find((entry) => entry.run_id === selectedRunId) || null;
      if (!run || !detail) {
        document.getElementById("detail-title").textContent = "Run Detail";
        document.getElementById("run-meta").textContent = "No run selected.";
        document.getElementById("detail-status").innerHTML = "";
        document.getElementById("detail-context").innerHTML = "";
        document.getElementById("run-output").textContent = "";
        document.getElementById("baseline-output").textContent = "";
        document.getElementById("judge-output").textContent = "";
        document.getElementById("server-log").textContent = "";
        document.getElementById("run-output-meta").textContent = "";
        document.getElementById("baseline-output-meta").textContent = "";
        document.getElementById("judge-output-meta").textContent = "";
        document.getElementById("task-list-meta").textContent = "";
        document.getElementById("server-status-meta").textContent = "";
        document.getElementById("task-list").innerHTML = "";
        document.getElementById("pipeline-summary").textContent = "Pipeline state not available yet.";
        document.getElementById("pipeline-stages").innerHTML = "";
        return;
      }

      document.getElementById("detail-title").textContent = run.display_label || run.run_id;
      const live = (detail || {}).live_status || {};
      const comparisonBaseline = (detail || {}).comparison_baseline || {};
      const selectedTask = (detail || {}).selected_task || {};
      const runMetaParts = [
        `run_id=<code>${escapeHtml(run.run_id)}</code>`,
        `pipeline=<code>${escapeHtml(run.pipeline || "")}</code>`,
        `architecture=<code>${escapeHtml(run.architecture || "")}</code>`,
      ];
      if (live.current_sample) {
        runMetaParts.push(`current exe=<code>${escapeHtml(live.current_sample)}</code>`);
      }
      if (live.current_task_id) {
        runMetaParts.push(`current task=<code>${escapeHtml(live.current_task_id)}</code>`);
      }
      if (!live.current_sample && !live.current_task_id) {
        runMetaParts.push("current=idle");
      }
      document.getElementById("run-meta").innerHTML = runMetaParts.join(" • ");
      document.getElementById("detail-status").innerHTML =
        `<span class="status-pill ${statusClass(run.status)}">${statusIcon(run.status)} ${escapeHtml(statusLabel(run.status))}</span>`;

      const contextParts = [];
      if (detail.focused_sample) {
        contextParts.push(`<span class="focus-chip">Executable • ${escapeHtml(detail.focused_sample)}</span>`);
      }
      if (selectedTask.task_id) {
        contextParts.push(`<span class="focus-chip">Task • ${escapeHtml(selectedTask.task_id)}</span>`);
      }
      if (comparisonBaseline.display_label && !comparisonBaseline.is_self) {
        contextParts.push(`<span class="focus-chip">Comparison baseline • ${escapeHtml(comparisonBaseline.display_label)}</span>`);
      }
      document.getElementById("detail-context").innerHTML = contextParts.join("");

      const runOutput = (detail || {}).run_output || {};
      const baselineOutput = (detail || {}).baseline_output || {};
      const judgeOutput = (detail || {}).judge_summary || {};
      const serverStatus = (detail || {}).server_status || {};
      document.getElementById("run-output").textContent = runOutput.text || "";
      document.getElementById("baseline-output").textContent = baselineOutput.text || "";
      document.getElementById("judge-output").textContent = judgeOutput.text || "";
      document.getElementById("server-log").textContent = serverStatus.text || "";

      const runOutputMetaParts = [];
      if (selectedTask.sample_task_id) {
        runOutputMetaParts.push(`Task • ${selectedTask.sample_task_id}`);
      }
      if (runOutput.meta) {
        runOutputMetaParts.push(runOutput.meta);
      }
      document.getElementById("run-output-meta").textContent = runOutputMetaParts.join(" • ");

      const baselineMetaParts = [];
      if (comparisonBaseline.display_label && !comparisonBaseline.is_self) {
        baselineMetaParts.push(`Comparison target • ${comparisonBaseline.display_label}`);
      }
      if (baselineOutput.meta) {
        baselineMetaParts.push(baselineOutput.meta);
      }
      document.getElementById("baseline-output-meta").textContent = baselineMetaParts.join(" • ");
      document.getElementById("judge-output-meta").textContent =
        judgeOutput.path ? `latest file: ${judgeOutput.path}` : "Latest judge summary";
      document.getElementById("server-status-meta").textContent =
        serverStatus.meta || "Live server logs and transient status messages.";

      renderPipeline(detail);
      renderTasks(detail);
    }

    async function refresh() {
      try {
        const state = await loadJson("/api/state");
        normalizeSelection(state);
        renderSummary(state);
        renderExecutableQueue(state);
        renderRunList(state);
        if (selectedRunId) {
          const sampleParam = selectedExecutable ? `&sample=${encodeURIComponent(selectedExecutable)}` : "";
          const sampleTaskParam = selectedSampleTaskId ? `&sample_task_id=${encodeURIComponent(selectedSampleTaskId)}` : "";
          const detail = await loadJson(`/api/detail?run_id=${encodeURIComponent(selectedRunId)}${sampleParam}${sampleTaskParam}`);
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


def _split_sample_task_id(sample_task_id: str) -> Tuple[str, str]:
    text = str(sample_task_id or "").strip()
    if "::" not in text:
        return "", ""
    sample_name, task_id = text.split("::", 1)
    return sample_name.strip(), task_id.strip()


def _task_entries_for_sample(live_status: Dict[str, Any], sample_name: str) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []
    target = str(sample_name or "").strip()
    if not target:
        return tasks
    for raw_entry in (live_status.get("tasks") or []):
        if not isinstance(raw_entry, dict):
            continue
        entry_sample = str(raw_entry.get("sample") or "").strip()
        if not entry_sample:
            entry_sample, _task_id = _split_sample_task_id(str(raw_entry.get("sample_task_id") or "").strip())
        if entry_sample == target:
            tasks.append(raw_entry)
    return tasks


def _classify_task_status(task_status: str) -> str:
    text = str(task_status or "").strip().lower()
    if text == "running":
        return "running"
    if not text or text in {"pending", "not started", "not_started"} or text.startswith("not_run_"):
        return "pending"
    if text in {"failed", "analysis_error", "worker_assignment_failed", "validator_blocked"} or text.startswith("failed_"):
        return "failed"
    if text in {"skipped", "not_applicable"}:
        return "skipped"
    return "completed"


def _resolve_scope_samples_and_tasks(
    manifest: Dict[str, Any],
    runs: List[Dict[str, Any]],
    run_live_statuses: Dict[str, Dict[str, Any]],
) -> Tuple[List[str], List[str]]:
    selected_samples = [
        str(item).strip()
        for item in (manifest.get("selected_samples") or [])
        if str(item).strip()
    ]
    selected_task_keys = [
        str(item).strip()
        for item in (manifest.get("selected_task_keys") or [])
        if str(item).strip()
    ]
    if not selected_samples and selected_task_keys:
        inferred_from_tasks: List[str] = []
        for key in selected_task_keys:
            sample_name, _task_id = _split_sample_task_id(key)
            if sample_name and sample_name not in inferred_from_tasks:
                inferred_from_tasks.append(sample_name)
        selected_samples = inferred_from_tasks
    if not selected_samples:
        inferred: List[str] = []
        for row in runs:
            current_sample = str(row.get("current_sample") or "").strip()
            if current_sample and current_sample not in inferred:
                inferred.append(current_sample)
            live_status = run_live_statuses.get(str(row.get("run_id") or "").strip(), {})
            for raw_task in (live_status.get("tasks") or []):
                if not isinstance(raw_task, dict):
                    continue
                sample_name = str(raw_task.get("sample") or "").strip()
                if not sample_name:
                    sample_name, _task_id = _split_sample_task_id(str(raw_task.get("sample_task_id") or "").strip())
                if sample_name and sample_name not in inferred:
                    inferred.append(sample_name)
        selected_samples = inferred
    return selected_samples, selected_task_keys


def _rollup_executable_status(status_counts: Dict[str, int]) -> str:
    pending = int(status_counts.get("pending") or 0)
    running = int(status_counts.get("running") or 0)
    completed = int(status_counts.get("completed") or 0)
    failed = int(status_counts.get("failed") or 0)
    skipped = int(status_counts.get("skipped") or 0)
    total = pending + running + completed + failed + skipped
    finished = completed + failed + skipped
    if running > 0:
        return "running"
    if total and finished > 0 and pending > 0:
        return "in_progress"
    if total and pending == 0:
        if failed > 0:
            return "failed"
        return "completed"
    return "pending"


def _summarize_executable_run_row(
    row: Dict[str, Any],
    live_status: Dict[str, Any],
    sample_name: str,
) -> Dict[str, Any]:
    effective_run_status = str(live_status.get("status") or row.get("status") or "pending").strip().lower() or "pending"
    current_sample = str(live_status.get("current_sample") or row.get("current_sample") or "").strip()
    current_task_id = str(live_status.get("current_task_id") or row.get("current_task_id") or "").strip()
    phase = str(live_status.get("current_phase") or row.get("current_phase") or row.get("stage") or "not started").strip() or "not started"
    is_active = effective_run_status == "running" and current_sample == sample_name

    sample_tasks = _task_entries_for_sample(live_status, sample_name)
    task_counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "skipped": 0}
    for task_entry in sample_tasks:
        bucket = _classify_task_status(task_entry.get("status"))
        task_counts[bucket] = task_counts.get(bucket, 0) + 1
    total_tasks = len(sample_tasks)
    finished_count = task_counts["completed"] + task_counts["failed"] + task_counts["skipped"]

    sample_status = "pending"
    if is_active or task_counts["running"] > 0:
        sample_status = "running"
    elif total_tasks:
        if finished_count == total_tasks:
            if task_counts["failed"] == total_tasks:
                sample_status = "failed"
            elif task_counts["skipped"] == total_tasks:
                sample_status = "skipped"
            else:
                sample_status = "completed"
        else:
            sample_status = "pending"

    meta_parts: List[str] = []
    if is_active:
        meta_parts.append(phase)
        if current_task_id:
            meta_parts.append(f"task={current_task_id}")
    elif effective_run_status == "running" and current_sample:
        meta_parts.append(f"active on {current_sample}")
        if phase:
            meta_parts.append(phase)
    elif phase:
        meta_parts.append(phase)

    if total_tasks:
        if finished_count == 0 and task_counts["running"] == 0:
            meta_parts.append("not started")
        else:
            meta_parts.append(f"{finished_count}/{total_tasks} tasks finished")
        if task_counts["failed"]:
            meta_parts.append(f"{task_counts['failed']} failed")

    return {
        "run_id": str(row.get("run_id") or ""),
        "display_label": str(row.get("display_label") or row.get("run_id") or ""),
        "status": sample_status,
        "global_status": str(row.get("status") or "pending"),
        "meta": " • ".join(part for part in meta_parts if part),
        "is_active": is_active,
        "pipeline": str(row.get("pipeline") or ""),
        "architecture": str(row.get("architecture") or ""),
        "variant_id": str(row.get("variant_id") or ""),
        "comparison_baseline_label": str(row.get("comparison_baseline_label") or ""),
    }


def _build_executable_hierarchy(
    manifest: Dict[str, Any],
    runs: List[Dict[str, Any]],
    run_live_statuses: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    selected_samples, selected_task_keys = _resolve_scope_samples_and_tasks(manifest, runs, run_live_statuses)
    task_ids_by_sample: Dict[str, List[str]] = {}
    for key in selected_task_keys:
        sample_name, task_id = _split_sample_task_id(key)
        if not sample_name or not task_id:
            continue
        task_ids = task_ids_by_sample.setdefault(sample_name, [])
        if task_id not in task_ids:
            task_ids.append(task_id)
    if not task_ids_by_sample:
        for live_status in run_live_statuses.values():
            for raw_task in (live_status.get("tasks") or []):
                if not isinstance(raw_task, dict):
                    continue
                sample_name = str(raw_task.get("sample") or "").strip()
                task_id = str(raw_task.get("task_id") or "").strip()
                if not sample_name or not task_id:
                    sample_name, task_id = _split_sample_task_id(str(raw_task.get("sample_task_id") or "").strip())
                if not sample_name or not task_id:
                    continue
                task_ids = task_ids_by_sample.setdefault(sample_name, [])
                if task_id not in task_ids:
                    task_ids.append(task_id)

    executables: List[Dict[str, Any]] = []
    for sample_name in selected_samples:
        run_rows: List[Dict[str, Any]] = []
        status_counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "skipped": 0}
        for row in runs:
            run_row = _summarize_executable_run_row(
                row,
                run_live_statuses.get(str(row.get("run_id") or "").strip(), {}),
                sample_name,
            )
            status_counts[run_row["status"]] = status_counts.get(run_row["status"], 0) + 1
            run_rows.append(run_row)
        total_runs = len(run_rows)
        finished_runs = status_counts["completed"] + status_counts["failed"] + status_counts["skipped"]
        task_count = len(task_ids_by_sample.get(sample_name) or [])
        executables.append(
            {
                "sample": sample_name,
                "status": _rollup_executable_status(status_counts),
                "task_count": task_count,
                "task_summary": (
                    f"{task_count} task(s) in scope" if task_count else "Task scope not yet available"
                ),
                "run_count": total_runs,
                "finished_runs": finished_runs,
                "counts": status_counts,
                "summary": f"{finished_runs}/{total_runs} runs finished" if total_runs else "No runs planned",
                "runs": run_rows,
            }
        )
    return executables


def _sample_dir_for_task(run_dir: Path | None, sample_task_id: str) -> Path | None:
    if run_dir is None:
        return None
    sample_name, task_id = _split_sample_task_id(sample_task_id)
    if not sample_name or not task_id:
        return None
    return run_dir / "samples" / f"{sample_slug(sample_name)}__{task_id}"


def _pick_sample_task_id_for_sample(run_dir: Path | None, live_status: Dict[str, Any], sample_name: str) -> str:
    target_sample = str(sample_name or "").strip()
    if not target_sample:
        return ""
    current_sample = str(live_status.get("current_sample") or "").strip()
    current_task_id = str(live_status.get("current_task_id") or "").strip()
    if current_sample == target_sample and current_task_id:
        return f"{current_sample}::{current_task_id}"

    grouped: Dict[str, List[str]] = {"running": [], "started": [], "pending": []}
    for entry in _task_entries_for_sample(live_status, target_sample):
        task_sample = str(entry.get("sample") or "").strip() or target_sample
        task_id = str(entry.get("task_id") or "").strip()
        sample_task_id = str(entry.get("sample_task_id") or "").strip()
        if not sample_task_id and task_sample and task_id:
            sample_task_id = f"{task_sample}::{task_id}"
        if not sample_task_id:
            continue
        bucket = _classify_task_status(entry.get("status"))
        if bucket == "running":
            grouped["running"].append(sample_task_id)
        elif bucket in {"completed", "failed", "skipped"}:
            grouped["started"].append(sample_task_id)
        else:
            grouped["pending"].append(sample_task_id)
    for key in ("running", "started", "pending"):
        if grouped[key]:
            return grouped[key][0]

    if run_dir is not None and run_dir.exists():
        latest_path: Path | None = None
        latest_mtime = -1.0
        for path in (run_dir / "samples").glob(f"{sample_slug(target_sample)}__*/record.json"):
            try:
                mtime = path.stat().st_mtime
            except Exception:
                continue
            if mtime >= latest_mtime:
                latest_mtime = mtime
                latest_path = path
        if latest_path is not None:
            record = _safe_json(latest_path)
            sample_task_id = str(record.get("sample_task_id") or "").strip()
            if sample_task_id:
                return sample_task_id
    return ""


def _select_sample_task_id(
    run_dir: Path | None,
    live_status: Dict[str, Any],
    requested_sample_task_id: str = "",
    preferred_sample: str = "",
) -> str:
    requested = str(requested_sample_task_id or "").strip()
    preferred = str(preferred_sample or "").strip()
    if requested and (not preferred or _split_sample_task_id(requested)[0] == preferred):
        return requested
    if preferred:
        preferred_match = _pick_sample_task_id_for_sample(run_dir, live_status, preferred)
        if preferred_match:
            return preferred_match
    current_sample = str(live_status.get("current_sample") or "").strip()
    current_task_id = str(live_status.get("current_task_id") or "").strip()
    if current_sample and current_task_id:
        return f"{current_sample}::{current_task_id}"
    if run_dir is not None and run_dir.exists():
        latest_record, _ = _latest_json_by_name(run_dir / "samples", "record.json")
        latest_sample_task_id = str(latest_record.get("sample_task_id") or "").strip()
        if latest_sample_task_id:
            return latest_sample_task_id
    for entry in (live_status.get("tasks") or []):
        sample_task_id = str(entry.get("sample_task_id") or "").strip()
        if sample_task_id:
            return sample_task_id
    return ""


def _build_task_view(live_status: Dict[str, Any], sample_name: str = "") -> Dict[str, Any]:
    target_sample = str(sample_name or "").strip()
    tasks = [
        dict(entry)
        for entry in (live_status.get("tasks") or [])
        if isinstance(entry, dict)
    ]
    if target_sample:
        tasks = _task_entries_for_sample({"tasks": tasks}, target_sample)
    meta = f"{len(tasks)} task(s)"
    if target_sample:
        meta += f" for {target_sample}"
    return {
        "sample": target_sample,
        "tasks": tasks,
        "meta": meta,
    }


def _load_task_artifacts(run_dir: Path | None, sample_task_id: str) -> Dict[str, Any]:
    sample_dir = _sample_dir_for_task(run_dir, sample_task_id)
    if sample_dir is None:
        return {"sample_dir": None, "record": {}, "record_path": None, "agent": {}, "agent_path": None, "judge": {}, "judge_path": None}
    record_path = sample_dir / "record.json"
    agent_path = sample_dir / "agent_result.json"
    judge_path = sample_dir / "judge_result.json"
    return {
        "sample_dir": sample_dir,
        "record": _safe_json(record_path),
        "record_path": record_path if record_path.exists() else None,
        "agent": _safe_json(agent_path),
        "agent_path": agent_path if agent_path.exists() else None,
        "judge": _safe_json(judge_path),
        "judge_path": judge_path if judge_path.exists() else None,
    }


def _selected_task_meta(sample_task_id: str, live_status: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, str]:
    sample_name, task_id = _split_sample_task_id(sample_task_id)
    task_name = str(record.get("task_name") or "").strip()
    for entry in (live_status.get("tasks") or []):
        candidate = str(entry.get("sample_task_id") or "").strip()
        if candidate != sample_task_id:
            continue
        if not sample_name:
            sample_name = str(entry.get("sample") or "").strip()
        if not task_id:
            task_id = str(entry.get("task_id") or "").strip()
        if not task_name:
            task_name = str(entry.get("task_name") or entry.get("task_id") or "").strip()
        break
    if not sample_name:
        sample_name = str(record.get("sample") or "").strip()
    if not task_id:
        task_id = str(record.get("task_id") or "").strip()
    if not task_name:
        task_name = str(record.get("task_name") or task_id).strip()
    return {
        "sample_task_id": str(sample_task_id or "").strip(),
        "sample": sample_name,
        "task_id": task_id,
        "task_name": task_name,
    }


def _summarize_run_output(
    run_dir: Path | None,
    live_status: Dict[str, Any],
    *,
    label: str = "Agent output",
    treat_as_baseline_self: bool = False,
    sample_task_id: str = "",
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

    selected_sample_task_id = _select_sample_task_id(run_dir, live_status, requested_sample_task_id=sample_task_id)
    task_artifacts = _load_task_artifacts(run_dir, selected_sample_task_id)
    record = task_artifacts.get("record") if isinstance(task_artifacts.get("record"), dict) else {}
    agent_payload = task_artifacts.get("agent") if isinstance(task_artifacts.get("agent"), dict) else {}
    record_path = task_artifacts.get("record_path")
    agent_path = task_artifacts.get("agent_path")
    selected_task = _selected_task_meta(selected_sample_task_id, live_status, record)

    if record or agent_payload:
        metrics = record.get("metrics") if isinstance(record.get("metrics"), dict) else {}
        query = str(record.get("task_query") or agent_payload.get("query") or "").strip()
        final_report = str(agent_payload.get("final_report") or "").strip()
        failure_reason = str(metrics.get("failure_reason") or agent_payload.get("failure_reason") or agent_payload.get("error") or "").strip()
        status_log = str(agent_payload.get("status_log") or "").strip()
        lines = []
        if selected_task.get("sample_task_id"):
            lines.append(f"sample_task_id: {selected_task['sample_task_id']}")
        if metrics.get("analysis_status") or agent_payload.get("status"):
            lines.append(f"analysis_status: {str(metrics.get('analysis_status') or agent_payload.get('status') or '').strip()}")
        if query:
            lines.extend(["", "query:", query])
        if final_report:
            lines.extend(["", "agent final output:", final_report])
        if failure_reason:
            lines.extend(["", "failure_reason:", failure_reason])
        if status_log:
            lines.extend(["", "status_log:", status_log])
        text = "\n".join(lines).strip() if lines else _build_pending_output_text(live_status, label=label).strip()
        source_path = agent_path or record_path
        meta_parts = []
        if selected_task.get("task_name"):
            meta_parts.append(selected_task["task_name"])
        if source_path is not None:
            meta_parts.append(source_path.name)
        return {
            "text": text + ("\n" if text and not text.endswith("\n") else ""),
            "meta": " • ".join(meta_parts) if meta_parts else "Agent output",
            "path": str(source_path) if source_path else "",
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


def _select_comparison_baseline_entry(runs: List[Dict[str, Any]], run_entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Function: _select_comparison_baseline_entry
    Inputs:
      - runs: experiment child-run rows as exposed to the live monitor.
      - run_entry: currently selected child-run row.
    Description:
      Resolve the comparison baseline for the selected run. Prefer the configured
      `comparison_baseline_id` and the same replicate index so family baselines
      line up with the selected variant instance.
    Outputs:
      Returns the matching comparison-baseline row, or an empty dictionary when
      no suitable baseline run is available yet.
    Side Effects:
      None.
    """
    if not runs or not run_entry:
        return {}
    if bool(run_entry.get("is_baseline")):
        return run_entry

    comparison_baseline_id = str(run_entry.get("comparison_baseline_id") or "").strip() or "baseline"
    try:
        replicate_index = int(run_entry.get("replicate_index") or 0)
    except Exception:
        replicate_index = 0

    candidates = [
        row for row in runs
        if str(row.get("variant_id") or "").strip() == comparison_baseline_id
    ]
    if replicate_index > 0:
        same_replicate = []
        for row in candidates:
            try:
                row_replicate = int(row.get("replicate_index") or 0)
            except Exception:
                row_replicate = 0
            if row_replicate == replicate_index:
                same_replicate.append(row)
        if same_replicate:
            return same_replicate[0]
    if candidates:
        return candidates[0]

    global_baselines = [row for row in runs if bool(row.get("is_baseline"))]
    if replicate_index > 0:
        same_replicate = []
        for row in global_baselines:
            try:
                row_replicate = int(row.get("replicate_index") or 0)
            except Exception:
                row_replicate = 0
            if row_replicate == replicate_index:
                same_replicate.append(row)
        if same_replicate:
            return same_replicate[0]
    return global_baselines[0] if global_baselines else {}


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
    run_terminal = run_status in {"completed", "completed_budget_exceeded", "budget_exceeded"}
    budget_terminal = run_status == "budget_exceeded" or live_stage == "budget_exceeded"

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
    elif live_stage in {"aggregate", "budget_aborted", "budget_limit_reached"}:
        current_key = "aggregate"
    elif live_stage in {"completed", "budget_exceeded"} or run_terminal:
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

    if live_stage in {"judge", "aggregate", "budget_aborted", "budget_limit_reached", "completed", "budget_exceeded"} or run_terminal:
        for name in configured_agent_stages:
            stage_index = key_to_index.get(f"agent:{name}")
            if stage_index is not None:
                stages[stage_index]["status"] = "completed"
                stages[stage_index]["state_text"] = "Completed"
    if live_stage in {"aggregate", "budget_aborted", "budget_limit_reached", "completed", "budget_exceeded"} or run_terminal:
        judge_index = key_to_index.get("judge")
        if judge_index is not None:
            stages[judge_index]["status"] = "completed"
            stages[judge_index]["state_text"] = "Completed"
    if live_stage in {"completed", "budget_exceeded"} or run_terminal:
        aggregate_index = key_to_index.get("aggregate")
        completed_index = key_to_index.get("completed")
        if aggregate_index is not None:
            stages[aggregate_index]["status"] = "completed"
            stages[aggregate_index]["state_text"] = "Completed"
        if completed_index is not None:
            stages[completed_index]["status"] = "completed"
            stages[completed_index]["state_text"] = "Budget exceeded" if budget_terminal else "Completed"

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
    if not current_label and run_status == "completed_budget_exceeded":
        current_label = "Completed (budget exceeded)"
    if not current_label and budget_terminal:
        current_label = "Budget exceeded"
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

def _summarize_judge_payload(judge_payload: Dict[str, Any], judge_path: Path | None, sample_task_id: str = "") -> Dict[str, Any]:
    if not judge_payload:
        return {"text": "Judge output not available yet.", "path": ""}
    lines = []
    if sample_task_id:
        lines.append(f"sample_task_id: {sample_task_id}")
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


def _summarize_judge(run_dir: Path, sample_task_id: str = "") -> Dict[str, Any]:
    task_artifacts = _load_task_artifacts(run_dir, sample_task_id)
    judge_payload = task_artifacts.get("judge") if isinstance(task_artifacts.get("judge"), dict) else {}
    judge_path = task_artifacts.get("judge_path")
    if judge_payload:
        return _summarize_judge_payload(judge_payload, judge_path, sample_task_id=sample_task_id)
    judge_payload, judge_path = _latest_json_by_name(run_dir / "samples", "judge_result.json")
    return _summarize_judge_payload(judge_payload, judge_path, sample_task_id=sample_task_id)


def _build_executable_overview(
    experiment_root: Path,
    state: Dict[str, Any],
    run_entry: Dict[str, Any],
    sample_task_id: str = "",
) -> Dict[str, Any]:
    focus_sample = _split_sample_task_id(sample_task_id)[0] or str(run_entry.get("current_sample") or "").strip()
    cards: List[Dict[str, Any]] = []
    for entry in (state.get("executables") or []):
        if not isinstance(entry, dict):
            continue
        card = dict(entry)
        card["is_focus"] = bool(focus_sample) and str(card.get("sample") or "") == focus_sample
        card["meta"] = card.get("summary") or ""
        card["runs"] = [
            {
                **dict(run_row),
                "is_selected": str(run_row.get("run_id") or "") == str(run_entry.get("run_id") or ""),
            }
            for run_row in (card.get("runs") or [])
            if isinstance(run_row, dict)
        ]
        cards.append(card)
    meta = (
        "Grouped by executable. Row status is executable-scoped, so a run can be active elsewhere while still pending here."
    )
    if focus_sample:
        meta = (
            f"Focused executable: {focus_sample}. "
            "Row status is executable-scoped, not the run's global status."
        )
    return {"focus_sample": focus_sample, "cards": cards, "meta": meta}


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
    run_live_statuses: Dict[str, Dict[str, Any]] = {}
    counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "skipped": 0}
    for raw_entry in (catalog.get("runs") or []):
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        run_id = str(entry.get("run_id") or "").strip()
        run_dir = Path(str(entry.get("run_dir") or "")).expanduser() if entry.get("run_dir") else None
        live_status = _safe_json(run_dir / "live_status.json") if run_dir and run_dir.exists() else {}
        run_live_statuses[run_id] = live_status
        if live_status:
            entry["stage"] = str(live_status.get("stage") or entry.get("stage") or "")
            entry["current_phase"] = str(live_status.get("current_phase") or entry.get("current_phase") or "")
            entry["current_sample"] = str(live_status.get("current_sample") or entry.get("current_sample") or "")
            entry["current_task_id"] = str(live_status.get("current_task_id") or entry.get("current_task_id") or "")
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
        "executables": _build_executable_hierarchy(manifest, runs, run_live_statuses),
    }


def load_live_view_detail(
    experiment_root: Path,
    run_id: str,
    sample_task_id: str = "",
    sample_name: str = "",
) -> Dict[str, Any]:
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
    baseline_entry = _select_comparison_baseline_entry(state.get("runs") or [], run_entry)
    run_dir = Path(str(run_entry.get("run_dir") or "")).expanduser() if run_entry.get("run_dir") else None
    baseline_dir = Path(str(baseline_entry.get("run_dir") or "")).expanduser() if baseline_entry.get("run_dir") else None
    log_path = Path(str(run_entry.get("log_path") or "")).expanduser() if run_entry.get("log_path") else None
    live_status = _safe_json(run_dir / "live_status.json") if run_dir and run_dir.exists() else {}
    run_manifest = _safe_json(run_dir / "run_manifest.json") if run_dir and run_dir.exists() else {}
    run_log = _safe_text(log_path) if log_path else ""
    baseline_is_self = bool(run_entry) and bool(baseline_entry) and str(run_entry.get("run_id") or "") == str(baseline_entry.get("run_id") or "")
    baseline_live_status = _safe_json(baseline_dir / "live_status.json") if baseline_dir and baseline_dir.exists() else {}
    focused_sample = str(sample_name or "").strip() or _split_sample_task_id(sample_task_id)[0] or str(run_entry.get("current_sample") or "").strip()
    selected_sample_task_id = _select_sample_task_id(
        run_dir,
        live_status,
        requested_sample_task_id=sample_task_id,
        preferred_sample=focused_sample,
    )
    selected_task_artifacts = _load_task_artifacts(run_dir, selected_sample_task_id)
    selected_task_record = selected_task_artifacts.get("record") if isinstance(selected_task_artifacts.get("record"), dict) else {}
    selected_task = _selected_task_meta(selected_sample_task_id, live_status, selected_task_record)
    focused_sample = str(selected_task.get("sample") or focused_sample or "").strip()
    return {
        "run_id": str(run_entry.get("run_id") or ""),
        "run_log": run_log,
        "live_status": live_status,
        "run_manifest": run_manifest,
        "focused_sample": focused_sample,
        "selected_task": selected_task,
        "task_view": _build_task_view(live_status, focused_sample),
        "run_output": _summarize_run_output(
            run_dir,
            live_status,
            label="Agent output",
            sample_task_id=selected_sample_task_id,
        ),
        "baseline_output": _summarize_run_output(
            baseline_dir,
            baseline_live_status,
            label="Baseline output",
            treat_as_baseline_self=baseline_is_self,
            sample_task_id=selected_sample_task_id,
        ),
        "comparison_baseline": {
            "display_label": str(baseline_entry.get("display_label") or ""),
            "run_id": str(baseline_entry.get("run_id") or ""),
            "is_self": baseline_is_self,
            "current_sample": str(baseline_live_status.get("current_sample") or ""),
            "current_task_id": str(baseline_live_status.get("current_task_id") or ""),
        },
        "judge_summary": (
            _summarize_judge(run_dir, sample_task_id=selected_sample_task_id)
            if run_dir and run_dir.exists()
            else {"text": "Judge output not available yet.", "path": ""}
        ),
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
            sample_task_id = str((params.get("sample_task_id") or [""])[0] or "")
            sample_name = str((params.get("sample") or [""])[0] or "")
            self._send_json(
                load_live_view_detail(
                    self.experiment_root,
                    run_id,
                    sample_task_id=sample_task_id,
                    sample_name=sample_name,
                )
            )
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
