"""
File: results_browser.py
Author: Matt-Ung
Last Updated: 2026-04-02
Purpose:
  Serve a browser-oriented viewer for completed or in-progress experiment runs.

Summary:
  This module reuses the live monitor's executable/run/detail loaders so past
  and current experiment directories can be browsed through the same mental
  model. It adds an experiment selector, a lightweight artifact server for
  charts and generated HTML pages, and a bottom visual gallery to support
  post-run analysis.
"""

from __future__ import annotations

import json
import mimetypes
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .live_progress import load_live_view_detail, load_live_view_state
from .paths import RESULTS_ROOT, ensure_dir, read_json


_BROWSER_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Testing Results Browser</title>
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
    .toolbar {
      margin-top: 18px;
      display: flex;
      flex-wrap: wrap;
      gap: 14px;
      align-items: end;
    }
    .selector {
      display: flex;
      flex-direction: column;
      gap: 6px;
      min-width: min(520px, 100%);
    }
    .selector span {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: rgba(248, 251, 255, 0.74);
    }
    .selector select {
      appearance: none;
      border: 1px solid rgba(255, 255, 255, 0.22);
      border-radius: 14px;
      background: rgba(9, 17, 31, 0.18);
      color: #f8fbff;
      font-size: 14px;
      padding: 12px 14px;
    }
    .toolbar-meta {
      color: rgba(248, 251, 255, 0.82);
      font-size: 13px;
      line-height: 1.5;
      max-width: 680px;
    }
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
      min-height: 780px;
    }
    .queue-panel .panel-body,
    .runs-panel .panel-body,
    .detail-panel .panel-body { flex: 1 1 auto; }
    .queue-panel .panel-body,
    .runs-panel .panel-body {
      display: flex;
      flex-direction: column;
      gap: 12px;
      max-height: calc(100vh - 290px);
      overflow: auto;
    }
    .detail-panel .panel-body {
      display: flex;
      flex-direction: column;
      gap: 18px;
      max-height: calc(100vh - 290px);
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
    .visual-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
      padding: 16px;
    }
    .visual-card {
      border: 1px solid var(--line);
      border-radius: 18px;
      overflow: hidden;
      background: rgba(255,255,255,0.98);
    }
    .visual-card img {
      display: block;
      width: 100%;
      height: 220px;
      object-fit: contain;
      background: #f8fbff;
      border-bottom: 1px solid var(--line);
    }
    .visual-card-body {
      padding: 12px 14px;
    }
    .visual-card-title {
      font-weight: 700;
      line-height: 1.35;
      margin-bottom: 6px;
    }
    .visual-card-copy {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    .link-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      padding: 0 16px 16px;
    }
    .link-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 10px;
      border-radius: 999px;
      background: rgba(36, 89, 209, 0.08);
      color: var(--run);
      text-decoration: none;
      font-size: 12px;
      font-weight: 700;
    }
    .muted { color: var(--muted); }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: rgba(15, 23, 42, 0.06);
      padding: 1px 6px;
      border-radius: 999px;
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
      .visual-grid { grid-template-columns: 1fr; }
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
        <div class="eyebrow">Results Browser</div>
        <h1>Testing Analysis View</h1>
        <p id="subtitle">Loading…</p>
        <div class="toolbar">
          <label class="selector">
            <span>Experiment</span>
            <select id="experiment-select"></select>
          </label>
          <div class="toolbar-meta" id="experiment-meta">Select an experiment sweep to browse its executable hierarchy and comparison outputs.</div>
        </div>
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

          <div class="surface visuals-panel">
            <div class="title">
              <h3>Visuals</h3>
              <div class="sub" id="visuals-meta">Charts and sample-specific comparison pages for the selected experiment.</div>
            </div>
            <div class="link-row" id="visual-links"></div>
            <div class="visual-grid" id="visual-grid"></div>
          </div>
        </div>
      </section>
    </div>
  </div>

  <script>
    const params = new URLSearchParams(window.location.search);
    let selectedExperimentId = params.get("experiment") || "";
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
      if (selectedExperimentId) next.searchParams.set("experiment", selectedExperimentId);
      else next.searchParams.delete("experiment");
      if (selectedExecutable) next.searchParams.set("sample", selectedExecutable);
      else next.searchParams.delete("sample");
      if (selectedRunId) next.searchParams.set("run_id", selectedRunId);
      else next.searchParams.delete("run_id");
      if (selectedSampleTaskId) next.searchParams.set("sample_task_id", selectedSampleTaskId);
      else next.searchParams.delete("sample_task_id");
      window.history.replaceState({}, "", next);
    }

    function renderCountChip(label, count, status) {
      if (!count) return "";
      return `<span class="count-chip ${statusClass(status)}"><strong>${escapeHtml(count)}</strong>${escapeHtml(label)}</span>`;
    }

    function normalizeExperimentSelection(catalog) {
      const experiments = catalog.experiments || [];
      if (!experiments.length) {
        selectedExperimentId = "";
        selectedExecutable = "";
        selectedRunId = "";
        selectedSampleTaskId = "";
        updateUrl();
        return null;
      }
      if (!selectedExperimentId || !experiments.some((entry) => entry.experiment_id === selectedExperimentId)) {
        selectedExperimentId = (experiments[0] || {}).experiment_id || "";
        selectedExecutable = "";
        selectedRunId = "";
        selectedSampleTaskId = "";
      }
      updateUrl();
      return experiments.find((entry) => entry.experiment_id === selectedExperimentId) || experiments[0];
    }

    function renderExperimentPicker(catalog) {
      const experiments = catalog.experiments || [];
      const select = document.getElementById("experiment-select");
      if (!experiments.length) {
        select.innerHTML = `<option value="">No experiments found</option>`;
        document.getElementById("experiment-meta").textContent = "Run a sweep first, or point the browser at a populated results root.";
        return;
      }
      select.innerHTML = experiments.map((entry) => `
        <option value="${escapeAttr(entry.experiment_id || "")}" ${entry.experiment_id === selectedExperimentId ? "selected" : ""}>
          ${escapeHtml(entry.experiment_id || "")}
        </option>
      `).join("");
      const current = experiments.find((entry) => entry.experiment_id === selectedExperimentId) || experiments[0];
      const metaParts = [
        current.corpus ? `${current.corpus} corpus` : "",
        current.run_count ? `${current.run_count} run(s)` : "",
        current.has_visuals ? `${current.visual_count || 0} chart(s)` : "no charts yet",
      ].filter(Boolean);
      document.getElementById("experiment-meta").textContent = metaParts.join(" • ");
      select.onchange = () => {
        const nextExperiment = select.value || "";
        if (!nextExperiment || nextExperiment === selectedExperimentId) return;
        selectedExperimentId = nextExperiment;
        selectedExecutable = "";
        selectedRunId = "";
        selectedSampleTaskId = "";
        refresh();
      };
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

    function renderSummary(catalogEntry, state) {
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
      const subtitleParts = [
        `${state.corpus || ""} corpus`,
        `${summary.completed || 0}/${summary.total_runs || 0} child runs finished`,
        `${executableCount} executable(s)`,
      ];
      if (catalogEntry && catalogEntry.has_visuals) {
        subtitleParts.push(`${catalogEntry.visual_count || 0} chart(s) available`);
      }
      document.getElementById("subtitle").textContent = subtitleParts.join(" • ");
    }

    function renderExecutableQueue(state) {
      const executables = state.executables || [];
      document.getElementById("executables-meta").textContent =
        executables.length
          ? `${executables.length} executable(s) planned. Select one to inspect its run sequence.`
          : "Executable scope is not available yet.";
      if (!executables.length) {
        document.getElementById("executable-rows").innerHTML = `<div class="column-empty">No executable scope is available for this experiment yet.</div>`;
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
        ].filter(Boolean).join("") || `<span class="count-chip"><strong>0</strong>signals</span>`;
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

    function renderVisuals(detail) {
      const gallery = (detail || {}).visual_gallery || {};
      const images = gallery.images || [];
      const taskPages = gallery.task_pages || [];
      document.getElementById("visuals-meta").textContent =
        gallery.meta || "Charts and sample-specific comparison pages for the selected experiment.";
      document.getElementById("visual-links").innerHTML = taskPages.map((entry) => `
        <a class="link-chip" href="${escapeAttr(entry.url || "#")}" target="_blank" rel="noreferrer">
          ${escapeHtml(entry.task_name || entry.sample_task_id || "task comparison")}
        </a>
      `).join("");
      if (!images.length) {
        document.getElementById("visual-grid").innerHTML = `<div class="column-empty">No chart images were found for this experiment yet.</div>`;
        return;
      }
      document.getElementById("visual-grid").innerHTML = images.map((entry) => `
        <a class="visual-card" href="${escapeAttr(entry.url || "#")}" target="_blank" rel="noreferrer">
          <img src="${escapeAttr(entry.url || "")}" alt="${escapeAttr(entry.title || entry.filename || "chart")}" loading="lazy">
          <div class="visual-card-body">
            <div class="visual-card-title">${escapeHtml(entry.title || entry.filename || "Chart")}</div>
            <div class="visual-card-copy">${escapeHtml(entry.description || entry.filename || "")}</div>
          </div>
        </a>
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
        document.getElementById("visuals-meta").textContent = "";
        document.getElementById("visual-links").innerHTML = "";
        document.getElementById("visual-grid").innerHTML = "";
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
      renderVisuals(detail);
    }

    async function refresh() {
      try {
        const catalog = await loadJson("/api/catalog");
        const catalogEntry = normalizeExperimentSelection(catalog);
        renderExperimentPicker(catalog);
        if (!selectedExperimentId) {
          document.getElementById("subtitle").textContent = "No experiment runs were found under Testing/results/experiments.";
          renderSummary({}, { summary: {} });
          renderExecutableQueue({ executables: [] });
          renderRunList({ executables: [] });
          renderDetail({ runs: [] }, null);
          return;
        }
        const state = await loadJson(`/api/state?experiment_id=${encodeURIComponent(selectedExperimentId)}`);
        normalizeSelection(state);
        renderSummary(catalogEntry, state);
        renderExecutableQueue(state);
        renderRunList(state);
        if (selectedRunId) {
          const sampleParam = selectedExecutable ? `&sample=${encodeURIComponent(selectedExecutable)}` : "";
          const sampleTaskParam = selectedSampleTaskId ? `&sample_task_id=${encodeURIComponent(selectedSampleTaskId)}` : "";
          const detail = await loadJson(`/api/detail?experiment_id=${encodeURIComponent(selectedExperimentId)}&run_id=${encodeURIComponent(selectedRunId)}${sampleParam}${sampleTaskParam}`);
          renderDetail(state, detail);
        } else {
          renderDetail(state, null);
        }
      } catch (error) {
        document.getElementById("subtitle").textContent = `Results browser error: ${error}`;
      }
    }

    refresh();
    setInterval(refresh, 2500);
  </script>
</body>
</html>
"""


def _safe_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return read_json(path)
    except Exception:
        return {}


def _experiments_root(results_root: Path) -> Path:
    return results_root / "experiments"


def _list_experiment_roots(results_root: Path) -> List[Path]:
    root = _experiments_root(results_root)
    if not root.exists():
        return []
    candidates = [path for path in root.iterdir() if path.is_dir()]
    return sorted(
        candidates,
        key=lambda path: (
            path.stat().st_mtime if path.exists() else 0.0,
            path.name,
        ),
        reverse=True,
    )


def _resolve_experiment_root(results_root: Path, experiment_id: str) -> Path | None:
    text = str(experiment_id or "").strip()
    if not text:
        roots = _list_experiment_roots(results_root)
        return roots[0] if roots else None
    candidate = (_experiments_root(results_root) / text).resolve()
    base = _experiments_root(results_root).resolve()
    if not str(candidate).startswith(str(base)) or not candidate.exists() or not candidate.is_dir():
        return None
    return candidate


def _safe_stat_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except Exception:
        return 0.0


def _normalize_artifact_path(experiment_root: Path, path_text: str) -> Path | None:
    text = str(path_text or "").strip()
    if not text:
        return None
    candidate = Path(text)
    options: List[Path] = []
    if candidate.is_absolute():
        options.append(candidate)
    else:
        options.append((experiment_root / candidate).resolve())
        options.append((Path.cwd() / candidate).resolve())
        options.append((experiment_root / "outputs" / candidate.name).resolve())
    base = experiment_root.resolve()
    for option in options:
        try:
            resolved = option.resolve()
        except Exception:
            continue
        if resolved.exists() and str(resolved).startswith(str(base)):
            return resolved
    return None


def _artifact_url(experiment_id: str, relative_path: Path) -> str:
    return "/artifact?" + urllib.parse.urlencode(
        {
            "experiment_id": experiment_id,
            "path": str(relative_path.as_posix()),
        }
    )


def _sample_tokens(sample_name: str) -> List[str]:
    text = str(sample_name or "").strip().lower()
    if not text:
        return []
    tokens = [text]
    stem = Path(text).stem
    if stem and stem not in tokens:
        tokens.append(stem)
    return tokens


def _match_score(sample_name: str, haystack: str) -> int:
    lower = str(haystack or "").lower()
    for token in _sample_tokens(sample_name):
        if token and token in lower:
            return 2
    return 0


def _build_visual_gallery_payload(experiment_root: Path, sample_name: str = "") -> Dict[str, Any]:
    experiment_id = experiment_root.name
    outputs_root = experiment_root / "outputs"
    chart_manifest = _safe_json(outputs_root / "chart_manifest.json")
    image_entries: List[Dict[str, Any]] = []
    created_files = chart_manifest.get("created_files") if isinstance(chart_manifest.get("created_files"), list) else []

    if created_files:
        for raw_entry in created_files:
            if not isinstance(raw_entry, dict):
                continue
            artifact_path = _normalize_artifact_path(experiment_root, str(raw_entry.get("path") or ""))
            if artifact_path is None:
                continue
            relative_path = artifact_path.relative_to(experiment_root)
            title = str(raw_entry.get("title") or artifact_path.stem.replace("_", " ").title()).strip()
            description = str(raw_entry.get("description") or "").strip()
            relevance = _match_score(sample_name, f"{artifact_path.name} {title} {description}")
            image_entries.append(
                {
                    "filename": artifact_path.name,
                    "title": title,
                    "description": description,
                    "relevance": relevance,
                    "url": _artifact_url(experiment_id, relative_path),
                }
            )
    elif outputs_root.exists():
        for artifact_path in sorted(outputs_root.rglob("*")):
            if artifact_path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".svg"}:
                continue
            if not artifact_path.is_file():
                continue
            relative_path = artifact_path.relative_to(experiment_root)
            image_entries.append(
                {
                    "filename": artifact_path.name,
                    "title": artifact_path.stem.replace("_", " ").title(),
                    "description": str(relative_path.parent),
                    "relevance": _match_score(sample_name, str(relative_path)),
                    "url": _artifact_url(experiment_id, relative_path),
                }
            )

    sample_specific = [entry for entry in image_entries if int(entry.get("relevance") or 0) > 0]
    if sample_name and sample_specific:
        image_entries = sample_specific + [entry for entry in image_entries if int(entry.get("relevance") or 0) == 0][:4]

    task_pages: List[Dict[str, str]] = []
    comparison_manifest = _safe_json(outputs_root / "task_output_comparisons" / "comparison_manifest.json")
    tasks_payload = comparison_manifest.get("tasks") if isinstance(comparison_manifest.get("tasks"), dict) else {}
    for sample_task_id, raw_entry in sorted(tasks_payload.items()):
        if not isinstance(raw_entry, dict):
            continue
        sample = str(raw_entry.get("sample") or "").strip()
        if sample_name and sample != sample_name and not str(sample_task_id).startswith(f"{sample_name}::"):
            continue
        page_path = str(raw_entry.get("page") or "").strip()
        if not page_path:
            continue
        relative_path = Path("outputs") / "task_output_comparisons" / page_path
        task_pages.append(
            {
                "sample_task_id": str(sample_task_id),
                "task_name": str(raw_entry.get("task_name") or raw_entry.get("task_id") or sample_task_id),
                "url": _artifact_url(experiment_id, relative_path),
            }
        )

    meta = "Experiment-level visuals."
    if sample_name and sample_specific:
        meta = f"Showing {len(sample_specific)} sample-matched chart(s) for {sample_name}, plus experiment-level context."
    elif sample_name:
        meta = f"No sample-specific chart filenames matched {sample_name}; showing experiment-level visuals."
    return {
        "sample": str(sample_name or "").strip(),
        "meta": meta,
        "images": image_entries[:8],
        "task_pages": task_pages[:10],
    }


def load_results_browser_catalog(results_root: Path = RESULTS_ROOT) -> Dict[str, Any]:
    experiments: List[Dict[str, Any]] = []
    for experiment_root in _list_experiment_roots(results_root):
        manifest = _safe_json(experiment_root / "experiment_manifest.json")
        state = load_live_view_state(experiment_root) if (experiment_root / "run_catalog.json").exists() else {"summary": {"total_runs": 0}}
        outputs_root = experiment_root / "outputs"
        chart_manifest = _safe_json(outputs_root / "chart_manifest.json")
        visual_count = 0
        if isinstance(chart_manifest.get("created_files"), list):
            visual_count = len(chart_manifest.get("created_files") or [])
        elif outputs_root.exists():
            visual_count = len(
                [
                    path
                    for path in outputs_root.rglob("*")
                    if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".svg"}
                ]
            )
        experiments.append(
            {
                "experiment_id": experiment_root.name,
                "corpus": str(manifest.get("corpus") or ""),
                "run_count": int(((state.get("summary") or {}).get("total_runs") or 0)),
                "updated_at_epoch": max(
                    _safe_stat_mtime(experiment_root / "run_catalog.json"),
                    _safe_stat_mtime(experiment_root / "report.md"),
                    _safe_stat_mtime(experiment_root),
                ),
                "has_visuals": visual_count > 0,
                "visual_count": visual_count,
                "path": str(experiment_root),
            }
        )
    return {
        "results_root": str(results_root),
        "experiments": experiments,
    }


def load_results_browser_state(results_root: Path, experiment_id: str) -> Dict[str, Any]:
    experiment_root = _resolve_experiment_root(results_root, experiment_id)
    if experiment_root is None:
        return {"summary": {"total_runs": 0}, "runs": [], "executables": []}
    return load_live_view_state(experiment_root)


def load_results_browser_detail(
    results_root: Path,
    experiment_id: str,
    run_id: str,
    *,
    sample_name: str = "",
    sample_task_id: str = "",
) -> Dict[str, Any]:
    experiment_root = _resolve_experiment_root(results_root, experiment_id)
    if experiment_root is None:
        return {}
    detail = load_live_view_detail(
        experiment_root,
        run_id,
        sample_task_id=sample_task_id,
        sample_name=sample_name,
    )
    detail["experiment_id"] = experiment_root.name
    detail["visual_gallery"] = _build_visual_gallery_payload(
        experiment_root,
        sample_name=str(detail.get("focused_sample") or sample_name or "").strip(),
    )
    return detail


class _ResultsBrowserHandler(BaseHTTPRequestHandler):
    results_root: Path
    browser_dir: Path

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, *, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, *, content_type: str = "text/html; charset=utf-8", status: int = 200) -> None:
        self._send_bytes(text.encode("utf-8"), content_type=content_type, status=status)

    def _send_artifact(self, experiment_id: str, relative_path: str) -> None:
        experiment_root = _resolve_experiment_root(self.results_root, experiment_id)
        if experiment_root is None:
            self._send_text("Unknown experiment\n", content_type="text/plain; charset=utf-8", status=404)
            return
        artifact_path = (experiment_root / str(relative_path or "").lstrip("/")).resolve()
        if not str(artifact_path).startswith(str(experiment_root.resolve())) or not artifact_path.exists() or not artifact_path.is_file():
            self._send_text("Artifact not found\n", content_type="text/plain; charset=utf-8", status=404)
            return
        content_type = mimetypes.guess_type(str(artifact_path))[0] or "application/octet-stream"
        self._send_bytes(artifact_path.read_bytes(), content_type=content_type, status=200)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._send_text(_BROWSER_HTML)
            return
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/api/catalog":
            self._send_json(load_results_browser_catalog(self.results_root))
            return
        if parsed.path == "/api/state":
            experiment_id = str((params.get("experiment_id") or [""])[0] or "")
            self._send_json(load_results_browser_state(self.results_root, experiment_id))
            return
        if parsed.path == "/api/detail":
            experiment_id = str((params.get("experiment_id") or [""])[0] or "")
            run_id = str((params.get("run_id") or [""])[0] or "")
            sample_task_id = str((params.get("sample_task_id") or [""])[0] or "")
            sample_name = str((params.get("sample") or [""])[0] or "")
            self._send_json(
                load_results_browser_detail(
                    self.results_root,
                    experiment_id,
                    run_id,
                    sample_name=sample_name,
                    sample_task_id=sample_task_id,
                )
            )
            return
        if parsed.path == "/artifact":
            experiment_id = str((params.get("experiment_id") or [""])[0] or "")
            relative_path = str((params.get("path") or [""])[0] or "")
            self._send_artifact(experiment_id, relative_path)
            return
        self._send_text("Not found\n", content_type="text/plain; charset=utf-8", status=404)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        return


def start_results_browser_server(
    results_root: Path = RESULTS_ROOT,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> Tuple[ThreadingHTTPServer, threading.Thread, str]:
    browser_dir = ensure_dir(results_root / "browser")
    (browser_dir / "index.html").write_text(_BROWSER_HTML, encoding="utf-8")
    handler = type(
        "TestingResultsBrowserHandler",
        (_ResultsBrowserHandler,),
        {"results_root": results_root, "browser_dir": browser_dir},
    )
    server = ThreadingHTTPServer((host, int(port)), handler)
    thread = threading.Thread(target=server.serve_forever, name="testing-results-browser", daemon=True)
    thread.start()
    url = f"http://{server.server_address[0]}:{server.server_address[1]}/"
    (browser_dir / "results_browser_url.txt").write_text(url + "\n", encoding="utf-8")
    return server, thread, url
