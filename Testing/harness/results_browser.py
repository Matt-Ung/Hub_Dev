"""
File: results_browser.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Serve a browser-oriented viewer for completed or in-progress experiment runs.

Summary:
  This module serves the active results browser for the current canonical
  experiment layout under `Testing/results/experiments/`. Legacy archived
  experiment trees are handled by the dedicated archive browser instead.
"""

from __future__ import annotations

import csv
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
    .wrap { padding: 24px; max-width: 1760px; margin: 0 auto; display: flex; flex-direction: column; }
    .topbar {
      order: 0;
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
    .analysis-panel {
      order: 1;
      margin-bottom: 18px;
    }
    .workspace {
      order: 2;
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
    .panel-head-row {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }
    .panel-toggle {
      appearance: none;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.94);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      padding: 8px 12px;
      cursor: pointer;
      white-space: nowrap;
    }
    .panel-toggle:hover {
      border-color: var(--line-strong);
      color: var(--ink);
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
      min-height: 0;
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
      overscroll-behavior: contain;
    }
    .detail-panel .panel-body {
      display: flex;
      flex-direction: column;
      gap: 18px;
      max-height: none;
      overflow: visible;
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
    .analysis-stack {
      display: flex;
      flex-direction: column;
      gap: 18px;
    }
    .analysis-summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
    }
    .analysis-card {
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 14px 16px;
      background: rgba(255,255,255,0.94);
    }
    .analysis-card .label {
      font-size: 11px;
      color: var(--muted-soft);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .analysis-card .value {
      font-size: 18px;
      font-weight: 800;
      letter-spacing: -0.02em;
      line-height: 1.25;
    }
    .analysis-card .subvalue {
      margin-top: 8px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }
    .analysis-meta {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }
    .analysis-meta strong {
      color: var(--ink);
    }
    .analysis-section > details {
      display: block;
    }
    .analysis-section summary.title {
      list-style: none;
      cursor: pointer;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }
    .analysis-section summary.title::-webkit-details-marker {
      display: none;
    }
    .analysis-section .collapse-indicator::before {
      content: "▸";
      font-size: 12px;
      transition: transform 160ms ease;
    }
    .analysis-section details[open] .collapse-indicator::before {
      transform: rotate(90deg);
    }
    .notice-banner {
      border: 1px solid rgba(180, 35, 24, 0.18);
      border-radius: 18px;
      padding: 14px 16px;
      background: rgba(251, 226, 223, 0.82);
      color: var(--fail);
      line-height: 1.6;
    }
    .notice-banner strong {
      display: block;
      margin-bottom: 4px;
      color: #7a271a;
    }
    .fallback-chart-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 14px;
    }
    .fallback-chart {
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255,255,255,0.96);
      padding: 14px 16px 16px;
    }
    .fallback-chart h4 {
      margin: 0 0 6px;
      font-size: 14px;
      letter-spacing: -0.01em;
    }
    .fallback-chart .sub {
      margin: 0 0 14px;
      font-size: 12px;
      color: var(--muted);
    }
    .bar-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .bar-row {
      display: grid;
      grid-template-columns: minmax(120px, 1.1fr) minmax(0, 2.2fr) auto;
      gap: 10px;
      align-items: center;
      min-width: 0;
    }
    .bar-label {
      font-size: 12px;
      line-height: 1.4;
      color: var(--ink);
      overflow-wrap: anywhere;
    }
    .bar-value {
      font-size: 12px;
      font-weight: 700;
      color: var(--muted);
      white-space: nowrap;
    }
    .bar-track {
      position: relative;
      height: 12px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.08);
      overflow: hidden;
    }
    .bar-fill {
      position: absolute;
      inset: 0 auto 0 0;
      border-radius: 999px;
      background: linear-gradient(90deg, rgba(36, 89, 209, 0.96), rgba(82, 139, 255, 0.96));
    }
    .bar-fill.success {
      background: linear-gradient(90deg, rgba(21, 127, 94, 0.96), rgba(58, 186, 131, 0.92));
    }
    .bar-fill.variance {
      background: linear-gradient(90deg, rgba(154, 100, 18, 0.96), rgba(224, 166, 54, 0.92));
    }
    .delta-track {
      display: grid;
      grid-template-columns: 1fr 2px 1fr;
      align-items: center;
      height: 12px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.04);
      overflow: hidden;
    }
    .delta-axis {
      height: 100%;
      background: rgba(15, 23, 42, 0.16);
    }
    .delta-fill-neg,
    .delta-fill-pos {
      height: 100%;
    }
    .delta-fill-neg {
      justify-self: end;
      border-radius: 999px 0 0 999px;
      background: linear-gradient(90deg, rgba(180, 35, 24, 0.92), rgba(232, 99, 84, 0.92));
    }
    .delta-fill-pos {
      justify-self: start;
      border-radius: 0 999px 999px 0;
      background: linear-gradient(90deg, rgba(21, 127, 94, 0.96), rgba(58, 186, 131, 0.92));
    }
    .queue-card,
    .run-card {
      flex: 0 0 auto;
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
    .run-top > div {
      min-width: 0;
      flex: 1 1 auto;
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
      overflow-wrap: normal;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
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
    .run-link {
      min-height: 92px;
      box-sizing: border-box;
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
    .surface.collapsible {
      overflow: hidden;
    }
    .surface.collapsible > details {
      display: block;
    }
    .surface.collapsible > details[open] {
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
    .surface .title h3 {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted-soft);
      margin-bottom: 6px;
    }
    .surface .title .sub { margin-top: 0; }
    details > summary.title {
      list-style: none;
      cursor: pointer;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
    }
    details > summary.title::-webkit-details-marker {
      display: none;
    }
    .collapse-copy {
      min-width: 0;
      flex: 1 1 auto;
    }
    .collapse-indicator {
      flex: 0 0 auto;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }
    details > summary.title .collapse-indicator::before {
      content: "▸";
      font-size: 12px;
      transition: transform 160ms ease;
    }
    details[open] > summary.title .collapse-indicator::before {
      transform: rotate(90deg);
    }
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
      min-height: 220px;
      max-height: none;
      flex: 0 0 auto;
    }
    .logs-panel pre {
      max-height: none;
      min-height: 180px;
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
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 18px;
      padding: 16px;
      align-items: start;
    }
    .visual-card {
      border: 1px solid var(--line);
      border-radius: 20px;
      overflow: hidden;
      background: rgba(255,255,255,0.98);
      box-shadow: 0 14px 30px rgba(15, 23, 42, 0.06);
    }
    .visual-card img {
      display: block;
      width: 100%;
      height: 300px;
      object-fit: contain;
      background: linear-gradient(180deg, #fbfdff 0%, #f4f8fd 100%);
      border-bottom: 1px solid var(--line);
      padding: 16px;
    }
    .visual-card-body {
      padding: 14px 16px 16px;
    }
    .visual-card-title {
      font-weight: 700;
      line-height: 1.4;
      margin-bottom: 8px;
    }
    .visual-card-copy {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
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
    .table-wrap {
      padding: 0 16px 16px;
      overflow: auto;
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

    <section class="panel analysis-panel">
      <div class="panel-head">
        <div class="kicker">Experiment Analysis</div>
        <h2>Aggregate Comparisons</h2>
        <div class="sub" id="analysis-meta">Experiment-level charts should aggregate repetitions and compare configurations before you inspect any one run.</div>
      </div>
      <div class="panel-body">
        <div class="analysis-stack">
          <div class="analysis-summary-grid" id="analysis-summary"></div>

          <div class="surface">
            <div class="title">
              <h3>Configuration Comparison</h3>
              <div class="sub" id="analysis-table-meta">Mean score, repetition variance, and task success aggregated across child runs.</div>
            </div>
            <div class="table-wrap" id="analysis-table"></div>
          </div>

          <div class="surface">
            <div class="title">
              <h3>Task Comparison Matrix</h3>
              <div class="sub" id="analysis-task-meta">Compare every configuration against baseline for each task in the selected scope.</div>
            </div>
            <div class="table-wrap" id="analysis-task-movers"></div>
          </div>

          <div class="surface">
            <div class="title">
              <h3>Tool Redundancy Hotspots</h3>
              <div class="sub" id="analysis-redundancy-meta">Repeated or near-equivalent tool calls that may indicate low-value rework.</div>
            </div>
            <div class="table-wrap" id="analysis-redundancy-table"></div>
          </div>

          <div id="analysis-chart-groups"></div>

          <div class="surface">
            <div class="title">
              <h3>Task Comparison Pages</h3>
              <div class="sub" id="analysis-pages-meta">Experiment-level task comparison pages. These can be filtered to the selected executable.</div>
            </div>
            <div class="link-row" id="analysis-task-pages"></div>
          </div>
        </div>
      </div>
    </section>

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
          <div class="panel-head-row">
            <div>
              <div class="kicker">Step 2</div>
              <h2 id="run-list-title">Runs For Executable</h2>
            </div>
            <button type="button" class="panel-toggle" id="runs-panel-toggle" aria-expanded="true">Hide Step 2</button>
          </div>
          <div class="sub" id="run-list-meta">Select an executable to view its baseline and variants.</div>
        </div>
        <div class="panel-body" id="run-rows"></div>
      </section>

      <section class="panel detail-panel">
        <div class="panel-head">
          <div class="panel-head-row">
            <div style="min-width:0; flex:1 1 auto;">
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
            <button type="button" class="panel-toggle" id="detail-panel-toggle" aria-expanded="true">Hide Step 3</button>
          </div>
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

          <div class="surface collapsible logs-panel">
            <details id="server-status-details">
              <summary class="title">
                <div class="collapse-copy">
                  <h3>Server Status</h3>
                  <div class="sub" id="server-status-meta">Live server logs and transient status messages.</div>
                </div>
                <span class="collapse-indicator">Log view</span>
              </summary>
              <pre id="server-log"></pre>
            </details>
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
    let analysisSectionState = {};
    let workspacePanelState = {
      runs: true,
      detail: true,
    };

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

    function numericValue(value) {
      const num = Number(value);
      return Number.isFinite(num) ? num : null;
    }

    function formatNumber(value, digits = 2) {
      const num = numericValue(value);
      return num === null ? "—" : num.toFixed(digits);
    }

    function formatSigned(value, digits = 2) {
      const num = numericValue(value);
      if (num === null) return "—";
      return `${num >= 0 ? "+" : ""}${num.toFixed(digits)}`;
    }

    function clampPercent(value) {
      const num = Number(value);
      if (!Number.isFinite(num)) return 0;
      return Math.max(0, Math.min(100, num));
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

    function applyWorkspacePanelState() {
      const runsBody = document.querySelector(".runs-panel .panel-body");
      const detailBody = document.querySelector(".detail-panel .panel-body");
      const runsToggle = document.getElementById("runs-panel-toggle");
      const detailToggle = document.getElementById("detail-panel-toggle");
      if (runsBody) {
        runsBody.style.display = workspacePanelState.runs ? "" : "none";
      }
      if (detailBody) {
        detailBody.style.display = workspacePanelState.detail ? "" : "none";
      }
      if (runsToggle) {
        runsToggle.textContent = workspacePanelState.runs ? "Hide Step 2" : "Show Step 2";
        runsToggle.setAttribute("aria-expanded", workspacePanelState.runs ? "true" : "false");
      }
      if (detailToggle) {
        detailToggle.textContent = workspacePanelState.detail ? "Hide Step 3" : "Show Step 3";
        detailToggle.setAttribute("aria-expanded", workspacePanelState.detail ? "true" : "false");
      }
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
      if (current.visualization_error) {
        metaParts.push("static charts failed to build");
      }
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

    function renderAnalysis(state) {
      const analysis = (state || {}).experiment_analysis || {};
      const sectionOpen = (key, defaultOpen) => {
        if (Object.prototype.hasOwnProperty.call(analysisSectionState, key)) {
          return !!analysisSectionState[key];
        }
        return !!defaultOpen;
      };
      document.getElementById("analysis-meta").textContent =
        analysis.meta || "Experiment-level charts should aggregate repetitions and compare configurations before you inspect any one run.";

      const summaryCards = [
        {
          label: "Configurations",
          value: String(analysis.configuration_count || 0),
          subvalue: `${analysis.sample_count || 0} executable(s) • ${analysis.task_scope_count || 0} sample-task cases`,
        },
        {
          label: "Repetitions",
          value: `${analysis.completed_repetitions || 0}/${analysis.planned_repetitions || 0}`,
          subvalue: "Completed vs planned repetitions across compared configurations",
        },
        {
          label: "Best Variant",
          value: ((analysis.best_variant || {}).display_label) || "No comparison yet",
          subvalue: analysis.best_variant
            ? `score delta ${formatSigned(analysis.best_variant.score_delta, 2)} • success delta ${formatSigned(analysis.best_variant.task_success_delta, 2)}`
            : "No non-baseline aggregate rows available",
        },
        {
          label: "Highest Variance",
          value: ((analysis.highest_variance_variant || {}).display_label) || "No variance yet",
          subvalue: analysis.highest_variance_variant
            ? `score sd ${formatNumber(analysis.highest_variance_variant.overall_score_stddev, 2)}`
            : "Repeat variance not available yet",
        },
        {
          label: "Largest Task Swing",
          value: ((analysis.widest_task_shift || {}).sample_task_id) || "No task deltas yet",
          subvalue: analysis.widest_task_shift
            ? `${analysis.widest_task_shift.display_label} • ${formatSigned(analysis.widest_task_shift.score_delta, 2)}`
            : "Task-level deltas not available yet",
        },
        {
          label: "Chart Coverage",
          value: String(analysis.chart_count || 0),
          subvalue: `${analysis.task_page_count || 0} task comparison page(s) • ${(analysis.variable_families || []).join(", ") || "no variant families"}`,
        },
        {
          label: "Most Redundant Variant",
          value: ((analysis.most_redundant_variant || {}).display_label) || "No repeats yet",
          subvalue: analysis.most_redundant_variant
            ? `${formatNumber(analysis.most_redundant_variant.mean_tool_semantic_duplicate_calls, 2)} repeated calls • rate ${formatNumber(analysis.most_redundant_variant.mean_tool_semantic_duplicate_rate, 2)}`
            : "No semantic duplicate-call data available yet",
        },
        {
          label: "Largest Executable Split",
          value: ((analysis.most_heterogeneous_variant || {}).display_label) || "No executable split yet",
          subvalue: analysis.most_heterogeneous_variant
            ? `${analysis.most_heterogeneous_variant.heterogeneity_label || "mixed"} • span ${formatNumber(analysis.most_heterogeneous_variant.delta_span, 2)}`
            : "Executable-level heterogeneity not available yet",
        },
        {
          label: "Worst Redundant Executable",
          value: analysis.most_redundant_executable
            ? `${analysis.most_redundant_executable.sample || ""} • ${analysis.most_redundant_executable.display_label || ""}`
            : "No executable hotspot yet",
          subvalue: analysis.most_redundant_executable
            ? `${formatNumber(analysis.most_redundant_executable.mean_tool_semantic_duplicate_calls, 2)} repeated calls • ${analysis.most_redundant_executable.tool_most_redundant_family || "tool family unknown"}`
            : "Executable-level redundancy is not available yet",
        },
        {
          label: "Worst Redundant Task",
          value: ((analysis.most_redundant_task || {}).sample_task_id) || "No hotspots yet",
          subvalue: analysis.most_redundant_task
            ? `${analysis.most_redundant_task.display_label} • ${formatNumber(analysis.most_redundant_task.tool_semantic_duplicate_calls, 2)} repeated calls`
            : "Task-level redundancy hotspots not available yet",
        },
      ];

      document.getElementById("analysis-summary").innerHTML = summaryCards.map((card) => `
        <div class="analysis-card">
          <div class="label">${escapeHtml(card.label)}</div>
          <div class="value">${escapeHtml(card.value)}</div>
          <div class="subvalue">${escapeHtml(card.subvalue)}</div>
        </div>
      `).join("");

      const variantRows = (analysis.variant_rows || []);
      document.getElementById("analysis-table-meta").textContent =
        "Rows are aggregated by configuration across repetitions. Score, success, and redundancy metrics use the same variant-level grouping.";
      if (!variantRows.length) {
        document.getElementById("analysis-table").innerHTML = `<div class="column-empty">No aggregate comparison rows are available for this experiment yet.</div>`;
      } else {
        const rows = variantRows.map((row) => `
          <tr>
            <td>${escapeHtml(row.display_label || row.variant_id || "")}</td>
            <td>${escapeHtml(row.changed_variable || "")}</td>
            <td>${formatNumber(row.overall_score_mean, 2)}</td>
            <td>${formatSigned(row.score_delta, 2)}</td>
            <td>${formatNumber(row.task_success_rate, 2)}</td>
            <td>${formatNumber(row.mean_tool_semantic_duplicate_calls, 2)}</td>
            <td>${formatNumber(row.mean_tool_semantic_duplicate_rate, 2)}</td>
            <td>${formatNumber(row.overall_score_stddev, 2)}</td>
            <td>${escapeHtml(`${row.completed_repetitions || 0}/${row.planned_repetitions || 0}`)}</td>
          </tr>
        `).join("");
        document.getElementById("analysis-table").innerHTML = `
          <table>
            <thead>
              <tr>
                <th>Configuration</th>
                <th>Variable</th>
                <th>Mean score</th>
                <th>Score delta</th>
                <th>Task success</th>
                <th>Repeated calls</th>
                <th>Repeat rate</th>
                <th>Score sd</th>
                <th>Repetitions</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        `;
      }

      const selectedSample = selectedExecutable || "";
      const taskRows = (analysis.task_spotlights || []);
      const redundancyRows = (analysis.redundancy_hotspots || []);
      const taskMatrixColumns = (analysis.task_matrix_columns || []);
      const taskMatrixRows = (analysis.task_matrix_rows || []);
      document.getElementById("analysis-task-meta").textContent = selectedSample
        ? `Experiment-wide task matrix. The executable selection below does not filter this table; it stays scoped to all executables/tasks in the experiment.`
        : "Experiment-wide task matrix across all executables and tasks in the selected experiment.";
      if (!taskMatrixRows.length) {
        document.getElementById("analysis-task-movers").innerHTML = `<div class="column-empty">No task comparison rows are available for this view yet.</div>`;
      } else {
        const headerCells = [
          "<th>Executable</th>",
          "<th>Task</th>",
          "<th>Baseline</th>",
          ...taskMatrixColumns.map((column) => `<th>${escapeHtml(column.display_label || column.variant_id || "")}</th>`),
        ].join("");
        const rows = taskMatrixRows.map((row) => {
          const configs = row.configs || {};
          const cells = taskMatrixColumns.map((column) => {
            const cell = configs[column.variant_id] || null;
            if (!cell) {
              return "<td>—</td>";
            }
            return `
              <td>
                <div>${escapeHtml(formatNumber(cell.score, 2))}</div>
                <div class="muted">${escapeHtml(formatSigned(cell.delta, 2))}</div>
              </td>
            `;
          }).join("");
          return `
            <tr>
              <td>${escapeHtml(row.sample || "")}</td>
              <td>${escapeHtml(row.task_name || row.task_id || row.sample_task_id || "")}</td>
              <td>${escapeHtml(formatNumber(row.baseline_score, 2))}</td>
              ${cells}
            </tr>
          `;
        }).join("");
        document.getElementById("analysis-task-movers").innerHTML = `
          <table>
            <thead>
              <tr>${headerCells}</tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        `;
      }

      document.getElementById("analysis-redundancy-meta").textContent = selectedSample
        ? "Experiment-wide redundancy hotspots. The executable selection does not filter this table so repeated-call patterns remain directly comparable."
        : "Experiment-wide hotspots showing repeated tool usage across sample-tasks.";
      if (!redundancyRows.length) {
        document.getElementById("analysis-redundancy-table").innerHTML = `<div class="column-empty">No repeated or near-equivalent tool-call hotspots were detected for this experiment yet.</div>`;
      } else {
        const rows = redundancyRows.map((row) => `
          <tr>
            <td>${escapeHtml(row.sample || "")}</td>
            <td>${escapeHtml(row.task_name || row.task_id || row.sample_task_id || "")}</td>
            <td>${escapeHtml(row.display_label || row.variant_id || "")}</td>
            <td>${formatNumber(row.tool_semantic_duplicate_calls, 2)}</td>
            <td>${formatNumber(row.tool_semantic_duplicate_rate, 2)}</td>
            <td>${escapeHtml(row.tool_most_redundant_target || "—")}</td>
          </tr>
        `).join("");
        document.getElementById("analysis-redundancy-table").innerHTML = `
          <table>
            <thead>
              <tr>
                <th>Executable</th>
                <th>Task</th>
                <th>Configuration</th>
                <th>Repeated calls</th>
                <th>Repeat rate</th>
                <th>Top repeated target</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        `;
      }

      const chartGroups = (analysis.chart_sections || []);
      const variantRowsForCharts = (analysis.variant_rows || []);
      const fallbackCharts = [];
      if (variantRowsForCharts.length) {
        const scoreRows = variantRowsForCharts.map((row) => {
          const score = numericValue(row.overall_score_mean);
          return `
            <div class="bar-row">
              <div class="bar-label">${escapeHtml(row.display_label || row.variant_id || "")}</div>
              <div class="bar-track"><div class="bar-fill" style="width:${clampPercent(score)}%;"></div></div>
              <div class="bar-value">${formatNumber(score, 2)}</div>
            </div>
          `;
        }).join("");
        fallbackCharts.push(`
          <div class="fallback-chart">
            <h4>Mean Score By Configuration</h4>
            <div class="sub">Aggregated score across completed repetitions. Scale assumes a 0-100 score range.</div>
            <div class="bar-list">${scoreRows}</div>
          </div>
        `);

        const successRows = variantRowsForCharts.map((row) => {
          const rate = numericValue(row.task_success_rate);
          return `
            <div class="bar-row">
              <div class="bar-label">${escapeHtml(row.display_label || row.variant_id || "")}</div>
              <div class="bar-track"><div class="bar-fill success" style="width:${clampPercent((rate || 0) * 100)}%;"></div></div>
              <div class="bar-value">${formatNumber(rate, 2)}</div>
            </div>
          `;
        }).join("");
        fallbackCharts.push(`
          <div class="fallback-chart">
            <h4>Task Success Rate</h4>
            <div class="sub">Fraction of tasks marked successful across completed repetitions.</div>
            <div class="bar-list">${successRows}</div>
          </div>
        `);

        const maxDelta = Math.max(...variantRowsForCharts.map((row) => Math.abs(numericValue(row.score_delta) || 0)), 1);
        const deltaRows = variantRowsForCharts.map((row) => {
          const delta = numericValue(row.score_delta) || 0;
          const width = clampPercent((Math.abs(delta) / maxDelta) * 100);
          return `
            <div class="bar-row">
              <div class="bar-label">${escapeHtml(row.display_label || row.variant_id || "")}</div>
              <div class="delta-track">
                <div class="delta-fill-neg" style="width:${delta < 0 ? width : 0}%;"></div>
                <div class="delta-axis"></div>
                <div class="delta-fill-pos" style="width:${delta > 0 ? width : 0}%;"></div>
              </div>
              <div class="bar-value">${formatSigned(delta, 2)}</div>
            </div>
          `;
        }).join("");
        fallbackCharts.push(`
          <div class="fallback-chart">
            <h4>Score Delta Vs Baseline</h4>
            <div class="sub">Positive bars improve on baseline; negative bars underperform it.</div>
            <div class="bar-list">${deltaRows}</div>
          </div>
        `);

        const varianceMax = Math.max(...variantRowsForCharts.map((row) => numericValue(row.overall_score_stddev) || 0), 1);
        const varianceRows = variantRowsForCharts.map((row) => {
          const sd = numericValue(row.overall_score_stddev) || 0;
          return `
            <div class="bar-row">
              <div class="bar-label">${escapeHtml(row.display_label || row.variant_id || "")}</div>
              <div class="bar-track"><div class="bar-fill variance" style="width:${clampPercent((sd / varianceMax) * 100)}%;"></div></div>
              <div class="bar-value">${formatNumber(sd, 2)}</div>
            </div>
          `;
        }).join("");
        fallbackCharts.push(`
          <div class="fallback-chart">
            <h4>Repetition Variance</h4>
            <div class="sub">Standard deviation of score across repetitions for each configuration.</div>
            <div class="bar-list">${varianceRows}</div>
          </div>
        `);

        const redundancyRows = variantRowsForCharts.map((row) => {
          const repeatedCalls = numericValue(row.mean_tool_semantic_duplicate_calls);
          const rate = numericValue(row.mean_tool_semantic_duplicate_rate);
          const width = clampPercent((Math.min(repeatedCalls || 0, 10) / 10) * 100);
          return `
            <div class="bar-row">
              <div class="bar-label">${escapeHtml(row.display_label || row.variant_id || "")}</div>
              <div class="bar-track"><div class="bar-fill variance" style="width:${width}%;"></div></div>
              <div class="bar-value">${formatNumber(repeatedCalls, 2)} (${formatNumber(rate, 2)})</div>
            </div>
          `;
        }).join("");
        fallbackCharts.push(`
          <div class="fallback-chart">
            <h4>Repeated Tool Calls</h4>
            <div class="sub">Mean semantic duplicate-call count per configuration, with duplicate rate in parentheses.</div>
            <div class="bar-list">${redundancyRows}</div>
          </div>
        `);
      }

      if (taskRows.length) {
        const maxTaskDelta = Math.max(...taskRows.slice(0, 8).map((row) => Math.abs(numericValue(row.score_delta) || 0)), 1);
        const taskDeltaRows = taskRows.slice(0, 8).map((row) => {
          const delta = numericValue(row.score_delta) || 0;
          const width = clampPercent((Math.abs(delta) / maxTaskDelta) * 100);
          return `
            <div class="bar-row">
              <div class="bar-label">${escapeHtml(row.sample_task_id || "")}</div>
              <div class="delta-track">
                <div class="delta-fill-neg" style="width:${delta < 0 ? width : 0}%;"></div>
                <div class="delta-axis"></div>
                <div class="delta-fill-pos" style="width:${delta > 0 ? width : 0}%;"></div>
              </div>
              <div class="bar-value">${formatSigned(delta, 2)}</div>
            </div>
          `;
        }).join("");
        fallbackCharts.push(`
          <div class="fallback-chart">
            <h4>${selectedSample ? "Task Movers For Selected Executable" : "Largest Task Movers"}</h4>
            <div class="sub">Largest task-level score deltas currently in view.</div>
            <div class="bar-list">${taskDeltaRows}</div>
          </div>
        `);
      }

      const chartLead = analysis.visualization_error
        ? `<div class="notice-banner"><strong>Static experiment charts were not generated.</strong>${escapeHtml(analysis.visualization_error)}. The browser is showing inline fallback charts built from the aggregate CSV data instead.</div>`
        : "";

      if (!chartGroups.length) {
        if (fallbackCharts.length) {
          document.getElementById("analysis-chart-groups").innerHTML = `
            ${chartLead}
            <div class="surface analysis-section">
              <details data-analysis-section="browser-native" ${sectionOpen("browser-native", true) ? "open" : ""}>
                <summary class="title">
                  <div class="collapse-copy">
                    <h3>Browser-Native Charts</h3>
                    <div class="sub">Experiment-level charts rendered directly from the aggregate tables when static chart artifacts are unavailable.</div>
                  </div>
                  <span class="collapse-indicator">Charts</span>
                </summary>
                <div style="padding:16px;">
                  <div class="fallback-chart-grid">${fallbackCharts.join("")}</div>
                </div>
              </details>
            </div>
          `;
        } else {
          document.getElementById("analysis-chart-groups").innerHTML = `
            ${chartLead}
            <div class="column-empty">No experiment charts were found yet.</div>
          `;
        }
      } else {
        document.getElementById("analysis-chart-groups").innerHTML = `
          ${chartLead}
          ${chartGroups.map((section) => `
            <div class="surface analysis-section">
              <details data-analysis-section="${escapeAttr(section.key || "")}" ${sectionOpen(section.key || "", section.open) ? "open" : ""}>
                <summary class="title">
                  <div class="collapse-copy">
                    <h3>${escapeHtml(section.title || "Charts")}</h3>
                    <div class="sub">${escapeHtml(section.description || "")}</div>
                  </div>
                  <span class="collapse-indicator">Charts</span>
                </summary>
                <div class="visual-grid">
                  ${(section.images || []).map((entry) => `
                    <a class="visual-card" href="${escapeAttr(entry.url || "#")}" target="_blank" rel="noreferrer">
                      <img src="${escapeAttr(entry.url || "")}" alt="${escapeAttr(entry.title || entry.filename || "chart")}" loading="lazy">
                      <div class="visual-card-body">
                        <div class="visual-card-title">${escapeHtml(entry.title || entry.filename || "Chart")}</div>
                        <div class="visual-card-copy">${escapeHtml(entry.description || entry.filename || "")}</div>
                      </div>
                    </a>
                  `).join("")}
                </div>
              </details>
            </div>
          `).join("")}
        `;
      }
      document.querySelectorAll("#analysis-chart-groups details[data-analysis-section]").forEach((details) => {
        const key = details.getAttribute("data-analysis-section") || "";
        if (!key) return;
        details.addEventListener("toggle", () => {
          analysisSectionState[key] = details.open;
        });
      });

      const taskPages = (analysis.task_pages || []).filter((entry) => !selectedSample || entry.sample === selectedSample);
      document.getElementById("analysis-pages-meta").textContent = selectedSample
        ? `Task comparison pages for ${selectedSample}.`
        : "Experiment-level task comparison pages. Select an executable to narrow this list.";
      document.getElementById("analysis-task-pages").innerHTML = taskPages.length
        ? taskPages.slice(0, 12).map((entry) => `
            <a class="link-chip" href="${escapeAttr(entry.url || "#")}" target="_blank" rel="noreferrer">
              ${escapeHtml(entry.task_name || entry.sample_task_id || "task comparison")}
            </a>
          `).join("")
        : `<div class="column-empty">No task comparison pages were found for this view yet.</div>`;
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
        renderAnalysis(state);
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

    document.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.id === "runs-panel-toggle") {
        workspacePanelState.runs = !workspacePanelState.runs;
        applyWorkspacePanelState();
      } else if (target.id === "detail-panel-toggle") {
        workspacePanelState.detail = !workspacePanelState.detail;
        applyWorkspacePanelState();
      }
    });

    refresh();
    applyWorkspacePanelState();
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


def _safe_csv_rows(path: Path) -> List[Dict[str, str]]:
    try:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    except Exception:
        return []


def _as_float(value: Any) -> float | None:
    try:
        text = str(value or "").strip()
        if not text:
            return None
        return float(text)
    except Exception:
        return None


def _as_int(value: Any) -> int | None:
    try:
        text = str(value or "").strip()
        if not text:
            return None
        return int(float(text))
    except Exception:
        return None


def _as_bool(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _collect_chart_entries(experiment_root: Path) -> List[Dict[str, Any]]:
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
            image_entries.append(
                {
                    "filename": artifact_path.name,
                    "title": str(raw_entry.get("title") or artifact_path.stem.replace("_", " ").title()).strip(),
                    "description": str(raw_entry.get("description") or "").strip(),
                    "url": _artifact_url(experiment_id, relative_path),
                }
            )
        return image_entries

    if outputs_root.exists():
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
                    "url": _artifact_url(experiment_id, relative_path),
                }
            )
    return image_entries


def _load_visualization_status(experiment_root: Path) -> Dict[str, Any]:
    outputs_root = experiment_root / "outputs"
    chart_manifest = _safe_json(outputs_root / "chart_manifest.json")
    error_payload = _safe_json(outputs_root / "visualization_error.json")
    created_files = chart_manifest.get("created_files") if isinstance(chart_manifest.get("created_files"), list) else []
    return {
        "has_static_charts": bool(created_files),
        "chart_count": len(created_files or []),
        "visualization_error": str(error_payload.get("error") or "").strip() if isinstance(error_payload, dict) else "",
    }


def _collect_task_page_entries(experiment_root: Path) -> List[Dict[str, str]]:
    experiment_id = experiment_root.name
    outputs_root = experiment_root / "outputs"
    task_pages: List[Dict[str, str]] = []
    comparison_manifest = _safe_json(outputs_root / "task_output_comparisons" / "comparison_manifest.json")
    tasks_payload = comparison_manifest.get("tasks") if isinstance(comparison_manifest.get("tasks"), dict) else {}
    for sample_task_id, raw_entry in sorted(tasks_payload.items()):
        if not isinstance(raw_entry, dict):
            continue
        page_path = str(raw_entry.get("page") or "").strip()
        if not page_path:
            continue
        relative_path = Path("outputs") / "task_output_comparisons" / page_path
        task_pages.append(
            {
                "sample": str(raw_entry.get("sample") or "").strip(),
                "sample_task_id": str(sample_task_id),
                "task_name": str(raw_entry.get("task_name") or raw_entry.get("task_id") or sample_task_id),
                "url": _artifact_url(experiment_id, relative_path),
            }
        )
    return task_pages


def _chart_section_key(entry: Dict[str, Any]) -> str:
    haystack = " ".join(
        [
            str(entry.get("filename") or ""),
            str(entry.get("title") or ""),
            str(entry.get("description") or ""),
        ]
    ).lower()
    if any(token in haystack for token in ("redundancy", "duplicate", "repeated tool", "wasteful")):
        return "redundancy"
    if any(token in haystack for token in ("executable", "cross-executable", "heterogeneous", "masked-by-average")):
        return "executable"
    if any(token in haystack for token in ("reliability", "coverage", "failure", "validator", "judge error", "outcome breakdown")):
        return "reliability"
    if any(token in haystack for token in ("time", "duration", "runtime")):
        return "timing"
    if any(token in haystack for token in ("task", "difficulty", "technique", "distribution", "category")):
        return "task"
    return "overview"


def _build_experiment_analysis_payload(experiment_root: Path) -> Dict[str, Any]:
    manifest = _safe_json(experiment_root / "experiment_manifest.json")
    variant_rows = _safe_csv_rows(experiment_root / "variant_summary.csv")
    task_rows = _safe_csv_rows(experiment_root / "task_comparison.csv")
    executable_rows = _safe_csv_rows(experiment_root / "executable_summary.csv")
    executable_consistency_rows = _safe_csv_rows(experiment_root / "executable_consistency.csv")
    redundancy_variant_rows = _safe_csv_rows(experiment_root / "tool_redundancy_by_variant.csv")
    charts = _collect_chart_entries(experiment_root)
    task_pages = _collect_task_page_entries(experiment_root)
    visualization_status = _load_visualization_status(experiment_root)

    section_meta = {
        "overview": {
            "title": "Performance And Tradeoffs",
            "description": "Overall ranking, runtime/cost tradeoffs, and effect-size summaries for the compared configurations.",
            "open": True,
        },
        "reliability": {
            "title": "Reliability And Coverage",
            "description": "Validation, analysis, judge, and coverage outcomes separated so infrastructure failures do not get conflated with performance.",
            "open": True,
        },
        "executable": {
            "title": "Per-Executable Performance",
            "description": "Executable-specific rankings and heatmaps showing where overall averages hide heterogeneous variant behavior.",
            "open": True,
        },
        "redundancy": {
            "title": "Tool Redundancy",
            "description": "Repeated and near-equivalent tool-use views broken down by configuration, executable, and likely wasteful hotspot targets.",
            "open": False,
        },
        "task": {
            "title": "Task And Category Effects",
            "description": "Category-level score shifts and task-score consistency views showing where configurations helped or hurt.",
            "open": False,
        },
        "timing": {
            "title": "Timing And Bottlenecks",
            "description": "Task-category runtime views showing where time is being spent and which configurations slow categories down.",
            "open": False,
        },
    }
    grouped_images: Dict[str, List[Dict[str, Any]]] = {"overview": [], "reliability": [], "executable": [], "redundancy": [], "task": [], "timing": []}
    for entry in charts:
        grouped_images[_chart_section_key(entry)].append(entry)

    chart_sections = [
        {
            "key": key,
            "title": meta["title"],
            "description": meta["description"],
            "open": meta["open"],
            "images": grouped_images.get(key, []),
        }
        for key, meta in section_meta.items()
        if grouped_images.get(key)
    ]

    sorted_variants = []
    for row in variant_rows:
        sorted_variants.append(
            {
                "variant_id": str(row.get("variant_id") or ""),
                "display_label": str(row.get("display_label") or row.get("variant_id") or ""),
                "changed_variable": str(row.get("changed_variable") or ""),
                "is_baseline": _as_bool(row.get("is_baseline")),
                "overall_score_mean": _as_float(row.get("overall_score_mean")),
                "overall_score_stddev": _as_float(row.get("overall_score_stddev")),
                "score_delta": _as_float(row.get("score_delta")),
                "task_success_rate": _as_float(row.get("task_success_rate")),
                "task_success_delta": _as_float(row.get("task_success_delta")),
                "mean_tool_exact_duplicate_calls": _as_float(row.get("mean_tool_exact_duplicate_calls")),
                "mean_tool_semantic_duplicate_calls": _as_float(row.get("mean_tool_semantic_duplicate_calls")),
                "mean_tool_exact_duplicate_rate": _as_float(row.get("mean_tool_exact_duplicate_rate")),
                "mean_tool_semantic_duplicate_rate": _as_float(row.get("mean_tool_semantic_duplicate_rate")),
                "analysis_failure_rate": _as_float(row.get("analysis_failure_rate")),
                "completed_repetitions": _as_int(row.get("completed_repetitions")),
                "planned_repetitions": _as_int(row.get("planned_repetitions")),
                "included_in_complete_aggregate": _as_bool(row.get("included_in_complete_aggregate")),
            }
        )
    sorted_variants.sort(
        key=lambda row: (
            0 if row.get("is_baseline") else 1,
            -9999.0 if row.get("score_delta") is None else -float(row.get("score_delta") or 0.0),
            str(row.get("display_label") or ""),
        )
    )

    non_baseline_variants = [row for row in sorted_variants if not row.get("is_baseline")]
    best_variant = max(
        [row for row in non_baseline_variants if row.get("score_delta") is not None],
        key=lambda row: float(row.get("score_delta") or 0.0),
        default=None,
    )
    highest_variance = max(
        [row for row in sorted_variants if row.get("overall_score_stddev") is not None],
        key=lambda row: float(row.get("overall_score_stddev") or 0.0),
        default=None,
    )
    most_redundant_variant = max(
        [
            row for row in non_baseline_variants
            if row.get("mean_tool_semantic_duplicate_calls") is not None or row.get("mean_tool_semantic_duplicate_rate") is not None
        ],
        key=lambda row: (
            float(row.get("mean_tool_semantic_duplicate_calls") or 0.0),
            float(row.get("mean_tool_semantic_duplicate_rate") or 0.0),
        ),
        default=None,
    )
    most_heterogeneous_variant = max(
        [
            {
                "variant_id": str(row.get("variant_id") or ""),
                "display_label": str(row.get("display_label") or row.get("variant_id") or ""),
                "changed_variable": str(row.get("changed_variable") or ""),
                "mean_score_delta": _as_float(row.get("mean_score_delta")),
                "delta_span": _as_float(row.get("delta_span")),
                "heterogeneity_label": str(row.get("heterogeneity_label") or ""),
                "masked_by_average": _as_bool(row.get("masked_by_average")),
                "strongest_executable": str(row.get("strongest_executable") or ""),
                "weakest_executable": str(row.get("weakest_executable") or ""),
            }
            for row in executable_consistency_rows
            if str(row.get("variant_id") or "")
        ],
        key=lambda row: (
            1 if row.get("masked_by_average") else 0,
            float(row.get("delta_span") or 0.0),
        ),
        default=None,
    )
    most_redundant_executable = max(
        [
            {
                "variant_id": str(row.get("variant_id") or ""),
                "display_label": str(row.get("display_label") or row.get("variant_id") or ""),
                "sample": str(row.get("sample") or ""),
                "mean_tool_semantic_duplicate_calls": _as_float(row.get("mean_tool_semantic_duplicate_calls")),
                "mean_tool_semantic_duplicate_rate": _as_float(row.get("mean_tool_semantic_duplicate_rate")),
                "tool_most_redundant_family": str(row.get("tool_most_redundant_family") or ""),
            }
            for row in executable_rows
            if str(row.get("variant_id") or "") and str(row.get("variant_id") or "") != "baseline"
        ],
        key=lambda row: (
            float(row.get("mean_tool_semantic_duplicate_calls") or 0.0),
            float(row.get("mean_tool_semantic_duplicate_rate") or 0.0),
        ),
        default=None,
    )

    task_spotlights = []
    redundancy_hotspots = []
    task_matrix_map: Dict[str, Dict[str, Any]] = {}
    for row in task_rows:
        score_delta = _as_float(row.get("score_delta"))
        sample_task_id = str(row.get("sample_task_id") or "")
        variant_id = str(row.get("variant_id") or "")
        display_label = str(row.get("display_label") or variant_id or "")
        matrix_entry = task_matrix_map.setdefault(
            sample_task_id,
            {
                "sample": str(row.get("sample") or ""),
                "task_id": str(row.get("task_id") or ""),
                "task_name": str(row.get("task_name") or row.get("task_id") or ""),
                "sample_task_id": sample_task_id,
                "baseline_score": _as_float(row.get("baseline_score")),
                "configs": {},
            },
        )
        baseline_score = _as_float(row.get("baseline_score"))
        if baseline_score is not None:
            matrix_entry["baseline_score"] = baseline_score
        score_value = _as_float(row.get("score"))
        if variant_id == "baseline" or display_label == "baseline":
            if score_value is not None:
                matrix_entry["baseline_score"] = score_value
        elif variant_id:
            matrix_entry["configs"][variant_id] = {
                "variant_id": variant_id,
                "display_label": display_label,
                "score": score_value,
                "delta": score_delta,
                "task_success_rate": _as_float(row.get("task_success_rate")),
            }
        if score_delta is None:
            score_row = None
        else:
            score_row = {
                "display_label": display_label,
                "sample": str(row.get("sample") or ""),
                "task_id": str(row.get("task_id") or ""),
                "task_name": str(row.get("task_name") or row.get("task_id") or ""),
                "sample_task_id": sample_task_id,
                "score": _as_float(row.get("score")),
                "baseline_score": _as_float(row.get("baseline_score")),
                "score_delta": score_delta,
                "task_success_rate": _as_float(row.get("task_success_rate")),
            }
            task_spotlights.append(score_row)
        semantic_duplicate_calls = _as_float(row.get("tool_semantic_duplicate_calls"))
        semantic_duplicate_rate = _as_float(row.get("tool_semantic_duplicate_rate"))
        if semantic_duplicate_calls is not None or semantic_duplicate_rate is not None:
            redundancy_hotspots.append(
                {
                    "variant_id": variant_id,
                    "display_label": display_label,
                    "sample": str(row.get("sample") or ""),
                    "task_id": str(row.get("task_id") or ""),
                    "task_name": str(row.get("task_name") or row.get("task_id") or ""),
                    "sample_task_id": sample_task_id,
                    "tool_semantic_duplicate_calls": semantic_duplicate_calls,
                    "tool_semantic_duplicate_rate": semantic_duplicate_rate,
                    "tool_most_redundant_target": str(row.get("tool_most_redundant_target") or ""),
                }
            )
    task_spotlights = [row for row in task_spotlights if row.get("display_label") != "baseline"]
    task_spotlights.sort(key=lambda row: abs(float(row.get("score_delta") or 0.0)), reverse=True)
    widest_task_shift = task_spotlights[0] if task_spotlights else None
    redundancy_hotspots = [row for row in redundancy_hotspots if row.get("display_label") != "baseline"]
    redundancy_hotspots.sort(
        key=lambda row: (
            float(row.get("tool_semantic_duplicate_calls") or 0.0),
            float(row.get("tool_semantic_duplicate_rate") or 0.0),
            str(row.get("sample_task_id") or ""),
        ),
        reverse=True,
    )
    most_redundant_task = redundancy_hotspots[0] if redundancy_hotspots else None
    task_matrix_columns = [
        {
            "variant_id": str(row.get("variant_id") or ""),
            "display_label": str(row.get("display_label") or row.get("variant_id") or ""),
        }
        for row in non_baseline_variants
        if str(row.get("variant_id") or "")
    ]
    task_matrix_rows = sorted(
        list(task_matrix_map.values()),
        key=lambda row: (
            str(row.get("sample") or ""),
            str(row.get("task_name") or row.get("task_id") or ""),
            str(row.get("sample_task_id") or ""),
        ),
    )

    planned_repetitions = max([row.get("planned_repetitions") or 0 for row in sorted_variants], default=0)
    completed_repetitions = min([row.get("completed_repetitions") or 0 for row in sorted_variants], default=0)
    selected_samples = manifest.get("selected_samples") if isinstance(manifest.get("selected_samples"), list) else []
    selected_task_keys = manifest.get("selected_task_keys") if isinstance(manifest.get("selected_task_keys"), list) else []
    variable_families = sorted(
        {
            str(row.get("changed_variable") or "").strip()
            for row in non_baseline_variants
            if str(row.get("changed_variable") or "").strip()
        }
    )

    return {
        "meta": "Experiment-level analysis combines child runs by configuration across repetitions. Use the run detail below for raw outputs and per-run debugging.",
        "sample_count": len(selected_samples),
        "task_scope_count": len(selected_task_keys),
        "configuration_count": len(sorted_variants),
        "planned_repetitions": planned_repetitions,
        "completed_repetitions": completed_repetitions,
        "chart_count": len(charts),
        "has_static_charts": bool(visualization_status.get("has_static_charts")),
        "visualization_error": str(visualization_status.get("visualization_error") or ""),
        "task_page_count": len(task_pages),
        "variable_families": variable_families,
        "best_variant": best_variant,
        "highest_variance_variant": highest_variance,
        "widest_task_shift": widest_task_shift,
        "most_redundant_variant": most_redundant_variant,
        "most_heterogeneous_variant": most_heterogeneous_variant,
        "most_redundant_executable": most_redundant_executable,
        "most_redundant_task": most_redundant_task,
        "variant_rows": sorted_variants,
        "task_spotlights": task_spotlights[:10],
        "redundancy_hotspots": redundancy_hotspots[:12],
        "executable_rows": executable_rows,
        "executable_consistency_rows": executable_consistency_rows,
        "redundancy_variant_rows": redundancy_variant_rows,
        "task_matrix_columns": task_matrix_columns,
        "task_matrix_rows": task_matrix_rows,
        "chart_sections": chart_sections,
        "task_pages": task_pages,
    }


def _build_visual_gallery_payload(experiment_root: Path, sample_name: str = "") -> Dict[str, Any]:
    visualization_status = _load_visualization_status(experiment_root)
    image_entries: List[Dict[str, Any]] = []
    for entry in _collect_chart_entries(experiment_root):
        relevance = _match_score(sample_name, " ".join([entry.get("filename") or "", entry.get("title") or "", entry.get("description") or ""]))
        image_entries.append({**entry, "relevance": relevance})

    sample_specific = [entry for entry in image_entries if int(entry.get("relevance") or 0) > 0]
    if sample_name and sample_specific:
        image_entries = sample_specific + [entry for entry in image_entries if int(entry.get("relevance") or 0) == 0][:4]

    task_pages: List[Dict[str, str]] = []
    for entry in _collect_task_page_entries(experiment_root):
        sample = str(entry.get("sample") or "").strip()
        sample_task_id = str(entry.get("sample_task_id") or "").strip()
        if sample_name and sample != sample_name and not sample_task_id.startswith(f"{sample_name}::"):
            continue
        task_pages.append(entry)

    meta = "Experiment-level visuals."
    if sample_name and sample_specific:
        meta = f"Showing {len(sample_specific)} sample-matched chart(s) for {sample_name}, plus experiment-level context."
    elif sample_name:
        meta = f"No sample-specific chart filenames matched {sample_name}; showing experiment-level visuals."
    return {
        "sample": str(sample_name or "").strip(),
        "meta": meta,
        "visualization_error": str(visualization_status.get("visualization_error") or ""),
        "images": image_entries[:8],
        "task_pages": task_pages[:10],
    }


def load_results_browser_catalog(results_root: Path = RESULTS_ROOT) -> Dict[str, Any]:
    experiments: List[Dict[str, Any]] = []
    for experiment_root in _list_experiment_roots(results_root):
        manifest = _safe_json(experiment_root / "experiment_manifest.json")
        state = load_live_view_state(experiment_root) if (experiment_root / "run_catalog.json").exists() else {"summary": {"total_runs": 0}}
        outputs_root = experiment_root / "outputs"
        visual_status = _load_visualization_status(experiment_root)
        visual_count = int(visual_status.get("chart_count") or 0)
        if not visual_count and outputs_root.exists():
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
                "visualization_error": str(visual_status.get("visualization_error") or ""),
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
    state = load_live_view_state(experiment_root)
    state["experiment_analysis"] = _build_experiment_analysis_payload(experiment_root)
    return state


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
