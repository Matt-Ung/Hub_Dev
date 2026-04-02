#!/usr/bin/env python3
"""
File: run_results_browser.py
Author: Matt-Ung
Last Updated: 2026-04-02
Purpose:
  Launch a browser-oriented viewer for completed or in-progress experiment runs.

Summary:
  This script starts the lightweight HTTP server that browses
  `Testing/results/experiments/` with an experiment selector, executable/run
  hierarchy, and chart footer for post-run analysis.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness.paths import RESULTS_ROOT
from harness.results_browser import load_results_browser_catalog, start_results_browser_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch the local results browser for Testing/results/experiments.")
    parser.add_argument("--results-root", default=str(RESULTS_ROOT), help="Results root to browse")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=0, help="Preferred port; 0 lets the OS choose")
    args = parser.parse_args()

    results_root = Path(args.results_root).expanduser().resolve()
    server, thread, url = start_results_browser_server(results_root, host=args.host, port=args.port)
    catalog = load_results_browser_catalog(results_root)
    print(
        json.dumps(
            {
                "results_root": str(results_root),
                "url": url,
                "experiment_count": len(catalog.get("experiments") or []),
            },
            indent=2,
        )
    )
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
