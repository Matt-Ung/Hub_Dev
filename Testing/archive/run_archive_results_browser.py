#!/usr/bin/env python3
"""
File: run_archive_results_browser.py
Author: Matt-Ung
Last Updated: 2026-04-08
Purpose:
  Launch the archive-only viewer for legacy results.

Summary:
  This script starts the lightweight HTTP server that browses archived
  pre-refactor results under `Testing/archive/results_legacy/`. It is the only
  maintained launcher for the old `results/runs` plus `samples/` layout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow direct execution from the repo root without keeping this archive-only
# launcher in the active `Testing/scripts/` entrypoint surface.
TESTING_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TESTING_ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Testing.harness.archive_results_browser import (
    ARCHIVE_RESULTS_ROOT,
    load_archive_results_browser_catalog,
    start_archive_results_browser_server,
)


"""
Function: main
Inputs:
  - None directly. Command-line flags choose the archive root, host, and
    preferred port for the local archive-browser server.
Description:
  Start the archive-only results browser, print its discovery payload, and
  keep the server thread alive until interrupted.
Outputs:
  Returns nothing. Prints a JSON object containing the server URL and current
  archived experiment count.
Side Effects:
  Starts a local HTTP server that reads under `Testing/archive/results_legacy/`.
"""
def main() -> None:
    parser = argparse.ArgumentParser(description="Launch the archive-only browser for legacy Testing/archive/results_legacy experiments.")
    parser.add_argument("--archive-root", default=str(ARCHIVE_RESULTS_ROOT), help="Archive results root to browse")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=0, help="Preferred port; 0 lets the OS choose")
    args = parser.parse_args()

    archive_root = Path(args.archive_root).expanduser().resolve()
    server, thread, url = start_archive_results_browser_server(archive_root, host=args.host, port=args.port)
    catalog = load_archive_results_browser_catalog(archive_root)
    print(
        json.dumps(
            {
                "archive_root": str(archive_root),
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
