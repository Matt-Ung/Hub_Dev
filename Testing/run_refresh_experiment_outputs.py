from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from harness.experiment_sweep import materialize_experiment_outputs
from harness.paths import read_json


def _safe_json(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            return read_json(path)
    except Exception:
        return {}
    return {}


def _load_run_entries(experiment_root: Path) -> List[Dict[str, Any]]:
    catalog = _safe_json(experiment_root / "run_catalog.json")
    entries: List[Dict[str, Any]] = []
    for raw_entry in (catalog.get("runs") or []):
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        run_dir = Path(str(entry.get("run_dir") or "")).expanduser()
        entry["run_dir"] = str(run_dir.resolve()) if run_dir.exists() else str(run_dir)
        entry["run_manifest"] = _safe_json(run_dir / "run_manifest.json")
        entry["aggregate"] = _safe_json(run_dir / "aggregate.json")
        entry["ok"] = bool(entry.get("ok")) and bool(entry.get("aggregate"))
        entry["status"] = str(entry.get("status") or ("completed" if entry.get("ok") else "failed"))
        entry["error"] = str(entry.get("error") or "")
        entries.append(entry)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate experiment-level outputs (tables, graphs, browser artifacts) for an existing experiment directory.")
    parser.add_argument("experiment_root", help="Path to Testing/results/experiments/<experiment_id>")
    parser.add_argument("--skip-visuals", action="store_true", help="Regenerate CSV/report/browser outputs without rebuilding PNG charts.")
    args = parser.parse_args()

    experiment_root = Path(args.experiment_root).expanduser().resolve()
    experiment_manifest = _safe_json(experiment_root / "experiment_manifest.json")
    if not experiment_manifest:
        raise FileNotFoundError(f"experiment_manifest.json not found under {experiment_root}")

    run_entries = _load_run_entries(experiment_root)
    if not run_entries:
        raise FileNotFoundError(f"No run entries were found under {experiment_root / 'run_catalog.json'}")

    outputs_summary = materialize_experiment_outputs(
        experiment_root=experiment_root,
        experiment_manifest=experiment_manifest,
        run_entries=run_entries,
        skip_visuals=bool(args.skip_visuals),
    )
    print(json.dumps({"ok": True, "experiment_root": str(experiment_root), "outputs_summary": outputs_summary}, indent=2))


if __name__ == "__main__":
    main()
