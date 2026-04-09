# Testing Archive

`Testing/archive/` is for retired historical outputs that no longer match the
maintained harness result layout.

## Current Archive Scope

- `results_legacy/`
  - archived pre-refactor experiments and run trees
  - old `results/runs/...` plus `samples/...` layout
  - old experiment directories that still relied on `run_dir`,
    `by_executable/`, `recovery_attempts/`, or `rebuilt_runs/`

## What To Use

- Active viewer for current runs:
  - [../scripts/run_results_browser.py](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/scripts/run_results_browser.py)
- Archive-only viewer for legacy runs:
  - [run_archive_results_browser.py](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/archive/run_archive_results_browser.py)
- Legacy broad-sweep relabel + graph refresh helper:
  - [refresh_legacy_broad_sweep_response_scope.sh](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/archive/refresh_legacy_broad_sweep_response_scope.sh)

The active live monitor and active results browser no longer support the legacy
format. Historical inspection happens here only.

## Historical Refresh Helpers

To regenerate the archived repaired broad-sweep graphs with the newer
`response_scope` naming, run:

```bash
bash Testing/archive/refresh_legacy_broad_sweep_response_scope.sh
```

This creates a copied archived experiment with a `-response-scope` suffix and
rebuilds its experiment-level outputs in place.
