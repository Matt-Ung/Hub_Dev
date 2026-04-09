# Testing Suite

`Testing/` contains the maintained evaluation harness for the repo.

## Active Track

- Binary-analysis workflow
  - compiled Windows PE samples plus prepared bundles
  - single runs, sweeps, recovery, merge, and browser tooling

## Layout

```text
Testing/
├── README.md
├── archive/       # archived legacy results + archive-only viewer docs
├── docs/          # quickstart + evaluation design
├── scripts/       # CLI entrypoints and utility commands
├── sources/       # prototype, experimental, and final-round corpora
├── config/        # sweeps, prompts, rubrics, budgets, presets
├── harness/       # implementation modules
├── build/         # compiled sample binaries
├── generated/     # prepared bundle artifacts
├── results/       # run, sweep, preflight, and browser outputs
└── tests/         # harness regression tests
```

## What To Use

Start here:

- [docs/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/docs/README.md)
- [docs/quickstart.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/docs/quickstart.md)
- [docs/evaluation_design.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/docs/evaluation_design.md)

Corpus docs:

- [sources/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/README.md)
- [sources/prototype/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/prototype/README.md)
- [sources/experimental/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/experimental/README.md)
- [sources/final_round/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/final_round/README.md)

Output/reference docs:

- [config/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/config/README.md)
- [results/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/results/README.md)

## Main Commands

```bash
python Testing/scripts/run_launch_doctor.py
python Testing/scripts/run_launch_preset.py --preset sanity_core_slice_r1 --preflight-only
python Testing/scripts/run_evaluation.py --corpus experimental
python Testing/scripts/run_experiment_sweep.py --corpus experimental --plan-only
python Testing/scripts/run_results_browser.py
python Testing/archive/run_archive_results_browser.py
```

`--preflight-only` sweep and preset commands now write under
`Testing/results/preflight/` so `Testing/results/experiments/` stays reserved
for real launched experiments.

## Structure Rationale

The directory now separates concerns more clearly:

- `scripts/` is only for human-facing entrypoints
- `harness/` is only implementation logic
- `sources/` is only sample-source corpora
- `config/` is only declarative configuration
- `build/`, `generated/`, and `results/` stay separate because they have
  different lifecycles:
  - `build/` = compiled binaries
  - `generated/` = prepared intermediate bundles
  - `results/` = experiment outputs and analysis artifacts
- `archive/` is only for retired legacy result trees and their archive-only
  inspection path

If you are extending the suite, prefer:

1. update a corpus manifest under `sources/`
2. update harness logic under `harness/` only when needed
3. add a new script under `scripts/` only if it shortens a common workflow
