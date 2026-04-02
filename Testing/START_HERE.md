# Start Here

This guide is the quickest way to run the maintained binary testing harness end to end.

## 1. Prepare The Environment

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Required runtime env:

- `OPENAI_API_KEY`
- `EVAL_JUDGE_MODEL`
- `GHIDRA_HEADLESS` or `GHIDRA_INSTALL_DIR`◊
- `GHIDRA_JAVA_HOME`
- `x86_64-w64-mingw32-gcc` on `PATH` for canonical Windows PE corpus builds

The harness loads repo `.env` automatically.

Notes:

- When `./.venv/bin/python` exists, the launch doctor and preset launcher now
  treat that repo interpreter as the effective runtime target for dependency
  checks and child-run launches.
- `requirements.txt` already includes the judge and visualization deps the doctor checks for, including `pydantic`, `pydantic-ai`, `matplotlib`, and `pandas`.
- `upx` is optional. Packed-variant targets are skipped when `UPX_BIN` is not available.
- The maintained experiment path targets Windows-style `.exe` samples. The corpus-local `*_gcc.exe` host builds are useful for development, but they are not the canonical full-experiment target.

## 2. Build The Binaries

```bash
make all-exes
```

That builds:

- `Testing/build/experimental/`
- `Testing/build/prototype/`

The experimental corpus is the benchmark corpus. The prototype corpus is for smoke/regression checks.

If `make all-exes` fails immediately with `x86_64-w64-mingw32-gcc: No such file or directory`, install the MinGW-w64 cross-compiler and rerun. The launch doctor now calls this out explicitly.

## 3. Prepare Bundles

Prepared bundles only need regeneration when bundle inputs change, for example:

- executable contents changed
- Ghidra export script changed
- bundle preparer version changed

Persona prompt changes do **not** invalidate bundles.

Prepare the experimental bundles:

```bash
python Testing/prepare_bundles.py --corpus experimental
```

Run the launch doctor after preparing bundles. It already includes bundle-integrity checks, toolchain checks, Python dependency checks, and cost projection:

```bash
python Testing/run_launch_doctor.py
```

This checks:

- MinGW toolchain presence for canonical corpus builds
- Python deps
- required env vars
- explicit judge-model config
- judge vs agent model separation
- bundle integrity
- pilot vs broad budget projection

If you want the doctor to behave like the old standalone bundle-integrity command, use:

```bash
python Testing/run_launch_doctor.py --corpus experimental --bundle-only
```

Useful related flags:

- `--show-bundle-details`: always print the per-sample missing/stale bundle breakdown
- `--bundle-only`: run only bundle-integrity checks for the selected scope and exit non-zero on failure

You can also make the doctor project a narrower sweep slice before launch:

- `--repetitions <n>`: override the projected repetition count
- `--variable <family>`: project only one or more sweep families
- `--sample <file>`: restrict the broad projection to selected sample binaries
- `--task <task_id>`: restrict the broad projection to selected manifest task ids
- `--difficulty-filter <level>`: restrict the broad projection to selected difficulty bands

Examples:

One-repetition broad projection:

```bash
python Testing/run_launch_doctor.py --corpus experimental --repetitions 1
```

One family only:

```bash
python Testing/run_launch_doctor.py \
  --corpus experimental \
  --variable worker_prompt_shape \
  --repetitions 1
```

One sample-task slice:

```bash
python Testing/run_launch_doctor.py \
  --corpus experimental \
  --sample config_decoder_test.exe \
  --task config_value_recovery \
  --variable worker_prompt_shape \
  --repetitions 1
```

Bundle-only for one narrowed scope:

```bash
python Testing/run_launch_doctor.py \
  --corpus experimental \
  --sample config_decoder_test.exe \
  --task config_value_recovery \
  --bundle-only \
  --show-bundle-details
```

## 4. Smallest Graph-Producing Sanity Sweep

Inspect the doctor projection for the recommended small sanity sweep:

```bash
python Testing/run_launch_doctor.py --pilot-preset sanity_core_slice_r1
```

Preflight it:

```bash
python Testing/run_launch_preset.py \
  --preset sanity_core_slice_r1 \
  --judge-model openai:gpt-4o-mini \
  --preflight-only
```

Run it for real:

```bash
python Testing/run_launch_preset.py \
  --preset sanity_core_slice_r1 \
  --judge-model openai:gpt-4o-mini
```

Projected cost is intentionally small, but this still produces:

- `variant_summary.csv`
- `task_comparison.csv`
- `significance_overall.csv`
- `outputs/*.png`

If a sweep is interrupted or some variants do not finish full coverage, the
main aggregate outputs stay conservative: incomplete comparison groups are
written separately to `partial_*.csv`, `partial_comparison.json`, and
`outputs/partial/`.

## 5. Recommended Under-Budget Study

Inspect the doctor projection for the recommended comparison study:

```bash
python Testing/run_launch_doctor.py --pilot-preset budget_best_value_r2
```

Preflight it:

```bash
python Testing/run_launch_preset.py \
  --preset budget_best_value_r2 \
  --judge-model openai:gpt-4o-mini \
  --preflight-only
```

Run it:

```bash
python Testing/run_launch_preset.py \
  --preset budget_best_value_r2 \
  --judge-model openai:gpt-4o-mini
```

Add `--live-view` if you want the lightweight local browser monitor while the sweep runs:

```bash
python Testing/run_launch_preset.py \
  --preset budget_best_value_r2 \
  --judge-model openai:gpt-4o-mini \
  --live-view
```

This preset is the recommended first decision-useful study because it:

- uses only focused, unique task IDs, so the selected scope is unambiguous
- covers deceptive cues, packing triage, config recovery, and harder low-leakage behavior recovery
- stays well below the repo's default experiment-cost ceiling
- produces readable graphs and aggregate tables without launching the full 21-group sweep

If you want the same study shape with lower cost and faster turnaround, use the
new one-repetition variant instead:

```bash
python Testing/run_launch_doctor.py --pilot-preset budget_best_value_r1
python Testing/run_launch_preset.py --preset budget_best_value_r1 --judge-model openai:gpt-4o-mini --preflight-only
```

If you want a single one-repetition run with much broader coverage and a
heuristic cost near `$60`, use:

```bash
python Testing/run_launch_doctor.py --pilot-preset coverage_broad_r1_60usd
python Testing/run_launch_preset.py --preset coverage_broad_r1_60usd --judge-model openai:gpt-4o-mini --preflight-only
```

By default, the harness no longer applies a child-run subprocess timeout. If
you want an explicit ceiling for build, bundle-prep, or run subprocesses, add
`--timeout-sec <seconds>` manually. `--timeout-sec 0` disables the timeout.

Estimated-cost settings such as `max_run_estimated_cost_usd` and
`max_experiment_estimated_cost_usd` are advisory warning thresholds. They still
appear in doctor/preflight output and `budget_status.json`, but they no longer
abort a started preset unless you explicitly configure the matching
`hard_max_*_estimated_cost_usd` field.

## 6. Broad Sweep

Inspect the default plan:

```bash
python Testing/run_experiment_sweep.py --plan-only
```

Budget-safer first sweep:

```bash
python Testing/run_experiment_sweep.py \
  --corpus experimental \
  --repetitions 1 \
  --judge-model openai:gpt-4o-mini \
  --preflight-only
```

Then run it:

```bash
python Testing/run_experiment_sweep.py \
  --corpus experimental \
  --repetitions 1 \
  --judge-model openai:gpt-4o-mini
```

Use the broad default sweep only after the sanity or budget presets above. It is the maintained research sweep, but it is not the shortest path to a decision-useful comparison.

To watch sweep progress live in a browser while child runs are executing:

```bash
python Testing/run_experiment_sweep.py \
  --corpus experimental \
  --repetitions 1 \
  --judge-model openai:gpt-4o-mini \
  --live-view
```

`--live-view` starts a tiny local HTTP monitor that polls the sweep artifacts
as they change. It is intentionally lightweight and developer-facing:

- run queue with pending/running/completed/failed states
- stage-based pipeline progress for the selected child run
- primary final-output pane for the selected run, with baseline and judge context beside it
- separate server-status log panel for transient live logs
- task-level status rows from each child run's `live_status.json`

The monitor metadata is written under:

```text
Testing/results/experiments/<experiment_id>/live_view/
```

Useful files there:

- `live_view_url.txt`: the local URL printed by the sweep
- `logs/<run_id>.log`: streamed child-run output captured while the sweep runs

Each child run also writes:

```text
Testing/results/runs/<run_id>/live_status.json
```

That file is what the live view polls for current phase and task progress.

## 7. Where To Look At Results

Single runs:

```text
Testing/results/runs/<run_id>/
```

Sweep runs:

```text
Testing/results/experiments/<experiment_id>/
```

Best drill-down view:

```text
.../by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/
```

Best high-level comparison view:

- `variant_summary.csv`
- `task_comparison.csv`
- `significance_overall.csv`
- `outputs/*.png`

## 7.1 Reset Generated Results

If you want a clean benchmark state without touching tracked docs or curated
reference artifacts:

```bash
bash Testing/clean_results.sh
```

That resets:

- `Testing/results/doctor/`
- `Testing/results/experiments/`
- `Testing/results/lineages/`
- `Testing/results/runs/`

Useful options:

- `--dry-run`: preview what would be removed
- `--include-catalog`: also reset `Testing/results/catalog/`
- `--include-logs`: also remove generated `logs/agentToolBench_*` folders

Make targets:

```bash
make clean-test-results
make clean-test-results-all
```

## 8. Where To Extend The Suite

- Add or edit benchmark binaries: [Experimental_Test_Source/README.md](Experimental_Test_Source/README.md)
- Add sweep dimensions or guardrails: [config/README.md](config/README.md)
- Understand the current supported evaluation design: [TESTING_PLAN.md](TESTING_PLAN.md)
