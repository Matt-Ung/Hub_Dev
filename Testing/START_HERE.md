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

The harness loads repo `.env` automatically.

## 2. Build The Binaries

```bash
make all-exes
```

That builds:

- `Testing/build/experimental/`
- `Testing/build/prototype/`

The experimental corpus is the benchmark corpus. The prototype corpus is for smoke/regression checks.

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

Check readiness:

```bash
python Testing/check_bundle_integrity.py --corpus experimental
```

## 4. Run Launch Doctor

Before a paid run:

```bash
python Testing/run_launch_doctor.py
```

This checks:

- Python deps
- required env vars
- explicit judge-model config
- judge vs agent model separation
- bundle integrity
- pilot vs broad budget projection

## 5. Safest First Paid Run

Preflight the recommended pilot:

```bash
python Testing/run_launch_preset.py \
  --preset paid_narrow_pilot \
  --judge-model openai:gpt-4o-mini \
  --preflight-only
```

Run it for real:

```bash
python Testing/run_launch_preset.py \
  --preset paid_narrow_pilot \
  --judge-model openai:gpt-4o-mini
```

## 6. Run A Sweep

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

## 8. Where To Extend The Suite

- Add or edit benchmark binaries: [Experimental_Test_Source/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/Experimental_Test_Source/README.md)
- Add sweep dimensions or guardrails: [config/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/config/README.md)
- Understand the current supported evaluation design: [TESTING_PLAN.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/TESTING_PLAN.md)
