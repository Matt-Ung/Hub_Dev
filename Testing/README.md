# Testing Suite

`Testing/` contains the maintained evaluation harness for the repo.

## What Is Active Today

- **Binary-analysis track**: the active automated benchmark
  - entry points: `Testing/run_evaluation.py`, `Testing/run_experiment_sweep.py`
  - benchmark corpus: `Testing/Experimental_Test_Source/`
  - development smoke corpus: `Testing/Prototype_Test_Source/`
- **Source-code track**: datasets, templates, and prompt scaffolding only
  - there is no dedicated source-eval runner yet

If you are new to the testing suite, start with [START_HERE.md](START_HERE.md).

The recommended operational path is now:

1. `python Testing/run_launch_doctor.py`
2. `python Testing/run_launch_preset.py --preset sanity_core_slice_r1 --preflight-only`
3. `python Testing/run_launch_preset.py --preset budget_best_value_r2`

## Directory Map

```text
Testing/
  START_HERE.md               # contributor quickstart
  README.md                   # suite overview
  TESTING_PLAN.md             # current evaluation design and scope
  config/                     # sweep, rubric, cost, prompt, and launch config
  Prototype_Test_Source/      # prototype regression corpus source + build docs
  Experimental_Test_Source/   # experimental benchmark corpus source + manifest
  C_Source_Evaluation/        # source-eval datasets + templates (no active runner)
  harness/                    # active harness implementation
  build/                      # compiled binaries
  generated/bundles/          # prepared Ghidra/tool bundles
  results/                    # runs, sweeps, charts, lineages, and catalogs
```

## Active Entry Points

```bash
python Testing/run_evaluation.py --corpus experimental
python Testing/run_evaluation.py --corpus experimental --prefer-unpacked-upx
python Testing/run_experiment_sweep.py --corpus experimental
python Testing/run_launch_doctor.py
python Testing/prepare_bundles.py --corpus experimental
python Testing/render_test_catalog.py --corpus experimental
python Testing/run_refresh_experiment_outputs.py Testing/results/experiments/<experiment_id>
python Testing/run_recover_failed_tasks.py Testing/results/runs/<run_id> --plan-only
```

## Which Scripts Matter Most

Primary entry points:

- `run_evaluation.py`
  - one configuration over a selected set of sample-task pairs
- `run_experiment_sweep.py`
  - baseline + variants + aggregation across many child runs
- `run_launch_doctor.py`
  - readiness and projected-cost gate before paid runs
- `prepare_bundles.py`
  - bundle preparation outside the full run path
- `run_recover_failed_tasks.py`
  - inspect an existing run or sweep directory and relaunch only failed or unfinished sample-task cases

Convenience wrappers:

- `run_launch_preset.py`
  - named operational shortcuts over the two primary runners
- `render_test_catalog.py`
  - static benchmark surface renderer, no agent calls
- `check_bundle_integrity.py`
  - compatibility wrapper around `run_launch_doctor.py --bundle-only`

If you are debugging execution flow, start with the primary entry points and
the modules under `Testing/harness/`. The convenience scripts mainly reduce
command length, not conceptual complexity.

When adding a new entry point, prefer extending one of the existing primary
commands or adding a flag to an existing wrapper. A new top-level script should
only exist if it shortens a genuinely common workflow and would otherwise force
users to memorize a long or error-prone command.

`run_launch_doctor.py` is now the main readiness entry point for both bundle integrity and budget/dependency checks. Use `--bundle-only` if you only want the integrity half of that workflow.

## Recommended Presets

Prefer these launch presets before using the full default sweep:

- `sanity_core_slice_r1`
  - smallest maintained sweep that still produces graphs and task-level comparison tables
- `budget_best_value_r1`
  - one-repetition version of the recommended budget study when you want the same comparison shape with lower cost
- `budget_best_value_r2`
  - recommended under-budget study for decision-useful comparisons across the experimental corpus
- `coverage_broad_r1_60usd`
  - one-repetition medium+hard broad-coverage preset that stays below the current 60 USD heuristic band by restricting the broad sweep to the query-verbosity, worker-subagent, and worker-prompt-shape families
- `full_suite_default_r1`
  - broad one-repetition research sweep after the smaller studies above are healthy

For deliberate depth work centered on `config_decoder_test.c`, use the focused
decoder presets:

- `sweep_decoder_depth_r3`
  - combined three-repetition decoder-depth study across both `config_decoder_test_stripped.exe` and `config_decoder_test_upx_stripped.exe`, trimmed to the worker-subagent comparison so the current heuristic stays below 30 USD
- `sweep_decoder_depth_followups_r3`
  - same decoder-depth scope and repetitions, but reduced to worker prompt shape plus one validator-backed pipeline follow-up while keeping the original decoder-depth baseline unchanged
- `sweep_decoder_depth_stripped_r3`
  - stripped-only three-repetition depth study on `config_decoder_test_stripped.exe`
- `sweep_decoder_depth_upx_stripped_r3`
  - packed-only three-repetition depth study on `config_decoder_test_upx_stripped.exe`

The harness does not impose a default subprocess timeout on builds, bundle
preparation, or child runs anymore. Use `--timeout-sec <seconds>` only when you
want an explicit ceiling; `0` disables it.

## UPX Unpack Continuation

By default, prepared bundles and downstream analysis use the original sample
binary exactly as built. If you want the harness to switch to an unpacked
derivative when a sample is recognized as UPX-packed, add
`--prefer-unpacked-upx` to `run_evaluation.py`, `run_experiment_sweep.py`, or
`run_launch_preset.py`.

When that flag is enabled:

- the harness tests the prepared sample with `upx -t`
- if UPX recognizes it, the harness runs `upx -d`
- it builds a derived unpacked bundle under
  `Testing/generated/bundles/<corpus>/<sample>/derived/upx_unpacked/`
- downstream artifact-backed analysis uses that derived bundle instead of the
  original packed one
- results still record the original packed sample path plus UPX detection and
  unpack metadata

If `upx` is unavailable, unpacking fails, or `analyzeHeadless` cannot build the
derived bundle, the run falls back to the original prepared bundle and records
that fallback reason in the result artifacts.

If a repo `.venv` exists, the launch doctor and preset launcher target that
interpreter for dependency checks and child-run launches instead of whatever
system Python happened to invoke the wrapper script.

For a live developer-facing sweep monitor, add `--live-view` to
`run_experiment_sweep.py` or `run_launch_preset.py`. The sweep will print a
local browser URL and write its live monitor assets under
`Testing/results/experiments/<experiment_id>/live_view/`.

## Current Sweep Dimensions

The maintained default sweep is defined in [Testing/config/experiment_sweeps.json](config/experiment_sweeps.json).

It currently studies these one-variable-at-a-time families:

- `query_verbosity`
- `worker_subagents`
- `worker_prompt_shape`
- `tool_availability`
- `architecture_preset`
- `pipeline_preset`
- `validator_topology`
- `validator_review_level`


The default sweep currently plans:

- `21` configuration groups total
- `3` repetitions per group by default

Check the exact current plan without launching runs:

```bash
python Testing/run_experiment_sweep.py --plan-only
```

That full sweep is maintained, but it is intentionally broader than the recommended first paid run. For day-to-day comparisons, use the launch presets above so cost, output volume, and interpretation stay manageable.

## Outputs

Single-run results live under:

```text
Testing/results/runs/<run_id>/
```

Sweep results live under:

```text
Testing/results/experiments/<experiment_id>/
```

The easiest artifact-inspection layout is:

```text
.../by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/
```

Inside each run slot:

- `agent_raw_output.md`
- `judge_scorecard.json`
- `judge_reasoning.md`
- `agent_result.json`
- `judge_result.json`
- `record.json`

See [Testing/results/README.md](results/README.md) for the full output map.

For later analysis, treat these as the main outputs first:

- single run:
  - `aggregate.json`
  - `summary.csv`
  - `samples/<sample_task_slug>/{agent_result.json, judge_result.json, record.json}`
- sweep:
  - `variant_summary.csv`
  - `task_comparison.csv`
  - `significance_overall.csv`
  - `outputs/`
  - `partial_*.csv` and `outputs/partial/` when a sweep produced useful partial work but not full comparison coverage

## Visualization Suite

The experiment visualization layer is now organized around a smaller
reporting-oriented figure set instead of many debug-style heatmaps.

The main static figures under `outputs/` are:

- `01_overall_performance_ranking.png`
  - ranked overall score view with repetition variance and task-success context
- `02_tradeoff_frontiers.png`
  - runtime-vs-score and cost-vs-score tradeoff panels
- `03_reliability_and_coverage.png`
  - validation, judge, analysis, transport, and missing-coverage outcomes kept separate
- `04_task_category_score_deltas.png`
  - score delta by task/technique category
- `05_task_category_runtime.png`
  - runtime bottlenecks by task category plus runtime delta vs baseline
- `06_task_score_distribution.png`
  - per-task score spread for consistency analysis
- `07_effect_size_summary.png`
  - effect-size-first significance summary when replicate statistics are available

Supporting files:

- `outputs/config_label_legend.json`
  - short-label to full configuration mapping used in the figures
- `outputs/figure_guide.md`
  - one-line purpose statement for each generated figure
- `outputs/chart_manifest.json`
  - machine-readable chart inventory for the browser

If plotting dependencies are missing, the harness writes
`outputs/visualization_error.json` instead of silently omitting charts. The
results browser now surfaces that error and falls back to browser-native
aggregate charts so the experiment is still analyzable.

The rest of the tree is still useful, but it is mostly for debugging, live
monitoring, or inspection-oriented browsing.

## Recovery Utility

When a run or sweep finishes with failed, interrupted, budget-skipped, or
otherwise incomplete task cases, use the recovery utility instead of rerunning
the whole scope:

```bash
python Testing/run_recover_failed_tasks.py \
  Testing/results/experiments/<experiment_id> \
  --plan-only
```

Execute the recovery plan:

```bash
python Testing/run_recover_failed_tasks.py \
  Testing/results/experiments/<experiment_id>
```

You can also target one child run directly:

```bash
python Testing/run_recover_failed_tasks.py \
  Testing/results/runs/<run_id>
```

What it does:

- inspects canonical run artifacts such as `run_manifest.json`,
  `live_status.json`, `aggregate.json`, and per-task
  `samples/*/{record.json,agent_result.json,judge_result.json}`
- classifies each expected sample-task as `completed`, `failed_analysis`,
  `failed_judge`, `skipped_budget`, `interrupted`, `incomplete`,
  `missing_artifacts`, or `active`
- retries only the retryable tasks by launching a fresh recovery run with the
  original run configuration plus exact `--sample-task-key` filters
- writes recovery bookkeeping under
  `<target>/recovery_attempts/<session_id>/recovery_session.json`
  without mutating the original run directory

Important assumptions and edge cases:

- `active` tasks from a still-running run are reported but not retried
- if `run_manifest.json` is missing, the utility falls back to sweep catalog and
  experiment-manifest metadata when available
- if per-task artifacts are too incomplete to resolve exact task scope, the
  recovery plan falls back to retrying the original run scope in a distinct
  recovery run
- recovery runs default to `--skip-build --skip-prepare`, so they assume the
  original binaries and prepared bundles are still valid

If you want the repaired task results to feed graphs, comparison tables, and
the results browser, rebuild a repaired experiment view after recovery:

```bash
python Testing/run_rebuild_experiment_from_recovery.py \
  Testing/results/experiments/<experiment_id> \
  --plan-only
```

Then materialize the repaired experiment:

```bash
python Testing/run_rebuild_experiment_from_recovery.py \
  Testing/results/experiments/<experiment_id>
```

What it does:

- reads one or more completed `recovery_attempts/<session_id>/recovery_session.json`
  manifests from the experiment
- overlays recovered `sample::task` records onto the original child-run
  aggregates without editing the original experiment directory
- writes a new sibling experiment directory under `Testing/results/experiments/`
  with rebuilt `variant_summary.csv`, `task_comparison.csv`, `outputs/*.png`,
  `by_executable/`, and other experiment-level artifacts
- materializes synthetic repaired run directories so the existing results
  browser and task drill-down pages keep working against the repaired dataset

In the results browser, read the top experiment-analysis section first. Those
charts and tables are aggregated across repetitions and configurations for the
entire experiment. The executable/run drill-down below is intended for
per-run outputs, failures, and task-level debugging after you identify an
interesting experiment-level pattern.

## Extension Guides

- [multi_agent_wf/extension_tutorial.md](../multi_agent_wf/extension_tutorial.md): workflow/dashboard extension map and how new pipeline or architecture options flow into testing
- [START_HERE.md](START_HERE.md): how to run the suite end to end
- [TESTING_PLAN.md](TESTING_PLAN.md): current evaluation design
- [config/README.md](config/README.md): how to add sweep variables, prompts, and guardrails
- [Experimental_Test_Source/README.md](Experimental_Test_Source/README.md): how to add samples and tasks
- [Prototype_Test_Source/README.md](Prototype_Test_Source/README.md): prototype smoke corpus notes
