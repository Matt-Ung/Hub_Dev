# Testing Plan

This document describes the testing system the repo actually supports today.

It is intentionally narrower than older versions of the plan. Historical ideas, ad hoc workflows, and speculative roadmap items were removed so this file stays aligned with the maintained harness.

## 1. Scope

There are two tracks in `Testing/`:

1. **Binary-analysis track**
   - active automated benchmark
   - entry points:
     - `Testing/run_evaluation.py`
     - `Testing/run_experiment_sweep.py`
2. **Source-code track**
   - datasets, prompts, and templates only
   - no dedicated runner yet

The binary-analysis track is the authoritative automated evaluation path.

## 2. Active Corpora

### Experimental Corpus

This is the benchmark corpus used for sweeps.

- source: `Testing/Experimental_Test_Source/`
- binaries: `Testing/build/experimental/`
- manifest: `Testing/Experimental_Test_Source/sample_manifest.json`

Current shape:

- `11` source programs
- `15` executable variants
- `24` manifest-defined sample-task pairs

The atomic evaluation unit is a **sample-task pair**, not just a sample.

### Prototype Corpus

This is a development smoke/regression corpus, not the main benchmark.

- source: `Testing/Prototype_Test_Source/`
- binaries: `Testing/build/prototype/`

Use it for:

- quick tool sanity checks
- smoke regression after workflow changes
- stripped/packed-path development checks

## 3. Binary Harness Workflow

The maintained single-run workflow is:

```text
build -> prepare bundles -> resolve sample-task set -> analyze -> judge -> aggregate
```

The maintained sweep workflow is:

```text
plan baseline + variants -> run child evaluations -> aggregate by variant -> compute deltas -> write charts/tables
```

Prepared bundles live under:

```text
Testing/generated/bundles/<corpus>/
```

Bundles are reused when fresh. Freshness depends on bundle-generation inputs such as:

- executable identity
- Ghidra export script hash
- bundle preparer version

Prompt or persona changes do **not** invalidate bundles.

## 4. Current Automated Sweep Design

The source of truth is:

- `Testing/config/experiment_sweeps.json`

The design is baseline-first and one-variable-at-a-time.

### Baseline

Current default baseline:

| Field | Value |
|---|---|
| corpus | `experimental` |
| pipeline | `auto_triage` |
| architecture | `balanced` |
| query variant | `default` |
| worker subagent profile | `default` |
| worker persona profile | `default` |
| worker role prompt mode | `default` |
| validator review level | `default` |
| tool profile | `full` |
| model profile | `repo_default` |
| judge mode | `agent` |

### Active Sweep Families

| Variable family | Variants |
|---|---|
| `query_verbosity` | `brief`, `detailed` |
| `worker_subagents` | `single_generalist` |
| `worker_prompt_shape` | `artifact_focused`, `empty` |
| `tool_availability` | `core_static`, `ghidra_only` |
| `architecture_preset` | `minimal`, `ghidra_focused`, `model_augmented` |
| `pipeline_preset` | `workers_reporter`, `planner_workers_reporter` |
| `validator_topology` | family baseline + `light`, `dual` |
| `validator_review_level` | family baseline + `easy`, `intermediate`, `strict` |


Some families also define a **family baseline**. This means the sweep inserts an extra local baseline run for that family using its `baseline_overrides`, and that family's variants are compared against that local baseline instead of only against the global default baseline. In the current sweep, this is used for `validator_topology` and `validator_review_level`.

Current default size:

- `21` configuration groups
- `3` repetitions per group by default

Recommended operational presets for normal experiment work:

- `sanity_core_slice_r1`
  - smallest graph-producing maintained sweep
- `budget_best_value_r1`
  - one-repetition version of the recommended budget study
- `budget_best_value_r2`
  - recommended under-budget comparison study
- `coverage_broad_r1_60usd`
  - one-repetition medium+hard broad-coverage preset that stays below the current 60 USD heuristic band by restricting the broad sweep to the query-verbosity, worker-subagent, and worker-prompt-shape families
- `full_suite_default_r1`
  - broad one-repetition sweep after the smaller presets are healthy

Check the real plan before launching:

```bash
python Testing/run_experiment_sweep.py --plan-only
```

### Selection Rules

The sweep always applies one configuration to the full selected task set.

The selected task set is controlled by:

- `--sample`
- `--task`
- `--difficulty-filter`

Important nuance:

- `--task` filters task IDs globally across the selected samples.
- That means repeated `--sample` plus repeated `--task` is safest when the chosen task IDs are unique across those samples.
- The recommended `budget_best_value_r2` preset is intentionally built from unique focused task IDs so its scope is unambiguous.

Total work is:

- `child_runs = configuration_groups * repetitions`
- `sample_task_evaluations = selected_sample_tasks * configuration_groups * repetitions`

## 5. Task Definition Model

Tasks come from the sample manifest.

Each sample may define `tasks[]` with:

- `task_id`
- `name`
- `query`
- `target_tools`
- `expected_evidence`
- `acceptance_targets`
- `tags`

If `tasks[]` is absent, the harness synthesizes one `default_analysis` task from `default_query`.

The maintained experimental corpus uses explicit tasks so sweep behavior stays stable and interpretable.

## 6. Judging And Scoring

The binary judge is driven by:

- rubric: `Testing/config/binary_judge_rubric.json`
- prompt: `Testing/config/prompts/binary_judge_prompt.md`
- implementation: `Testing/harness/judge.py`

The continuous score is:

- `overall_score_0_to_100`

The legacy `70/100` pass threshold still exists for binary pass/fail interpretation, but sweep comparison should rely primarily on:

- score deltas
- success/error rates
- significance outputs

The harness now treats these outcomes as first-class:

- `completed`
- `validator_blocked`
- `analysis_error`
- `no_result`
- `judge_error`

Those outcomes are preserved in run records and sweep aggregates instead of silently disappearing.

## 7. Statistical Comparison

Sweep outputs now distinguish descriptive movement from statistically supported movement.

Supported comparison layers:

- replicate-level permutation testing when repeated runs exist
- paired-task sign-flip testing across matched sample-task pairs

The default confidence target is:

- `p <= 0.05` for 95% confidence

Repetition is still useful for stronger claims, but the harness can now produce limited significance outputs even for repetition-1 sweeps when enough matched tasks exist.

## 8. Outputs

### Single Runs

Single-run outputs live under:

```text
Testing/results/runs/<run_id>/
```

Canonical machine-readable files:

- `run_manifest.json`
- `aggregate.json`
- `summary.csv`

Inspection-first filesystem view:

```text
by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/
```

### Sweeps

Sweep outputs live under:

```text
Testing/results/experiments/<experiment_id>/
```

Important files:

- `variant_summary.csv`
- `task_comparison.csv`
- `difficulty_summary.csv`
- `significance_overall.csv`
- `variable_significance_summary.csv`
- `lineage_summary.csv`
- `outputs/*.png`
- `outputs/task_output_comparisons/`
- `by_executable/`

### Cross-Run Configuration Grouping

Equivalent configurations are grouped by stable:

- `config_lineage_id`

Persistent lineage outputs live under:

```text
Testing/results/lineages/
```

This is the supported way to accumulate repetitions over time across separate sweeps.

## 9. Timing

Timing is tracked per sample-task record:

- `analysis_duration_sec`
- `judge_duration_sec`
- `total_duration_sec`
- `task_wall_clock_duration_sec`

Sweep aggregation then summarizes timing by:

- configuration
- sample-task
- task tag/category
- difficulty
- technique bucket

## 10. Current Contributor Workflow

### Quickstart

```bash
make all-exes
python Testing/prepare_bundles.py --corpus experimental
python Testing/run_launch_doctor.py
python Testing/run_launch_preset.py --preset paid_narrow_pilot --judge-model openai:gpt-4o-mini --preflight-only
```

If you only want to validate bundle freshness/completeness for a narrowed scope, use:

```bash
python Testing/run_launch_doctor.py --corpus experimental --bundle-only --show-bundle-details
```

### First Narrow Paid Run

```bash
python Testing/run_launch_preset.py \
  --preset paid_narrow_pilot \
  --judge-model openai:gpt-4o-mini
```

### Safer First Sweep

```bash
python Testing/run_experiment_sweep.py \
  --corpus experimental \
  --repetitions 1 \
  --judge-model openai:gpt-4o-mini
```

## 11. Source-Code Track Status

`Testing/C_Source_Evaluation/` remains valuable, but it is not yet an active automated runner.

What exists there today:

- generated datasets
- prompt libraries
- JSON templates
- dataset manifest

What does **not** exist yet:

- a maintained source-eval runner comparable to the binary harness

So the source-code track should currently be treated as a scaffold for future work, not as part of the active automated sweep system.

## 12. What Is Not In Scope Today

The maintained harness does **not** currently provide first-class support for:

- full architecture-matrix sweeps across every repo preset
- dedicated presweep on/off sweeps
- role-selective model assignment families
- worker concurrency sweep families
- tool-free binary evaluation
- a dedicated automated source-code runner

Those may still be useful future experiments, but they are not part of the supported current workflow and should not be implied by the docs.
