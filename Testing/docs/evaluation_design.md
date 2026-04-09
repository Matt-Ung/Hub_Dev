# Evaluation Design

This document describes the testing system the repo actually supports today.

It is intentionally narrower than older versions of the plan. Historical ideas, ad hoc workflows, and speculative roadmap items were removed so this file stays aligned with the maintained harness.

## 1. Scope

`Testing/` currently exposes one maintained automated evaluation track:

1. **Binary-analysis track**
   - manifest-backed Windows PE corpora
   - artifact-backed bundle preparation
   - single runs, sweeps, recovery, merge, and results browsing
   - primary entry points:
     - `Testing/scripts/run_evaluation.py`
     - `Testing/scripts/run_experiment_sweep.py`
     - `Testing/scripts/run_launch_preset.py`
     - `Testing/scripts/run_launch_doctor.py`

Everything in this document refers to that active binary-analysis path.

## 2. Active Corpora

### Experimental Corpus

This is the benchmark corpus used for sweeps.

- source: `Testing/sources/experimental/`
- binaries: `Testing/build/experimental/`
- manifest: `Testing/sources/experimental/sample_manifest.json`

Current shape:

- `11` source programs
- `17` executable variants
- `33` manifest-defined sample-task pairs

The atomic evaluation unit is a **sample-task pair**, not just a sample.

### Prototype Corpus

This is a development smoke/regression corpus, not the main benchmark.

- source: `Testing/sources/prototype/`
- binaries: `Testing/build/prototype/`

Use it for:

- quick tool sanity checks
- smoke regression after workflow changes
- stripped/packed-path development checks

### Final-Round Held-Out Evaluation Corpus

The repo now includes a runnable held-out final corpus that is closer to an
actual thesis final run:

- active corpus manifest:
  - `Testing/sources/final_round/sample_manifest.json`
- opaque runtime samples:
  - `sample1.exe` through `sample5.exe`
- source-grounded evaluator references:
  - `Testing/sources/final_round/reference/`
- evaluator-side scoring notes:
  - `Testing/sources/final_round/evaluation/`

This corpus is final-round by design:

- the source code lives under `Testing/sources/final_round/`
- the build writes opaque outputs under `Testing/build/deepseek_final/output/`
- runtime analysis sees only opaque sample filenames and manifest-defined task metadata
- evaluator-side family labels and source-grounded references stay outside the runtime prompt path

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
| response-scope variant | `default` |
| analysis-hint variant | `default` |
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
| `response_scope` | `brief`, `detailed` |
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
  - one-repetition medium+hard broad-coverage preset that stays below the current 60 USD heuristic band by restricting the broad sweep to the response-scope, worker-subagent, and worker-prompt-shape families
- `sweep_decoder_depth_r3`
  - three-repetition combined decoder depth study over `config_decoder_test_stripped.exe` and `config_decoder_test_upx_stripped.exe`, trimmed to the single worker-subagent family so the current heuristic stays below 30 USD
- `sweep_decoder_depth_followups_r3`
  - same decoder-depth scope and repetitions, but reduced to worker prompt shape plus one validator-backed pipeline follow-up while keeping the original decoder-depth baseline unchanged
- `thesis_final_eval_r3_100usd`
  - held-out five-sample final-evaluation scaffold
  - one blind `default_analysis` pass per sample and three repetitions
  - widened to worker breadth, worker prompt shape, response scope, and
    architecture follow-ups while staying interpretable
  - projects near `52.5 USD` under the current `0.50` per sample-task heuristic,
    with a `100 USD` advisory target and a higher hard-stop ceiling to absorb
    moderate retry or token-usage variance

Check the real plan before launching:

```bash
python Testing/scripts/run_experiment_sweep.py --plan-only
```

### Broad Coverage Versus Final Evaluation

The repo should distinguish three levels of evidence:

1. **Development / pilot runs**
   - used to debug workflow, judging, recovery, and reporting
2. **Broad-coverage realism checks**
   - wider sample-family testing, potentially using analyst-supplied malware in
     a controlled lab
   - useful for stress-testing external validity, but not sufficient by
     themselves for the strongest thesis claims
3. **Final held-out evaluation run**
   - final locked sample set, final configuration choices, and final reporting
     language
   - this is the run that should carry the main thesis-grade claims

The intended final preset structure is deliberately selective rather than
exhaustive:

- baseline
- `worker_subagents:single_generalist`
- `worker_prompt_shape:artifact_focused`
- `worker_prompt_shape:empty`
- `response_scope:brief`
- `architecture_preset:ghidra_focused`
- `architecture_preset:model_augmented`

This keeps the final run interpretable while still using the freed task budget
to compare a broader set of development-informed conditions on a held-out
sample set. The goal is not to rerun the full ablation space, but to widen the
final comparison enough to make the single-task held-out run more informative.

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
- `case_index.csv`

Canonical task artifacts:

```text
cases/<sample>/<task>/
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
- `config_group_summary.csv`
- `case_index.csv`
- `outputs/*.png`
- `outputs/task_output_comparisons/`

### Configuration Grouping

Equivalent configurations are grouped by stable:

- `config_lineage_id`

This is a deterministic configuration fingerprint carried in run and experiment
artifacts so repeated runs with the same knobs group together cleanly inside a
single experiment. The harness no longer maintains a separate global lineage
store under `Testing/results/`.

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
python Testing/scripts/prepare_bundles.py --corpus experimental
python Testing/scripts/run_launch_doctor.py
python Testing/scripts/run_launch_preset.py --preset sanity_core_slice_r1 --judge-model openai:gpt-4o-mini --preflight-only
```

If you only want to validate bundle freshness/completeness for a narrowed scope, use:

```bash
python Testing/scripts/run_launch_doctor.py --corpus experimental --bundle-only --show-bundle-details
```

### First Narrow Paid Run

```bash
python Testing/scripts/run_launch_preset.py \
  --preset sanity_core_slice_r1 \
  --judge-model openai:gpt-4o-mini
```

### Safer First Sweep

```bash
python Testing/scripts/run_experiment_sweep.py \
  --corpus experimental \
  --repetitions 1 \
  --judge-model openai:gpt-4o-mini
```

## 11. What Is Not In Scope Today

The maintained harness does **not** currently provide first-class support for:

- full architecture-matrix sweeps across every repo preset
- dedicated presweep on/off sweeps
- role-selective model assignment families
- worker concurrency sweep families
- tool-free binary evaluation
- a dedicated automated source-code runner

Those may still be useful future experiments, but they are not part of the supported current workflow and should not be implied by the docs.
