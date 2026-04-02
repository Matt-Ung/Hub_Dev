# Testing Results Directory

`Testing/results/` stores structured outputs from the unified evaluation runner.

If you only need the shortest path for later analysis, start here:

1. single run:
   - `aggregate.json`
   - `summary.csv`
   - `samples/<sample_task_slug>/record.json`
2. sweep:
   - `variant_summary.csv`
   - `task_comparison.csv`
   - `significance_overall.csv`
   - `outputs/`

Main sweep aggregates now exclude incomplete comparison groups by default. If a
sweep is interrupted or some variants only finish partially, those rows are
written separately as `partial_*.csv`, `partial_comparison.json`,
`partial_report.md`, and `outputs/partial/`.

Everything else in this tree should be read as either a derived inspection view
or an operational/debug artifact.

## Source-Control Policy

This directory mixes tracked documentation with generated result trees.

- Tracked by default:
  - `README.md`
  - `run_record_template.md`
  - `reference_examples/`
- Gitignored by default:
  - `doctor/`
  - `catalog/`
  - `lineages/`
  - `runs/`
  - `experiments/`

If you want to keep a specific result artifact in git, copy or distill it into
`reference_examples/` instead of committing the live generated run tree.

To reset generated run state locally while preserving tracked docs/templates,
use:

```bash
bash Testing/clean_results.sh
```

Add `--include-catalog` to also remove generated benchmark catalog outputs, or
`--include-logs` to remove generated `logs/agentToolBench_*` folders as well.

## Active Layout

```text
results/
  doctor/
    <doctor_id>/
      doctor_report.json
  lineages/
    index.json
    <config_lineage_id>.json
  catalog/
    <corpus>/
      benchmark_catalog.html
      benchmark_catalog.md
      catalog.json
      samples.csv
      tasks.csv
      query_variants.csv
      sweep_dimensions.csv
      task_dimension_matrix.csv
  runs/
    <run_id>/
      run_manifest.json
      live_status.json
      build_record.json
      prepare_record.json
      bundle_readiness.json
      preflight.json
      aggregate.json
      result_layout.json
      summary.csv
      report.md
      by_executable/
        index.json
        index.csv
        <exe_name>/
          <config_lineage_id>/
            metadata.json
            aggregate_summary.json
            tasks/
              <task_id>/
                metadata.json
                aggregate_summary.json
                runs/
                  run_001/
                    metadata.json
                    agent_raw_output.md
                    agent_result.json
                    judge_scorecard.json
                    judge_reasoning.md
                    judge_result.json
                    record.json
      samples/
        <sample_task_slug>/
          agent_result.json
          judge_result.json
          record.json
  experiments/
    <experiment_id>/
      experiment_manifest.json
      run_catalog.json
      run_catalog.csv
      live_view/
        index.html
        live_view_url.txt
        logs/
          <run_id>.log
      preflight.json
      comparison.json
      partial_comparison.json
      result_layout.json
      variant_summary.csv
      partial_variant_summary.csv
      dimension_summary.csv
      partial_dimension_summary.csv
      task_comparison.csv
      partial_task_comparison.csv
      difficulty_summary.csv
      partial_difficulty_summary.csv
      technique_summary.csv
      partial_technique_summary.csv
      lineage_summary.csv
      significance.json
      significance_overall.csv
      significance_by_difficulty.csv
      significance_by_task.csv
      variable_significance_summary.csv
      significance_report.md
      report.md
      partial_report.md
      by_executable/
        index.json
        index.csv
        <exe_name>/
          <config_lineage_id>/
            metadata.json
            aggregate_summary.json
            tasks/
              <task_id>/
                metadata.json
                aggregate_summary.json
                runs/
                  run_001/
                    metadata.json
                    agent_raw_output.md
                    agent_result.json
                    judge_scorecard.json
                    judge_reasoning.md
                    judge_result.json
                    record.json
      outputs/
        *.png
        task_timing_individual.csv
        task_timing_summary.csv
        task_tag_timing_summary.csv
        variant_timing_summary.csv
        timing_report.md
        task_output_comparisons/
          index.html
          index.md
          comparison_manifest.json
          all_rows.csv
          task_variant_summary.csv
          tasks/
            *.html
            *.md
```

## How Results Are Produced

Run:

```bash
python Testing/run_evaluation.py --corpus experimental
```

To generate a static catalog of the benchmark surface without running agent calls:

```bash
python Testing/render_test_catalog.py --corpus experimental
```

That writes a browsable HTML/Markdown summary under `Testing/results/catalog/<corpus>/` so you can inspect samples, manifest-defined tasks, prompt/query variants, and sweep families before launching runs.

For baseline + one-variable-at-a-time sweeps, run:

```bash
python Testing/run_experiment_sweep.py --corpus experimental
```

For a lightweight local browser monitor during the sweep:

```bash
python Testing/run_experiment_sweep.py --corpus experimental --live-view
```

That will:

1. build binaries into `Testing/build/<corpus>/`
2. prepare bundles into `Testing/generated/bundles/<corpus>/`
3. resolve the manifest-defined sample-task evaluation set
4. execute the analysis workflow
5. run the agent-based judge
6. write per-sample-task and aggregate outputs here

## Important Files

Read this section in three buckets instead of treating every artifact as equally
important.

### Canonical machine-readable outputs

These are the files later analysis should usually start from:

- `run_manifest.json`
- `aggregate.json`
- `summary.csv`
- `samples/<sample_task_slug>/agent_result.json`
- `samples/<sample_task_slug>/judge_result.json`
- `samples/<sample_task_slug>/record.json`
- `variant_summary.csv`
- `task_comparison.csv`
- `significance_overall.csv`

### Inspection-oriented mirrors and convenience views

These are useful for browsing and manual review, but they are mostly derived
from the canonical outputs above:

- `result_layout.json`
- `by_executable/`
- `report.md`
- `outputs/*.png`
- `outputs/task_output_comparisons/`
- `lineage_summary.csv`

### Operational / debug / preflight artifacts

These explain how a run was prepared or what happened while it was executing.
They are valuable when something goes wrong, but they are not the first place
to start for normal experiment analysis:

- `build_record.json`
- `prepare_record.json`
- `bundle_readiness.json`
- `preflight.json`
- `live_status.json`
- `live_view/`
- `doctor_report.json`
- `summary.csv` — one row per sample-task for quick comparison across runs
- `report.md` — compact human-readable report
- `by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/agent_raw_output.md` — raw final report text for a specific executable/config/task/run
- `by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/judge_scorecard.json` — structured judge score breakdown for that run
- `by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/runs/run_###/judge_reasoning.md` — judge narrative / justification for that run
- `by_executable/<exe>/<config_lineage_id>/aggregate_summary.json` — config-level aggregate for one executable within a run or experiment
- `by_executable/<exe>/<config_lineage_id>/tasks/<task_id>/aggregate_summary.json` — task-level aggregate across replicated runs within that executable/config folder
- `comparison.json` — experiment-level baseline vs variant deltas
- `partial_comparison.json` — incomplete or interrupted comparison groups kept separate from the main aggregate outputs
- `live_view/live_view_url.txt` — local browser URL for the live progress monitor
- `live_view/logs/<run_id>.log` — streamed child-run output captured for the live monitor
- `lineage_summary.csv` — experiment-local view of the persistent configuration lineage groups touched by this sweep
- `variant_summary.csv` — one row per configuration variant in a sweep
- `partial_variant_summary.csv` — incomplete or interrupted configuration rows excluded from the main aggregate summary
- `task_comparison.csv` — per-sample-task comparison table across variants
- `outputs/task_timing_individual.csv` — one row per completed sample-task record with timing fields preserved
- `outputs/task_timing_summary.csv` — timing aggregated by configuration and sample-task across replicate runs
- `outputs/task_tag_timing_summary.csv` — timing aggregated by configuration and task tag/category
- `outputs/variant_timing_summary.csv` — timing aggregated by configuration variant
- `outputs/timing_report.md` — quick narrative timing summary
- `significance_overall.csv` — replicate-level significance test for overall score shifts versus the configured comparison baseline
- `significance_by_difficulty.csv` — the same significance test broken down by difficulty bucket
- `significance_by_task.csv` — per-sample-task significance rows
- `paired_task_significance_overall.csv` — matched-task sign-flip significance test that works even for repetition-1 sweeps
- `paired_task_significance_by_difficulty.csv` — paired-task significance broken down by difficulty
- `variable_significance_summary.csv` — summary table showing which changed-variable families produced statistically significant improvements or degradations
- `significance_report.md` — human-readable explanation of the statistical test configuration and outcome table
- `outputs/*.png` — generated comparison visuals
- `outputs/partial/*.png` — clearly labeled visuals for incomplete or interrupted comparison groups
- `outputs/task_output_comparisons/index.html` — browsable per-task comparison view of the actual agent outputs across configurations
- `outputs/task_output_comparisons/task_variant_summary.csv` — per-task, per-configuration summary with score, success, cost, and representative-run info
- `outputs/task_output_comparisons/all_rows.csv` — every captured sample-task output row across runs/replicates
- `doctor_report.json` — launch-readiness checklist covering deps, env, bundle integrity, and pilot-vs-broad budget status
- `benchmark_catalog.html` — easiest overview of samples, tasks, prompts, and tested dimensions
- `tasks.csv` — one row per manifest-defined sample-task with prompt variants
- `task_dimension_matrix.csv` — sample-task coverage against sweep families

Runs can now end in distinct analysis states:

- `completed`
- `validator_blocked`
- `analysis_error`
- `no_result`

If `bundle_readiness.json` shows missing required files such as `ghidra_analysis.json`, the run is now recorded as `analysis_error` with an explicit prerequisite message instead of failing later inside the artifact-backed Ghidra MCP path.

The new `by_executable/` view is intentionally additive. The original run-centric files under `samples/` remain the canonical machine-readable outputs used by the harness, while `by_executable/` is the inspection-oriented mirror that groups those artifacts by executable and stable configuration lineage id.

## What New Contributors Usually Need First

If you only need to answer “did this run work and how did it score?”, open:

1. `summary.csv`
2. `aggregate.json`
3. the matching `samples/<sample_task_slug>/record.json`

If you only need to answer “why did this run fail or behave strangely?”, open:

1. `preflight.json`
2. `bundle_readiness.json`
3. `live_status.json`
4. `live_view/logs/<run_id>.log` or `logs/agentToolBench_*`

## CSV Columns

Single-run `summary.csv` includes:

- `run_id`
- `corpus`
- `sample`
- `task_id`
- `task_name`
- `sample_task_id`
- `difficulty`
- `pipeline`
- `architecture`
- `query_variant`
- `subagent_profile`
- `worker_persona_profile`
- `worker_role_prompt_mode`
- `validator_review_level`
- `model_profile`
- `force_model`
- `judge_model`
- `analysis_status`
- `judge_status`
- `produced_result`
- `scored_result`
- `validator_blocked`
- `failure_reason`
- `judge_failure_reason`
- `overall_score_0_to_100`
- `judge_pass`
- `task_success`
- rubric dimension columns
- `tool_calls_total`
- `target_tool_hit_rate`
- `total_relative_cost_index`
- `tools_used`
- `analysis_duration_sec`
- `judge_duration_sec`
- `total_duration_sec`
- `task_wall_clock_duration_sec`

Experiment outputs add:

- baseline vs variant score deltas
- family-baseline vs variant score deltas for validator sweeps
- task success-rate deltas
- produced-result / validator-blocked / analysis-error outcome rates
- judge-error and scored-result rates
- repetition completion counts and completion rates per configuration
- rubric-dimension deltas
- cost/performance comparison metrics
- difficulty- and technique-level summaries
- task-tag/category timing summaries
- persistent configuration lineage summaries
- repetition counts and merged replicate aggregates
- coverage metadata separating fully covered comparisons from partial/incomplete rows

The default v6 sweep plans 21 configuration groups and runs each group 3 times unless `--repetitions` overrides the config default.

Generated visuals now include:

- absolute baseline-vs-variant score and task-success charts
- delta-first score and task-success charts
- family-grouped score-delta chart for within-variable comparisons
- significance markers on the score-delta charts so statistically credible changes stand out from descriptive-only deltas
- run outcome rates
- cost vs performance
- variable-impact summary
- rubric-dimension delta heatmap
- per-sample-task score and success-rate heatmaps
- mean completion-time by configuration
- per-sample-task completion-time heatmap
- task-category completion-time heatmap
- per-sample-task significance-status heatmap
- per-difficulty significance-status heatmap
- difficulty-band and technique-bucket delta heatmaps

Sweep preflight now also checks for the chart dependencies required to create these PNGs. If `matplotlib` or `pandas` are missing in the interpreter that launches the sweep, preflight fails unless you pass `--skip-visuals`.

The `task_output_comparisons/` bundle does not depend on `matplotlib`. It is still generated on sweep runs even when you pass `--skip-visuals`.

There is no dedicated model-cost sweep variable in the default config anymore. Cost summaries are derived from actual model usage captured during each run.

Aggregate means now treat judge-error records as zero-equivalent failures rather than silently dropping them from score averages. This is intentional: a run with incomplete judging should not look artificially stronger just because some outputs were left unscored.

Bundle integrity now distinguishes between:

- missing required files
- present but stale bundles

The bundle freshness check is based on the current binary identity plus the current Ghidra headless export script/preparer version. Prompt-only changes, including worker persona overlays or worker role prompt mode changes, do not invalidate bundles.

Statistical significance now uses a two-sided permutation test over replicate-level score series. The default interpretation target is 95% confidence, which corresponds to `p <= 0.05`, not `p >= 0.95`. When repetitions are too small to support a credible test, the significance rows are still written but marked `insufficient_repetitions`.

The framework also writes a second, cheaper significance basis: a paired across-task sign-flip test. That test compares each variant to its baseline over matched sample-task score deltas within the same sweep and is useful when you only ran one repetition per configuration. It supports overall and per-difficulty inference, but it does not replace replicate-based per-task significance.

## Notes

Experiment-level comparisons now live under `Testing/results/experiments/`, while individual run outputs remain under `Testing/results/runs/`.
