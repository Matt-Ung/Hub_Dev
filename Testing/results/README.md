# Testing Results

`Testing/results/` stores only the active canonical run format, experiment
aggregates, and local UI state.

## Mental Model

- `runs/`
  Standalone one-off evaluations launched directly with `run_evaluation.py`.
- `experiments/`
  Multi-run sweeps. Each experiment owns its child runs, summaries, logs, and charts.
- `doctor/`
  Launch-readiness reports.
- `preflight/`
  Preflight-only sweep scaffolds. These are planning and readiness artifacts,
  not real executed experiments.
- `catalog/`
  Static benchmark catalogs.

Legacy result trees are no longer kept here. Old-format outputs now live under:

```text
Testing/archive/results_legacy/
```

and are inspected only through the archive browser.

The canonical raw task outputs now live under:

```text
cases/<sample>/<task>/
```

The old mirrored `by_executable/` tree is gone from the active layout. The
additive inspection artifact is now a flat:

```text
case_index.json
case_index.csv
```

that points at the canonical case directories.

## Active Layout

```text
results/
  runs/
    <run_id>/
      run_manifest.json
      live_status.json
      build_record.json
      prepare_record.json
      bundle_readiness.json
      preflight.json
      aggregate.json
      budget_status.json
      summary.csv
      report.md
      result_layout.json
      case_index.json
      case_index.csv
      logs/
        run.log
        tasks/
          <sample>/
            <task>.log
      cases/
        <sample>/
          <task>/
            agent_result.json
            judge_result.json
            record.json
            attempts/
              attempt_01/
                agent_result.json
  experiments/
    <experiment_id>/
      experiment_manifest.json
      run_catalog.json
      run_catalog.csv
      preflight.json
      comparison.json
      partial_comparison.json
      variant_summary.csv
      partial_variant_summary.csv
      task_comparison.csv
      partial_task_comparison.csv
      difficulty_summary.csv
      partial_difficulty_summary.csv
      technique_summary.csv
      partial_technique_summary.csv
      config_group_summary.csv
      significance_overall.csv
      significance_by_difficulty.csv
      significance_by_task.csv
      variable_significance_summary.csv
      significance_report.md
      report.md
      partial_report.md
      result_layout.json
      case_index.json
      case_index.csv
      runs/
        <variant_id>/
          r001/
            ...same run layout as above...
          r002/
            ...
      outputs/
        *.png
        task_output_comparisons/
        partial/
      live_view/
        index.html
        live_view_url.txt
  preflight/
    <preflight_id>/
      experiment_manifest.json
      run_catalog.json
      build_record.json
      prepare_record.json
      preflight.json
      cost_projection.json
```

## Where To Look

For one task run:

1. `cases/<sample>/<task>/record.json`
2. `cases/<sample>/<task>/agent_result.json`
3. `cases/<sample>/<task>/judge_result.json`
4. `logs/tasks/<sample>/<task>.log`

For one run:

1. `aggregate.json`
2. `summary.csv`
3. `case_index.csv`
4. `logs/run.log`

For one experiment:

1. `variant_summary.csv`
2. `task_comparison.csv`
3. `run_catalog.csv`
4. `case_index.csv`
5. `outputs/`

For one preflight-only preset or sweep:

1. `Testing/results/preflight/<preflight_id>/preflight.json`
2. `Testing/results/preflight/<preflight_id>/cost_projection.json`
3. `Testing/results/preflight/<preflight_id>/prepare_record.json`

## Commands

Single run:

```bash
python Testing/scripts/run_evaluation.py --corpus experimental
```

Sweep:

```bash
python Testing/scripts/run_experiment_sweep.py --corpus experimental
```

Live monitor:

```bash
python Testing/scripts/run_experiment_sweep.py --corpus experimental --live-view
```

Active results browser:

```bash
python Testing/scripts/run_results_browser.py
```

Archive-only results browser:

```bash
python Testing/archive/run_archive_results_browser.py
```

Reset generated results:

```bash
bash Testing/scripts/clean_results.sh
```
