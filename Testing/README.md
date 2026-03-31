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
python Testing/run_experiment_sweep.py --corpus experimental
python Testing/run_launch_doctor.py
python Testing/prepare_bundles.py --corpus experimental
python Testing/render_test_catalog.py --corpus experimental
```

## Current Sweep Dimensions

The maintained default sweep is defined in [Testing/config/experiment_sweeps.json](config/experiment_sweeps.json).

It currently studies these one-variable-at-a-time families:

- `query_verbosity`
- `worker_subagents`
- `worker_persona_prompt`
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

## Extension Guides

- [multi_agent_wf/extension_tutorial.md](../multi_agent_wf/extension_tutorial.md): workflow/dashboard extension map and how new pipeline or architecture options flow into testing
- [START_HERE.md](START_HERE.md): how to run the suite end to end
- [TESTING_PLAN.md](TESTING_PLAN.md): current evaluation design
- [config/README.md](config/README.md): how to add sweep variables, prompts, and guardrails
- [Experimental_Test_Source/README.md](Experimental_Test_Source/README.md): how to add samples and tasks
- [Prototype_Test_Source/README.md](Prototype_Test_Source/README.md): prototype smoke corpus notes
