# Testing Config Guide

JSON config files in this directory are the main extension surface for the testing harness.

Because JSON does not support comments, treat this file as the lightweight guide for what each config controls and how to extend it safely.

If you are extending the workflow/dashboard itself, start with
[multi_agent_wf/extension_tutorial.md](../../multi_agent_wf/extension_tutorial.md)
first, then return here to wire the new option into sweep configs or launch
presets.

## File Roles

- `binary_judge_rubric.json`
  - source of truth for binary judging dimensions, weights, and pass thresholds
  - the judge and reporting layers load this directly
- `experiment_sweeps.json`
  - baseline plus one-variable-at-a-time sweep definition
  - used when you run `Testing/scripts/run_experiment_sweep.py` directly
  - this is the maintained generic sweep config, not a named preset
- `response_scope_variants.json`
  - response-scope wrappers such as `default`, `brief`, and `detailed`
- `analysis_hint_variants.json`
  - optional verify-first hint wrappers intended for pilot studies
- `tool_profiles.json`
  - named MCP tool-availability profiles for ablations
- `budget_guardrails.json`
  - launch-time token, cost, and spend ceilings
- `presets/`
  - one JSON file per named operational preset
  - this is the maintained preset surface used by
    `Testing/scripts/run_launch_preset.py`
- `model_cost_profiles.json`
  - local relative-cost and optional USD heuristics used for reporting
- `prompts/binary_judge_prompt.md`
  - the judge prompt template used with the rubric

## Presets Versus Sweep Configs

There are now two distinct concepts:

- `Testing/config/presets/*.json`
  - predefined runnable presets
  - each JSON file is one preset
  - sweep presets are self-contained and include their own `baseline`,
    `repetitions`, and `sweeps`
- `Testing/config/experiment_sweeps.json`
  - the generic direct-sweep config used when you invoke
    `Testing/scripts/run_experiment_sweep.py` without a named preset

This keeps named operational presets browsable in one folder while still
preserving one generic sweep config for direct ad hoc experiment launches.

## Add A New Sweep Dimension

Edit [experiment_sweeps.json](experiment_sweeps.json).

Rules:

1. Keep the baseline explicit.
2. Add only one changed variable family per sweep block.
3. Use `baseline_overrides` only when a family needs a different local comparison baseline.
4. Keep variant names stable, because they flow into run labels and reports.

Minimal pattern:

```json
{
  "variable": "new_dimension",
  "description": "What this changes while holding the rest fixed.",
  "variants": [
    {
      "name": "variant_a",
      "overrides": {
        "some_field": "value_a"
      }
    }
  ]
}
```

If the new field is a run-level knob, also wire it through:

- [Testing/harness/runner.py](../harness/runner.py)
- [Testing/harness/preflight.py](../harness/preflight.py)
- reporting only if it should appear in summaries

## Add A New Tool-Availability Profile

Edit [tool_profiles.json](tool_profiles.json).

Use:

- `full` as the unconstrained baseline
- `disabled_servers` for subtractive ablations

Prefer tool profiles when studying MCP/tool availability instead of creating ad hoc architecture presets.

## Add A New Response-Scope Variant

Edit [response_scope_variants.json](response_scope_variants.json).

Each variant wraps the base task query as:

`prefix + base_query + suffix`

Keep these variants small and mechanical. If a change is really a role/persona or workflow change, do not encode it here.

## Add A New Analysis-Hint Variant

Edit [analysis_hint_variants.json](analysis_hint_variants.json).

These wrappers are for future pilot studies that add generic, verify-first
investigation leads without asserting that a behavior is present. Keep them:

- conservative
- evidence-seeking
- explicit about verification rather than assumption

## Add Or Change The Binary Rubric

Edit [binary_judge_rubric.json](binary_judge_rubric.json).

The current harness derives dimension fields from this rubric, so the safe order is:

1. update the rubric
2. verify judge prompt still matches it
3. run preflight
4. inspect one judged run before broad sweeps

Do not hardcode rubric field names elsewhere unless absolutely necessary.

## Adjust Budget / Launch Safety

Edit [budget_guardrails.json](budget_guardrails.json) when you want to change:

- per-run ceilings
- experiment ceilings
- projected-cost heuristics
- judge-model requirements

Budget naming note:

- `max_run_estimated_cost_usd` and `max_experiment_estimated_cost_usd`
  - advisory warning thresholds
  - shown in doctor output, preflight warnings, and `budget_status.json`
  - do not abort a started run or sweep by themselves
- `hard_max_run_estimated_cost_usd` and `hard_max_experiment_estimated_cost_usd`
  - explicit hard-stop ceilings for estimated USD cost
  - use these only when you intentionally want estimated-cost abort behavior
- token ceilings and relative-cost-index ceilings remain hard guardrails when their abort flags are enabled

Use `Testing/config/presets/*.json` for named operational entry points, not
for generic sweep definitions.

A preset can target either:

- `runner: "single_run"`
  - good for default baselines and targeted one-configuration comparisons
  - supports run-level overrides such as `pipeline`, `architecture`,
    `response_scope_variant`, `analysis_hint_variant`, `tool_profile`, `validator_review_level`, and
    `force_model`
- `runner: "sweep"`
  - good for one-variable-at-a-time studies or broad full-suite launches
  - supports sweep-scoping fields such as `repetitions`, `samples`, `tasks`,
    `difficulty_filters`, and the embedded `baseline`/`sweeps` plan
  - for maintained presets, the preset file itself is the sweep config passed
    to `run_experiment_sweep.py`

If a preset should buffer child output by default when launched through
`run_launch_preset.py`, set `quiet_child_output: true` in the preset entry.

Remember that `tasks` in a launch preset are global task-id filters across the
selected samples. If you want a curated multi-sample scope, prefer unique
focused task IDs instead of mixing many `default_analysis` selections.

## Final-Round Evaluation Scaffold

The repo now includes a runnable repo-local final-run scaffold:

- [../sources/final_round/sample_manifest.json](../sources/final_round/sample_manifest.json)
- [../sources/final_round/reference/](../sources/final_round/reference/)
- [../sources/final_round/evaluation/README.md](../sources/final_round/evaluation/README.md)
- [presets/thesis_final_eval_r3_100usd.json](presets/thesis_final_eval_r3_100usd.json)
- launch preset name: `thesis_final_eval_r3_100usd`

Important constraints:

- runtime sample filenames are intentionally opaque, for example `sample1.exe`
- evaluator-side family labels and reference material stay outside the model-visible runtime path
- the active held-out preset is intentionally locked to a single blind
  `default_analysis` task per sample so more of the budget can be spent on
  configuration comparisons
- the corpus is built from `Testing/sources/final_round/`, not staged from placeholder paths
- source-grounded references already live under `Testing/sources/final_round/reference/`
- the maintained judge consumes those checked-in JSON references as
  evaluator-only grounding during scoring
- this is a repo-local simulation corpus, not a live-malware transport mechanism
