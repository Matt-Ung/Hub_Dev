# Testing Config Guide

JSON config files in this directory are the main extension surface for the testing harness.

Because JSON does not support comments, treat this file as the lightweight guide for what each config controls and how to extend it safely.

If you are extending the workflow/dashboard itself, start with
[multi_agent_wf/extension_tutorial.md](../../multi_agent_wf/extension_tutorial.md)
first, then return here to wire the new option into sweeps or launch presets.

## File Roles

- `binary_judge_rubric.json`
  - source of truth for binary judging dimensions, weights, and pass thresholds
  - the judge and reporting layers load this directly
- `experiment_sweeps.json`
  - baseline plus one-variable-at-a-time sweep definition
  - this is the source of truth for the default automated sweep
- `query_variants.json`
  - prompt wrappers such as `default`, `brief`, and `detailed`
- `tool_profiles.json`
  - named MCP tool-availability profiles for ablations
- `budget_guardrails.json`
  - launch-time token, cost, and spend ceilings
- `launch_presets.json`
  - named operational presets such as the recommended paid pilot
- `model_cost_profiles.json`
  - local relative-cost and optional USD heuristics used for reporting
- `prompts/binary_judge_prompt.md`
  - the judge prompt template used with the rubric

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

## Add A New Query Variant

Edit [query_variants.json](query_variants.json).

Each variant wraps the base task query as:

`prefix + base_query + suffix`

Keep these variants small and mechanical. If a change is really a role/persona or workflow change, do not encode it here.

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

Use [launch_presets.json](launch_presets.json) for named operational entry points, not for scientific sweep definitions.
