# Workflow Extension Tutorial

This guide is the repo-specific extension map for `multi_agent_wf/`.

It is written to be used side-by-side with the real code. Every section points
to the exact files that currently define, load, render, or test workflow
options in this repo.

## Tutorial 0: Orientation

### Tutorial 0.1: Runtime Path

The live path through the workflow system is:

```text
multi_agent_wf/main.py
  -> multi_agent_wf/config.py
  -> multi_agent_wf/frontend.py
  -> multi_agent_wf/runtime.py
  -> multi_agent_wf/pipeline.py
```

The config source of truth is:

```text
multi_agent_wf/workflow_config/
```

The current responsibilities are:

- [workflow_config_loader.py](workflow_config_loader.py)
  - validates and normalizes workflow JSON
- [config.py](config.py)
  - loads env defaults and exposes normalized workflow config
- [frontend.py](frontend.py)
  - renders dropdowns, knobs, and stage/log panels
- [runtime.py](runtime.py)
  - turns config into stage managers, worker agents, and tool partitions
- [pipeline.py](pipeline.py)
  - executes the stage flow

### Tutorial 0.2: Extension Surface Map

| Extension area | Main files | Notes |
|---|---|---|
| Pipeline presets | [workflow_config/pipeline_presets.json](workflow_config/pipeline_presets.json), [workflow_config_loader.py](workflow_config_loader.py), [config.py](config.py), [frontend.py](frontend.py) | Preset names auto-appear in the pipeline dropdown. |
| Stage kinds | [workflow_config/stage_kind_metadata.json](workflow_config/stage_kind_metadata.json), [workflow_config/stage_manager_prompts.json](workflow_config/stage_manager_prompts.json), [workflow_config/stage_output_contracts.json](workflow_config/stage_output_contracts.json), [runtime.py](runtime.py), [pipeline.py](pipeline.py) | This is the least forgiving extension path. |
| Architecture presets | [workflow_config/architecture_presets.json](workflow_config/architecture_presets.json), [workflow_config_loader.py](workflow_config_loader.py), [frontend.py](frontend.py), [runtime.py](runtime.py) | Preset names auto-appear in the architecture dropdown. |
| New roles/archetypes | [workflow_config/agent_archetype_specs.json](workflow_config/agent_archetype_specs.json), [workflow_config/agent_archetype_prompts.json](workflow_config/agent_archetype_prompts.json), [workflow_config/base_prompts.json](workflow_config/base_prompts.json), [runtime.py](runtime.py) | Required when a new architecture references a role that does not already exist. |
| New dashboard knobs | [config.py](config.py), [frontend.py](frontend.py), usually [runtime.py](runtime.py) or [pipeline.py](pipeline.py) | Needed only for brand new controls, not for new preset names. |
| Testing | [../Testing/config/experiment_sweeps.json](../Testing/config/experiment_sweeps.json), [../Testing/config/presets/](../Testing/config/presets/), [../Testing/harness/runner.py](../Testing/harness/runner.py), [../Testing/harness/experiment_sweep.py](../Testing/harness/experiment_sweep.py) | Only needed if the new workflow option should be benchmarked or launched via a named preset. |

### Tutorial 0.3: Key Rule

- New pipeline presets are usually config-first changes.
- New architecture presets are usually config-first changes.
- New `stage_kind` values are never config-only. If you add one, you must also
  update Python control flow. See [Tutorial 2](#tutorial-2-add-a-new-stage-kind).

## Tutorial 1: Add a New Pipeline Preset

Use this when you want a new ordered stage flow such as:

- adding a review stage between workers and reporter
- creating a cheaper no-validator pipeline
- creating a pipeline that reuses the selected worker architecture differently

If the preset uses only existing `stage_kind` values, this tutorial is usually
enough. If it introduces a new `stage_kind`, continue to
[Tutorial 2](#tutorial-2-add-a-new-stage-kind).

### Tutorial 1.1: Decide Whether a New Preset Is Enough

Use a new pipeline preset when:

- the change is mostly stage ordering or stage composition
- existing stage kinds already capture the behavior you want
- you do not need a new execution branch in [pipeline.py](pipeline.py)

Do not stop at Tutorial 1 if:

- you need a new `stage_kind`
- you need a stage with custom shared-state handling
- you need a stage with new prompt-shaping logic in [runtime.py](runtime.py)

### Tutorial 1.2: Edit workflow_config/pipeline_presets.json

File:
[workflow_config/pipeline_presets.json](workflow_config/pipeline_presets.json)

Role:
top-level source of truth for named pipeline presets

Edit type:
required

Expected schema:

- top-level object keyed by preset name
- each preset value is an object with:
  - `description`: string or string array
  - `stages`: array
- each stage entry uses:
  - `name`
  - `stage_kind`
  - `architecture`
  - `use_worker_architecture`
  - optional `model`

Tutorial 1.2 example JSON entry:

```json
{
  "EXAMPLE": {
    "description": [
      "EXAMPLE: this pipeline includes an example stage that uses a custom stage kind and does not reuse the worker architecture."
    ],
    "stages": [
      {
        "name": "EXAMPLE",
        "stage_kind": "EXAMPLE",
        "architecture": [["EXAMPLE", 1]],
        "use_worker_architecture": false,
        "model": "openai:gpt-5-nano"
      }
    ]
  }
}
```

How the example maps to the real file:

- `use_worker_architecture: true` on the `workers` stage means
  [config.py](config.py) will replace that stage’s `architecture` with the
  currently selected architecture preset
- the other stages keep their explicit `architecture` slot lists
- the preset name becomes available to the frontend automatically after the
  loader accepts the JSON

### Tutorial 1.3: Only Edit stage_manager_prompts.json If the Preset Needs a New Stage Kind or Prompt Variant

File:
[workflow_config/stage_manager_prompts.json](workflow_config/stage_manager_prompts.json)

Role:
manager-facing instructions keyed by `stage_kind`

Edit type:
conditional

Expected schema:

- top-level object keyed by `stage_kind`
- each value is a string or string array

Tutorial 1.3 example JSON entry:

```json
{
  "artifact_review": [
    "You are the artifact-review stage coordinator for a malware-analysis pipeline.",
    "",
    "Rules:",
    "- Review the worker bundle for completeness, redundancy, and missing concrete artifacts.",
    "- Do not perform broad new discovery or planner-style decomposition here."
  ]
}
```

How the example maps to the real file:

- [runtime.py](runtime.py) loads this through `PIPELINE_STAGE_MANAGER_PROMPTS`
- `build_stage_manager_instructions()` wraps this base text with generic stage
  metadata and capability rules

### Tutorial 1.4: Only Edit stage_output_contracts.json If the Preset Needs a New Stage Kind or Output Contract

File:
[workflow_config/stage_output_contracts.json](workflow_config/stage_output_contracts.json)

Role:
required output format keyed by `stage_kind`

Edit type:
conditional

Expected schema:

- top-level object keyed by `stage_kind`
- each value is a string or string array

Tutorial 1.4 example JSON entry:

```json
{
  "artifact_review": [
    "Produce a compact artifact review of the worker output.",
    "List supported claims, claims that need narrower wording, and the exact missing artifacts that block final reporting."
  ]
}
```

How the example maps to the real file:

- [runtime.py](runtime.py) injects this contract into `build_stage_prompt()`
- the stage manager sees it as the current stage output contract

### Tutorial 1.5: Frontend Behavior for New Pipeline Presets

Files:

- [frontend.py](frontend.py)
- [config.py](config.py)

Role:
the pipeline dropdown and stage log panel list are derived from loaded presets

Edit type:
usually no edit required

What actually happens:

- [frontend.py](frontend.py) builds `_PIPELINE_PRESET_CHOICES` from
  `DEEP_AGENT_PIPELINE_PRESETS`
- [config.py](config.py) derives `PIPELINE_LOG_SLOTS` from the configured stage
  names and stage kinds

So a valid new preset will usually:

- appear automatically in the dropdown
- create new stage log accordions automatically if it introduces a new stage
  name

### Tutorial 1.6: Add the Preset to Maintained Sweeps If You Want It Benchmarked

File:
[../Testing/config/experiment_sweeps.json](../Testing/config/experiment_sweeps.json)

Role:
source of truth for maintained one-variable-at-a-time experiment families

Edit type:
conditional

Expected schema:

- top-level `baseline`
- top-level `sweeps` array
- each sweep block contains:
  - `variable`
  - `description`
  - optional `baseline_overrides`
  - `variants`

Tutorial 1.6 example JSON block:

```json
{
  "sweeps": [
    {
      "variable": "pipeline_preset",
      "description": "EXAMPLE",
      "variants": [
        {
          "name": "EXAMPLE",
          "overrides": {
            "pipeline": "EXAMPLE"
          }
        }
      ]
    }
  ]
}
```

How the example maps to the real file:

- [../Testing/harness/experiment_sweep.py](../Testing/harness/experiment_sweep.py)
  expands this into one child run per variant
- [../Testing/harness/runner.py](../Testing/harness/runner.py) passes the
  selected `pipeline` through to the runtime

If your preset introduces a new stage kind, continue to
[Tutorial 2](#tutorial-2-add-a-new-stage-kind).

## Tutorial 2: Add a New Stage Kind

Use this only when you are creating a new `stage_kind`, such as
`artifact_review`.

This is the least forgiving extension path because it crosses JSON validation,
prompt assembly, and Python control flow.

### Tutorial 2.1: Register the Stage Flags in stage_kind_metadata.json

File:
[workflow_config/stage_kind_metadata.json](workflow_config/stage_kind_metadata.json)

Role:
declares orchestration flags for each `stage_kind`

Edit type:
required

Expected schema:

- top-level object keyed by `stage_kind`
- each value must contain all five booleans:
  - `tool_free`
  - `supports_parallel_assignments`
  - `finalizes_report`
  - `parses_planner_work_items`
  - `runs_validation_gate`

Tutorial 2.1 example JSON entry:

```json
{
  "artifact_review": {
    "tool_free": true,
    "supports_parallel_assignments": false,
    "finalizes_report": false,
    "parses_planner_work_items": false,
    "runs_validation_gate": false
  }
}
```

How the example maps to the real file:

- [config.py](config.py) exposes this through `get_stage_kind_metadata()`
- [pipeline.py](pipeline.py) uses these flags to decide orchestration behavior

### Tutorial 2.2: Add the Stage Manager Prompt

File:
[workflow_config/stage_manager_prompts.json](workflow_config/stage_manager_prompts.json)

Role:
manager instructions for the stage

Edit type:
required

Tutorial 2.2 example JSON entry:

```json
{
  "artifact_review": [
    "You are the artifact-review stage coordinator for a malware-analysis pipeline.",
    "",
    "Rules:",
    "- Review worker output for evidence quality, redundancy, and readiness for final reporting.",
    "- Do not perform broad new discovery or create a fresh plan."
  ]
}
```

How the example maps to the real file:

- loaded by [workflow_config_loader.py](workflow_config_loader.py)
- consumed by `build_stage_manager_instructions()` in [runtime.py](runtime.py)

### Tutorial 2.3: Add the Stage Output Contract

File:
[workflow_config/stage_output_contracts.json](workflow_config/stage_output_contracts.json)

Role:
declares what the stage must return

Edit type:
required

Tutorial 2.3 example JSON entry:

```json
{
  "artifact_review": [
    "Produce a compact artifact review of the worker bundle.",
    "List supported findings, findings that need narrower wording, and any missing artifacts that block final reporting."
  ]
}
```

How the example maps to the real file:

- `build_stage_prompt()` in [runtime.py](runtime.py) inserts this into the
  stage prompt automatically

### Tutorial 2.4: Add the New Stage to a Pipeline Preset

File:
[workflow_config/pipeline_presets.json](workflow_config/pipeline_presets.json)

Role:
actually places the new stage in a runnable flow

Edit type:
required

Tutorial 2.4 example JSON stage entry:

```json
{
  "name": "artifact_review",
  "stage_kind": "artifact_review",
  "architecture": [["reporting_analyst", 1]],
  "use_worker_architecture": false,
  "model": "openai:gpt-5-mini"
}
```

How the example maps to the real file:

- once this stage appears in a preset, the runtime can build a manager for it
- the stage still needs a matching execution branch in [pipeline.py](pipeline.py)

### Tutorial 2.5: Add the Execution Branch in pipeline.py

File:
[pipeline.py](pipeline.py)

Role:
actual stage execution semantics

Edit type:
required

Where to change:

- `run_deepagent_pipeline()`
- specifically the `while stage_index < len(runtime.stages):` loop

What to add:

- a new `elif stage.stage_kind == "artifact_review":` branch
- stage-specific execution and any shared-state updates

Tutorial 2.5 example Python branch:

```python
elif stage.stage_kind == "artifact_review":
    result = stage.agent.run_sync(
        stage_prompt,
        message_history=old_history if old_history else None,
        deps=stage.deps,
    )
```

How the example maps to the real code:

- use this when the stage is just a normal manager run
- if the stage needs a helper, add a helper near the existing stage helpers and
  call it from this branch
- keep error handling, cancellation checks, and status transitions aligned with
  the surrounding branches

### Tutorial 2.6: Only Add Prompt Shaping in runtime.py If JSON Is Not Enough

File:
[runtime.py](runtime.py)

Role:
assembles the stage prompt and stage runtime

Edit type:
conditional

Where to change:

- `build_stage_prompt()`

What to add:

- a new `elif stage_kind == "artifact_review":` block only if the stage needs
  runtime-derived context or special prompt shaping beyond the JSON prompt and
  contract

Tutorial 2.6 example Python block:

```python
elif stage_kind == "artifact_review":
    sections.extend(
        [
            "",
            "Artifact-review mode:",
            "- Focus on narrowing and evidence quality, not fresh discovery.",
        ]
    )
```

Do not move normal stage instructions out of JSON unless they truly depend on
runtime state.

### Tutorial 2.7: Only Add Frontend Logic If the Stage Needs a Special Panel

File:
[frontend.py](frontend.py)

Role:
dashboard panels, approval queues, and stage display logic

Edit type:
conditional

When you need this:

- the stage needs a custom panel like the validation gate or Ghidra queue
- the stage produces new shared-state structures that need their own renderer

When you do not need this:

- the stage only needs a normal stage-log accordion

Why:

- stage log accordions are already derived from `PIPELINE_LOG_SLOTS`

## Tutorial 3: Add a New Architecture Preset or Role

### Tutorial 3.1: Add a Preset That Uses Only Existing Roles

File:
[workflow_config/architecture_presets.json](workflow_config/architecture_presets.json)

Role:
named worker topology presets

Edit type:
required

Expected schema:

- top-level object keyed by preset name
- each value is an object with:
  - `description`
  - `slots`
- `slots` is an array of `[role_name, quantity]`

Tutorial 3.1 example JSON entry:

```json
{
  "decode_focused": {
    "description": [
      "Use when decoded strings and config recovery matter more than broad capability mapping."
    ],
    "slots": [
      ["triage_analyst", 1],
      ["ghidra_analyst", 1],
      ["string_analyst", 1],
      ["type_recovery_analyst", 1]
    ]
  }
}
```

How the example maps to the real file:

- [workflow_config_loader.py](workflow_config_loader.py) normalizes the slot list
- [frontend.py](frontend.py) auto-populates the architecture dropdown from the
  loaded preset names
- [runtime.py](runtime.py) expands the slot list into worker instances

If the new preset references a role that does not already exist, continue to
[Tutorial 3.2](#tutorial-32-add-a-new-role-spec).

### Tutorial 3.2: Add a New Role Spec

File:
[workflow_config/agent_archetype_specs.json](workflow_config/agent_archetype_specs.json)

Role:
declares role metadata and `tool_domain`

Edit type:
required when a new architecture references a new role

Expected schema:

- top-level object keyed by role name
- each value uses:
  - `description`
  - `tool_domain`
  - `preferred_mode`
  - `typical_complexity`
  - optional `model`

Tutorial 3.2 example JSON entry:

```json
{
  "decoder_analyst": {
    "description": "Static specialist focused on decode loops, config recovery, and decoded artifact interpretation.",
    "tool_domain": "static",
    "preferred_mode": "sync",
    "typical_complexity": "complex",
    "model": "openai:gpt-5-mini"
  }
}
```

How the example maps to the real file:

- [runtime.py](runtime.py) uses `tool_domain` to decide which MCP toolsets the
  role receives

### Tutorial 3.3: Add the Role Prompt

File:
[workflow_config/agent_archetype_prompts.json](workflow_config/agent_archetype_prompts.json)

Role:
prompt template for each role

Edit type:
required

Expected schema:

- top-level object keyed by role name
- each value contains:
  - `base`
  - optional `specialization`

Tutorial 3.3 example JSON entry:

```json
{
  "decoder_analyst": {
    "base": "static_agent_instructions",
    "specialization": [
      "Prioritize decode loops, decoded strings, config material, and key/value recovery.",
      "Connect each decoded artifact back to the exact function or data location that produces it."
    ]
  }
}
```

How the example maps to the real file:

- [workflow_config_loader.py](workflow_config_loader.py) resolves `base`
  against [workflow_config/base_prompts.json](workflow_config/base_prompts.json)

### Tutorial 3.4: Add a New Base Prompt Only If Existing Bases Do Not Fit

File:
[workflow_config/base_prompts.json](workflow_config/base_prompts.json)

Role:
reusable shared prompt families

Edit type:
conditional

Tutorial 3.4 example JSON entry:

```json
{
  "decoder_agent_instructions": [
    "You are DecoderAgent (reverse engineering specialist).",
    "",
    "Rules:",
    "- Focus on encoded or transformed data, decode loops, and recovered artifacts.",
    "- Tie decoded outputs back to exact code and data anchors."
  ]
}
```

Use this only when `static_agent_instructions` or `dynamic_agent_instructions`
cannot be specialized enough.

### Tutorial 3.5: Reference the New Role From an Architecture Preset

File:
[workflow_config/architecture_presets.json](workflow_config/architecture_presets.json)

Role:
puts the new role into a selectable worker topology

Edit type:
required

Tutorial 3.5 example JSON entry:

```json
{
  "decode_focused": {
    "description": [
      "Use when decoded config and transformed data matter more than broad capability mapping."
    ],
    "slots": [
      ["triage_analyst", 1],
      ["ghidra_analyst", 1],
      ["decoder_analyst", 1],
      ["type_recovery_analyst", 1]
    ]
  }
}
```

### Tutorial 3.6: Add a New tool_domain Mapping Only If the Role Needs One

File:
[runtime.py](runtime.py)

Role:
maps `tool_domain` strings to actual MCP toolset partitions

Edit type:
conditional

Where to change:

- `_toolsets_for_domain()`

Tutorial 3.6 example Python branch:

```python
if tool_domain == "decode_static":
    return list(static_tools)
```

Only add a new `tool_domain` if the existing choices are insufficient:

- `none`
- `preflight`
- `static`
- `dynamic`
- `all`

## Tutorial 4: Add a New Dashboard Workflow Knob

Use this only when you are adding a brand new user-selectable control such as a
new review-depth or routing knob.

Do not use Tutorial 4 for new pipeline or architecture preset names. Those
already auto-populate in the frontend.

### Tutorial 4.1: Add the Default and Normalization in config.py

File:
[config.py](config.py)

Role:
env loading, normalization, and runtime settings assembly

Edit type:
required

What to add:

- a normalizer helper if the value needs one
- a default in `_build_runtime_settings()`

Tutorial 4.1 example Python helper:

```python
def _normalize_review_depth_profile(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"shallow", "default", "deep"}:
        return normalized
    return "default"
```

Tutorial 4.1 example runtime setting:

```python
"REVIEW_DEPTH_PROFILE": _normalize_review_depth_profile(
    env.get("REVIEW_DEPTH_PROFILE", "default")
),
```

### Tutorial 4.2: Add the Dashboard Control in frontend.py

File:
[frontend.py](frontend.py)

Role:
dashboard widgets, state handlers, and UI updates

Edit type:
required

What to add:

1. a helper near the other `_..._dropdown()` / `_..._checkbox()` helpers
2. the actual Gradio control in `WorkflowUI`
3. change handlers that write the chosen value back into workflow state

Tutorial 4.2 example Python helper:

```python
def _review_depth_profile_dropdown(state: Dict[str, Any], interactive: bool = True, visible: bool = True):
    value = str((state or {}).get("review_depth_profile", "default")).strip() or "default"
    return gr.update(
        choices=[("shallow", "shallow"), ("default", "default"), ("deep", "deep")],
        value=value,
        interactive=interactive,
        visible=visible,
    )
```

### Tutorial 4.3: Consume the New Knob in runtime.py or pipeline.py

Files:

- [runtime.py](runtime.py)
- [pipeline.py](pipeline.py)

Role:
actual behavior change

Edit type:
required

Rule:

- if the knob changes prompt shaping or stage instructions, edit [runtime.py](runtime.py)
- if it changes execution flow or shared-state behavior, edit [pipeline.py](pipeline.py)

Tutorial 4.3 example Python block in runtime.py:

```python
if review_depth_profile == "deep":
    sections.append("- Use deeper evidence review before final synthesis.")
```

## Tutorial 5: Extend Testing For the New Workflow Option

The benchmark mechanics are already documented in:

- [../Testing/README.md](../Testing/README.md)
- [../Testing/docs/evaluation_design.md](../Testing/docs/evaluation_design.md)
- [../Testing/config/README.md](../Testing/config/README.md)

Tutorial 5 only covers the workflow-specific wiring points.

### Tutorial 5.1: Add a Maintained Sweep Family

File:
[../Testing/config/experiment_sweeps.json](../Testing/config/experiment_sweeps.json)

Role:
source of truth for maintained one-variable-at-a-time experiment families

Edit type:
required if the new workflow option should be benchmarked

Tutorial 5.1 example JSON block:

```json
{
  "sweeps": [
    {
      "variable": "EXAMPLE",
      "description": "EXAMPLE",
      "variants": [
        {
          "name": "EXAMPLE",
          "overrides": {
            "pipeline": "EXAMPLE"
          }
        }
      ]
    }
  ]
}
```

Use:

- `pipeline` in `overrides` for pipeline preset studies
- `architecture` in `overrides` for architecture studies
- another explicit run-level field only if [../Testing/harness/runner.py](../Testing/harness/runner.py)
  already understands it

### Tutorial 5.2: Add an Operational Launch Preset

File:
[../Testing/config/presets/EXAMPLE.json](../Testing/config/presets/README.md)

Role:
named operational entry points, not scientific sweep definitions

Edit type:
conditional

Expected schema:

- one JSON object per preset file
- each preset supports:
  - `name`
  - `description`
  - `runner`
  - `corpus`
  - optional `samples`
  - optional `tasks`
  - optional `difficulty_filters`
  - optional `repetitions`
  - optional `skip_visuals`
  - optional `recommended_judge_model`
- sweep presets should also include:
  - `baseline`
  - `sweeps`

Tutorial 5.2 example JSON file:

```json
{
  "name": "EXAMPLE",
  "description": "EXAMPLE",
  "runner": "sweep",
  "corpus": "experimental",
  "samples": ["EXAMPLE"],
  "tasks": ["EXAMPLE"],
  "repetitions": 1,
  "skip_visuals": true,
  "recommended_judge_model": "openai:gpt-4o-mini",
  "baseline": {
    "corpus": "experimental",
    "pipeline": "auto_triage",
    "architecture": "balanced",
    "query_variant": "default",
    "subagent_profile": "default",
    "worker_persona_profile": "default",
    "worker_role_prompt_mode": "default",
    "validator_review_level": "default",
    "tool_profile": "full",
    "model_profile": "repo_default",
    "force_model": "",
    "judge_mode": "agent"
  },
  "sweeps": []
}
```

How the example maps to the real file:

- [../Testing/harness/launch_presets.py](../Testing/harness/launch_presets.py)
  builds a command line from these keys
- for sweep presets, the preset file itself is also passed to
  `run_experiment_sweep.py --config`

### Tutorial 5.3: Add a New Run-Level Workflow Knob to the Harness

Use this only when the new workflow option is not already covered by existing
fields like:

- `--pipeline`
- `--architecture`
- `--tool-profile`
- `--worker-persona-profile`
- `--subagent-profile`

#### Tutorial 5.3.1: Add the Field in runner.py

File:
[../Testing/harness/runner.py](../Testing/harness/runner.py)

Role:
canonical single-run entry point

Edit type:
required

What to add:

1. `argparse` field
2. env passthrough if the runtime reads the knob from env
3. `run_metadata` field

Tutorial 5.3.1 example Python lines:

```python
parser.add_argument("--review-depth-profile", default="default", help="EXAMPLE")
```

```python
os.environ["DEEP_REVIEW_DEPTH_PROFILE"] = str(args.review_depth_profile or "default").strip() or "default"
```

```python
"review_depth_profile": str(args.review_depth_profile or "default").strip() or "default",
```

#### Tutorial 5.3.2: Validate the New Knob in preflight.py

File:
[../Testing/harness/preflight.py](../Testing/harness/preflight.py)

Role:
run-configuration validation before launch

Edit type:
required

What to add:

- validation that the new knob is legal or supported before the run starts

#### Tutorial 5.3.3: Extend experiment_sweep.py Only If the New Knob Should Be Swept or Reported

File:
[../Testing/harness/experiment_sweep.py](../Testing/harness/experiment_sweep.py)

Role:
sweep orchestration and aggregation

Edit type:
conditional

What to add:

- only the minimum wiring needed for planning, pass-through, or reporting

### Tutorial 5.4: Add a New Benchmark Task or Sample Entry

File:
[../Testing/sources/experimental/sample_manifest.json](../Testing/sources/experimental/sample_manifest.json)

Role:
source of truth for experimental executable tasks

Edit type:
required if you are expanding the benchmark corpus itself

Expected schema:

- top-level `samples` array
- each sample contains:
  - `sample`
  - `difficulty`
  - `primary_techniques`
  - `expected_evidence`
  - `acceptance_targets`
  - `target_tools`
  - `default_query`
  - `tasks`
- each task contains:
  - `task_id`
  - `name`
  - `query`
  - `target_tools`
  - `expected_evidence`
  - `acceptance_targets`
  - `tags`

Tutorial 5.4 example JSON block:

```json
{
  "samples": [
    {
      "sample": "EXAMPLE",
      "difficulty": "EXAMPLE",
      "primary_techniques": ["EXAMPLE"],
      "expected_evidence": ["EXAMPLE"],
      "acceptance_targets": ["EXAMPLE"],
      "target_tools": ["EXAMPLE"],
      "default_query": "EXAMPLE",
      "tasks": [
        {
          "task_id": "EXAMPLE",
          "name": "EXAMPLE",
          "query": "EXAMPLE",
          "target_tools": ["EXAMPLE"],
          "expected_evidence": ["EXAMPLE"],
          "acceptance_targets": ["EXAMPLE"],
          "tags": ["EXAMPLE"]
        }
      ]
    }
  ]
}
```

For full benchmark-shape guidance, also read:

- [../Testing/sources/experimental/README.md](../Testing/sources/experimental/README.md)

## Tutorial 6: Validation Checklist

### Tutorial 6.1: Workflow Validation

Run these after workflow/config changes:

```bash
python3 -m py_compile multi_agent_wf/*.py Testing/harness/*.py
python3 -m multi_agent_wf.main
```

### Tutorial 6.2: Testing Validation

Run these when the extension should be benchmarked:

```bash
python3 Testing/scripts/run_experiment_sweep.py --plan-only
python3 Testing/scripts/run_evaluation.py --corpus experimental --preflight-only
```

### Tutorial 6.3: Sync Checklist

Before you consider the extension done:

1. The JSON loads without validation errors.
2. The new preset or control appears in the dashboard if expected.
3. The runtime resolves the new preset into concrete stages/archetypes.
4. Every new `stage_kind` exists in:
   - [workflow_config/stage_kind_metadata.json](workflow_config/stage_kind_metadata.json)
   - [workflow_config/stage_manager_prompts.json](workflow_config/stage_manager_prompts.json)
   - [workflow_config/stage_output_contracts.json](workflow_config/stage_output_contracts.json)
   - [pipeline.py](pipeline.py)
5. Every new role exists in:
   - [workflow_config/agent_archetype_specs.json](workflow_config/agent_archetype_specs.json)
   - [workflow_config/agent_archetype_prompts.json](workflow_config/agent_archetype_prompts.json)
6. If a new role uses a new `tool_domain`, [runtime.py](runtime.py) supports it.
7. If the new option should be benchmarked, the Testing harness knows about it.

## Cross-References

- Package map: [README.md](README.md)
- Setup path: [../SETUP_GUIDE.md](../SETUP_GUIDE.md)
- Testing suite overview: [../Testing/README.md](../Testing/README.md)
- Testing config guide: [../Testing/config/README.md](../Testing/config/README.md)
- Testing plan: [../Testing/docs/evaluation_design.md](../Testing/docs/evaluation_design.md)
