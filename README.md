# Hub_Dev

This repo has two active centers of gravity:

- [`multi_agent_wf/`](multi_agent_wf/): the main multi-agent reverse-engineering application
- [`Testing/`](Testing/): the maintained binary-analysis evaluation harness

If you are new to the repo, start with the section that matches your goal instead of exploring everything at once.

## Where To Start

- App setup and runtime overview:
  - [`SETUP_GUIDE.md`](SETUP_GUIDE.md)
  - [`multi_agent_wf/README.md`](multi_agent_wf/README.md)
- Testing harness quickstart and evaluation flow:
  - [`Testing/START_HERE.md`](Testing/START_HERE.md) for the sanity sweep and recommended under-budget study
  - [`Testing/README.md`](Testing/README.md)
  - [`Testing/TESTING_PLAN.md`](Testing/TESTING_PLAN.md)
- Workflow/dashboard extension guidance:
  - [`multi_agent_wf/extension_tutorial.md`](multi_agent_wf/extension_tutorial.md)
- Default runtime data-flow diagrams:
  - [`docs/agent_run_dataflow.md`](docs/agent_run_dataflow.md)

## Repo Map

```text
.
  multi_agent_wf/           # main agent runtime, pipeline, frontend, workflow config
  MCPServers/               # MCP server implementations and server manifest
  Testing/                  # evaluation harness, corpora, config, generated results
  skills/                   # repo-local Codex skills for tool usage
  third_party/              # optional external rule/signature corpora
  docs/                     # diagrams and implementation-grounded architecture docs
  GhidraMCP/                # Ghidra plugin source for the live bridge path
  agent_artifacts/          # generated artifacts written by analysis tools
  logs/                     # tool and worker logs produced during runs
```

## What Is Active vs Historical

Active and maintained:

- `multi_agent_wf/`
- `Testing/`
- `MCPServers/`
- `skills/`
- `docs/`

Mostly supporting or historical:

- `GhidraMCP/` is still used for the live Ghidra bridge, but not for the artifact-backed testing path
- `In_Progress/` is not part of the main runtime or testing workflow

## Mental Model

The app and the harness are related but different:

- `multi_agent_wf` is the runtime under test
- `Testing` builds corpora, prepares bundles, runs the workflow, judges outputs, and aggregates experiment results

That means many files in `Testing/` exist to observe or compare the behavior of `multi_agent_wf`, not to duplicate its logic.

## Documentation Hierarchy

The repo now follows this intended documentation structure:

1. Root overview:
   - [`README.md`](README.md)
2. Subsystem overviews:
   - [`multi_agent_wf/README.md`](multi_agent_wf/README.md)
   - [`Testing/README.md`](Testing/README.md)
3. Task-oriented quickstarts:
   - [`SETUP_GUIDE.md`](SETUP_GUIDE.md)
   - [`Testing/START_HERE.md`](Testing/START_HERE.md)
4. Deep-dive design and extension docs:
   - [`Testing/TESTING_PLAN.md`](Testing/TESTING_PLAN.md)
   - [`multi_agent_wf/extension_tutorial.md`](multi_agent_wf/extension_tutorial.md)
   - [`docs/agent_run_dataflow.md`](docs/agent_run_dataflow.md)

If a local README only repeats parent-level material, prefer pruning or linking instead of expanding it.
