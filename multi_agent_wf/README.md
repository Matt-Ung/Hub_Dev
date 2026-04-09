# multi_agent_wf

`multi_agent_wf/` is the main interactive reverse-engineering application in
this repository.

## Start Here

- platform setup: [docs/setup/README.md](../docs/setup/README.md)
- minimal launch instructions: [SETUP_GUIDE.md](../SETUP_GUIDE.md)
- extension guide: [extension_tutorial.md](extension_tutorial.md)
- default run dataflow diagrams: [docs/agent_run_dataflow.md](../docs/agent_run_dataflow.md)
- entrypoint: `python -m multi_agent_wf.main`
- workflow config source of truth: [workflow_config/](workflow_config)

## Package Layout

- `main.py`
  Package entrypoint. Bootstraps env/config and launches the Gradio UI.
- `config.py`
  Environment loading, default settings, path normalization, and workflow-config loading.
- `workflow_config/`
  JSON-only workflow configuration for prompts, agent archetypes, architectures, pipelines, and stage contracts.
- `workflow_config_loader.py`
  Validates and loads the JSON workflow configuration into Python structures.
- `runtime.py`
  MCP server loading, tool partitioning, deep-agent construction, and runtime assembly.
- `pipeline.py`
  Stage prompting, planner/validator parsing, and staged workflow execution.
- `shared_state.py`
  Shared-state mutation, UI snapshotting, tool-log/state helpers, and sample metadata handling.
- `frontend.py`
  Gradio components, handlers, live panels, and automation trigger wiring.

## Repo-Adjacent Directories Used At Runtime

- `MCPServers/`
  MCP server scripts and `servers.json`.
- `skills/`
  Repo-local Codex skills consumed by the deep-agent runtime.

## Pathing Policy

- Package-local workflow config is resolved from `multi_agent_wf/workflow_config/`.
- Repo-level runtime assets like `MCPServers/` and `skills/` are resolved from the repository root, not the current working directory.
