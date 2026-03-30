`multi_agent_wf/` package layout

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

Repo-adjacent directories still used by this package

- `MCPServers/`
  MCP server scripts and `servers.json`.
- `skills/`
  Repo-local Codex skills consumed by the deep-agent runtime.

Pathing policy

- Package-local workflow config is resolved from `multi_agent_wf/workflow_config/`.
- Repo-level runtime assets like `MCPServers/` and `skills/` are resolved from the repository root, not the current working directory.
