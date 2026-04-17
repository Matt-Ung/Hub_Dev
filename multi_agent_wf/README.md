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
- `mcp_output_sanitizer.py`
  Shared preprocessing for MCP tool results before they are cached, logged, or returned to agents.
- `pipeline.py`
  Stage prompting, planner/validator parsing, and staged workflow execution.
- `shared_state.py`
  Shared-state mutation, UI snapshotting, tool-log/state helpers, and sample metadata handling.
- `frontend.py`
  Gradio components, handlers, live panels, and automation trigger wiring.
- `security/mcp_output_denylist.txt`
  Maintained denylist of MCP output substrings and patterns that should be redacted centrally.
- `security/mcp_output_prompt_injection_patterns.txt`
  Maintained heuristics for prompt-injection-like artifact text that should be labeled and redacted as untrusted content.

## Repo-Adjacent Directories Used At Runtime

- `MCPServers/`
  MCP server scripts and `servers.json`.
- `skills/`
  Repo-local Codex skills consumed by the deep-agent runtime.

## Pathing Policy

- Package-local workflow config is resolved from `multi_agent_wf/workflow_config/`.
- Repo-level runtime assets like `MCPServers/` and `skills/` are resolved from the repository root, not the current working directory.

## MCP Output Sanitization

- Normal MCP tool returns are sanitized centrally in `runtime.py` through the shared tool-call wrapper before results are cached, summarized for history, logged, or returned to the agent.
- Host-side direct MCP calls used by deterministic presweeps also pass through the same sanitizer before their results are recorded or reused.
- The denylist lives at `multi_agent_wf/security/mcp_output_denylist.txt`.
- Prompt-injection heuristics live at `multi_agent_wf/security/mcp_output_prompt_injection_patterns.txt`.
- Extend the denylist by adding one rule per line. Supported prefixes are `literal:`, `literal_ci:`, `regex:`, and `regex_ci:`. Plain lines are treated as `literal:` rules.
- The same rule syntax applies to the prompt-injection heuristics file.
- Exact denylist matches are substring or regex based and replace only the matching span with a deterministic redaction token so the rest of the tool output remains available.
- Prompt-injection heuristic matches also label the affected string as `UNTRUSTED_ARTIFACT_TEXT` so later workers, validators, and the reporter treat it as hostile sample content rather than instructions.
- Runtime telemetry records sanitization events and stores compact `untrusted_artifact_alerts` in shared state without logging the raw matched text.
