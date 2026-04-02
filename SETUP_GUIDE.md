# Setup Guide

This guide is for the active `multi_agent_wf` application.

It is intentionally minimal:

- first get the Gradio app running
- then enable optional capabilities such as live Ghidra, richer rule corpora, automation triggers, and the testing harness

If you only want the evaluation harness, start with [Testing/START_HERE.md](Testing/START_HERE.md) instead.

## What `multi_agent_wf` Actually Is

`multi_agent_wf/` is the main agentic app. The real runtime path is:

1. [multi_agent_wf/main.py](multi_agent_wf/main.py)
2. [multi_agent_wf/config.py](multi_agent_wf/config.py)
3. [multi_agent_wf/frontend.py](multi_agent_wf/frontend.py)
4. [multi_agent_wf/runtime.py](multi_agent_wf/runtime.py)
5. [multi_agent_wf/pipeline.py](multi_agent_wf/pipeline.py)

Important adjacent inputs:

- [multi_agent_wf/workflow_config/](multi_agent_wf/workflow_config)
- [MCPServers/servers.json](MCPServers/servers.json)
- repo `.env`

The UI is Gradio. MCP servers are launched over `stdio` from `servers.json`. Tool servers are loaded when a run actually needs them, not when the page first renders.

## Minimal Quickstart

These are the smallest required steps to get the app running locally.

### 1. Create a venv and install Python deps

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Create a minimal `.env`

Only one variable is effectively required for a normal launch:

```dotenv
OPENAI_API_KEY=your_key_here
```

Useful but optional defaults:

```dotenv
OPENAI_MODEL_ID=openai:gpt-5-mini
GRADIO_SERVER_PORT=7860
AUTOMATION_TRIGGER_ENABLED=false
```

Notes:

- If `OPENAI_API_KEY` is missing, [config.py](multi_agent_wf/config.py) will prompt for it interactively.
- `DEEP_SKILL_DIRS` is optional. The runtime already auto-discovers the repo-local `skills/` directory.
- The automation HTTP sidecar is now opt-in. Leave it disabled unless you explicitly need Ghidra-triggered automation.

### 3. Launch the app

```bash
python -m multi_agent_wf.main
```

The UI should come up at:

- [http://127.0.0.1:7860](http://127.0.0.1:7860) by default

You can still use:

```bash
python multi_agent_wf/main.py
```

but `python -m multi_agent_wf.main` is the cleaner path.

## Minimal Run Requirements vs Optional Capabilities

Required for the UI to launch and build:

- Python dependencies from [requirements.txt](requirements.txt)
- `OPENAI_API_KEY` or an interactive terminal prompt

Not required for the UI to launch:

- live Ghidra plugin
- headless Ghidra
- capa rules/signatures
- YARA corpus
- FLOSS/capa/binwalk/gitleaks/searchsploit/trivy binaries on `PATH`
- testing harness bundles/results

Those become relevant only when you want the corresponding tools to work during an analysis run.

## Environment and Config Notes

The real env/bootstrap behavior is in [multi_agent_wf/config.py](multi_agent_wf/config.py).

### Frequently used variables

| Variable | Required | What it does |
|---|---:|---|
| `OPENAI_API_KEY` | Yes, unless you want an interactive prompt | API key for the main agent model |
| `OPENAI_MODEL_ID` | No | Primary agent model, default `openai:gpt-5-mini` |
| `GRADIO_SERVER_NAME` | No | Bind host for the UI |
| `GRADIO_SERVER_PORT` | No | Bind port for the UI |
| `DEFAULT_VALIDATOR_REVIEW_LEVEL` | No | Default validator strictness in the UI |
| `DEFAULT_SHELL_EXECUTION_MODE` | No | Default shell access mode in the UI |
| `AUTOMATION_TRIGGER_ENABLED` | No | Enables the extra HTTP automation trigger server |
| `MCP_SERVER_MANIFEST_PATH` | No | Alternative path to the MCP manifest; default is `MCPServers/servers.json` |

### Advanced but real variables

These are implemented, but not needed for a basic launch:

- `DEEP_AGENT_ARCHITECTURE_NAME`
- `DEEP_AGENT_PIPELINE_NAME`
- `DEEP_FORCE_MODEL_ID`
- `DEEP_WORKER_SUBAGENT_PROFILE`
- `DEEP_WORKER_PERSONA_PROFILE`
- `DEEP_ENABLE_MEMORY`
- `DEEP_PERSIST_BACKEND`
- `DEEP_BACKEND_ROOT`
- `DEEP_CONTEXT_MAX_TOKENS`
- `DEEP_AGENT_PIPELINE_ROUTER_MODEL`
- `DEEP_AGENT_RETRIES`
- `HOST_PARALLEL_WORKER_EXECUTION`

### Variables that do not belong in the minimal path

These are optional and should only be set when you need the feature:

- `YARA_RULES_DIR`
- `AGENT_ARTIFACT_DIR` and `AGENT_*_ARTIFACT_DIR`
- `GHIDRA_INSTALL_DIR`, `GHIDRA_HEADLESS`, `GHIDRA_JAVA_HOME`
- `GHIDRA_ARTIFACT_BUNDLE_DIR`, `GHIDRA_MCP_FALLBACK_MODE`
- `ALT_MODEL_*`, `OPENAI_COMPAT_*`, `HF_*`

## Frontend / Backend Wiring

The actual wiring is:

- [multi_agent_wf/frontend.py](multi_agent_wf/frontend.py) builds the Gradio UI
- [multi_agent_wf/runtime.py](multi_agent_wf/runtime.py) loads MCP servers from [MCPServers/servers.json](MCPServers/servers.json)
- [multi_agent_wf/workflow_config/](multi_agent_wf/workflow_config) is the source of truth for architectures, pipelines, prompts, and worker personas

Current defaults worth knowing:

- default architecture preset: `aws_collaboration`
- default pipeline preset: `preflight_planner_workers_validators_reporter`
- worker persona defaults to `default`
- automation trigger defaults to disabled unless enabled in `.env`

The UI and runtime do not require a separate backend web server beyond Gradio. The only extra HTTP service is the optional automation trigger sidecar on port `7861`.

## Optional Capability Enablement

### Live Ghidra bridge

This is optional for startup but important for high-quality reverse-engineering runs.

The live bridge path is:

- [GhidraMCP/](GhidraMCP) Java plugin
- [MCPServers/bridge_mcp_ghidra.py](MCPServers/bridge_mcp_ghidra.py) MCP wrapper

Important:

- the plugin build is currently pinned to Ghidra `12.0.2` in [GhidraMCP/pom.xml](GhidraMCP/pom.xml)
- this is separate from the headless Ghidra path used by the testing harness

If you need the live bridge, build and install the plugin from `GhidraMCP/`. If you do not, the app can still launch; Ghidra-backed tool calls will just be unavailable or must rely on artifact fallback if configured.

### capa rules and signatures

These are optional for startup. They are only needed if you want `capaMCP` scans to work well.

Supported lookup paths are implemented in [MCPServers/capaMCP.py](MCPServers/capaMCP.py):

- `CAPA_RULES_DIR`
- `CAPA_SIGS_DIR`
- fallback repo-local `third_party/capa-rules`
- fallback repo-local `third_party/capa-sigs/sigs` or `third_party/capa-testfiles/sigs`
- legacy fallback `MCPServers/capa-rules` and `MCPServers/capa-sigs`

Official upstream sources:

- rules: [mandiant/capa-rules](https://github.com/mandiant/capa-rules)
- signatures: [mandiant/capa-testfiles](https://github.com/mandiant/capa-testfiles) in its `sigs/` directory

Recommended repo-local layout:

```bash
mkdir -p third_party
git clone https://github.com/mandiant/capa-rules third_party/capa-rules
git clone https://github.com/mandiant/capa-testfiles third_party/capa-sigs
```

Recommended `.env` values:

```dotenv
CAPA_RULES_DIR=./third_party/capa-rules
CAPA_SIGS_DIR=./third_party/capa-sigs/sigs
```

Notes:

- `CAPA_SIGS_DIR` should point at the `sigs/` subdirectory, not just the root clone.
- The code also accepts `./third_party/capa-testfiles/sigs` if you prefer to keep the upstream repo name as the local directory name.
- If you prefer, you can copy or symlink only that `sigs/` directory into another local folder and point `CAPA_SIGS_DIR` there instead.

### YARA corpus

Also optional for startup.

Supported base path is implemented in [artifact_paths.py](artifact_paths.py):

- `YARA_RULES_DIR`
- otherwise `./third_party/signature-base` when present
- legacy fallback `MCPServers/yara_rules`

Official upstream source:

- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)

Recommended repo-local layout:

```bash
mkdir -p third_party
git clone https://github.com/Neo23x0/signature-base third_party/signature-base
```

Recommended `.env` value for this repo:

```dotenv
YARA_RULES_DIR=./third_party/signature-base
```

Notes:

- This repo is already configured to work with `./third_party/signature-base` as the base YARA corpus.
- [MCPServers/yaraMCP.py](MCPServers/yaraMCP.py) scans the configured directory recursively for `*.yar` and `*.yara`, so pointing at the repo root is fine even though most rules live under `yara/`.
- Some `signature-base` rules are designed for LOKI/THOR-style external variables. If plain YARA reports `undefined identifier`, check the upstream repository README for the files it recommends excluding in non-LOKI/non-THOR setups.

Generated rules are written under `agent_artifacts/yara/`.

### Alternate-model lane

[MCPServers/modelGatewayMCP.py](MCPServers/modelGatewayMCP.py) exists, but it is **not enabled by default** in [MCPServers/servers.json](MCPServers/servers.json).

If you want alternate-model tools, add that server to `servers.json` and then configure the relevant `ALT_MODEL_*`, `OPENAI_COMPAT_*`, or `HF_*` variables.

### Automation trigger server

When enabled, the app starts an extra HTTP listener on:

- `AUTOMATION_TRIGGER_HOST`
- `AUTOMATION_TRIGGER_PORT`

Implemented endpoints live in [multi_agent_wf/frontend.py](multi_agent_wf/frontend.py):

- `POST /automation/ghidra-load`
- `GET /automation/health`
- `GET /automation/status`

The automation status panel in the Gradio UI is only shown when `AUTOMATION_TRIGGER_ENABLED=true`.

Important correction:

- `program_key` is used for duplicate-run tracking
- there is currently **no allow-list enforcement** in the implementation

## Troubleshooting

### The UI launches but analysis fails on first query

That usually means one of these:

- `OPENAI_API_KEY` is missing or invalid
- an MCP server dependency from [requirements.txt](requirements.txt) is missing
- a tool CLI such as `capa`, `floss`, `yara`, or `binwalk` is not on `PATH`
- live Ghidra is not available and no artifact fallback is configured

### The UI launches but remote automation status polling is broken

That usually happens when you expose the UI remotely but leave the automation host as `127.0.0.1`. The frontend now resolves local-style automation hosts against the browser hostname, which is better for remote use, but you should still set explicit host/port values when deploying remotely.

### You only want testing/evaluation

Do not follow the whole app setup guide first. Use:

- [Testing/START_HERE.md](Testing/START_HERE.md)
- [Testing/README.md](Testing/README.md)

## Minimal Correct Command List

If you want the shortest accurate version:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
printf "OPENAI_API_KEY=your_key_here\nAUTOMATION_TRIGGER_ENABLED=false\n" > .env
python -m multi_agent_wf.main
```

Everything else in this guide is optional capability enablement, not part of the critical path.
