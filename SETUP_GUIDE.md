# Setup Guide

## Repo Overview

| Folder | Purpose |
|---|---|
| `GhidraMCP/` | Java/Maven Ghidra extension that exposes analysis data over HTTP for the bridge MCP server. |
| `MCPServers/` | Python FastMCP wrappers for capa, FLOSS, strings, YARA, HashDB, Ghidra bridge, binwalk, gitleaks, searchsploit, trivy. |
| `multi_agent_wf/` | Main deep-agent workflow app: config loading, runtime, pipeline orchestration, Gradio frontend, and JSON workflow configuration. |
| `skills/` | Repo-local skill definitions that teach agents safe command construction and tool usage patterns. |
| `Testing/Prototype_Test_Executables/` | Original regression sample corpus: 8 Windows PE samples covering static analysis, string obfuscation, API hashing, anti-debug, and control-flow flattening. Build scripts and Makefile included. |
| `Testing/Experimental_Test_Executables/` | 8 new samples stratified by difficulty (easy / medium / hard). Designed to cover the full MCP server surface including binwalk, hashdb, YARA, and UPX. |
| `Testing/` | `TESTING_PLAN.md`, `Testing_Documentation/`, and evidence from prior runs. |

---

## Python Environment Setup

Replace `USR_PATH` with the parent directory where you cloned this repo, so the root becomes `USR_PATH/Hub_Dev`.

```bash
cd "USR_PATH/Hub_Dev"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
cd "USR_PATH\\Hub_Dev"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**Dependency notes:**
- `python-dotenv` — `config.py` loads `.env` on startup.
- `pydantic-ai` / `pydantic-ai-backend` — agent runtime; `runtime.py` imports `pydantic_ai_backends`.
- `gradio` — Gradio UI in `frontend.py`.
- `PyYAML`, `PyGithub` — used by maintenance scripts under `MCPServers/capa-rules/.github/scripts`.
- External CLI tools (`capa`, `floss`, `strings`, `yara`, `binwalk`, `gitleaks`, `searchsploit`, `trivy`) must be on `PATH` separately — they are not Python packages.

---

## Environment Configuration (`.env`)

Create a `.env` file in the repo root. All fields are optional unless marked required.

```dotenv
# ── Model ─────────────────────────────────────────────────────────────────────
# Model ID in pydantic-ai format (provider:model-name)
OPENAI_MODEL_ID=openai:gpt-4o-mini

# ── Agent runtime ──────────────────────────────────────────────────────────────
# Max messages kept in each agent's rolling chat history
MAX_ROLE_HISTORY_MESSAGES=16

# Max worker agents running in parallel
MAX_PARALLEL_WORKERS=2

# Max retries if the validation gate rejects worker output
MAX_VALIDATION_REPLAN_RETRIES=1

# ── Deep-agent features ────────────────────────────────────────────────────────
# Enable persistent agent memory across turns
DEEP_ENABLE_MEMORY=true

# Enable agent skill loading from skill directories
DEEP_ENABLE_SKILLS=true

# Colon-separated list of skill directories
DEEP_SKILL_DIRS=USR_PATH/Hub_Dev/skills

# Max tokens of context passed to the deep-agent backend per agent
DEEP_CONTEXT_MAX_TOKENS=18000

# ── Defaults (overridable from UI) ─────────────────────────────────────────────
# easy | default | intermediate | strict
DEFAULT_VALIDATOR_REVIEW_LEVEL=default

# none | ask | full
DEFAULT_SHELL_EXECUTION_MODE=none

# ── Gradio UI ─────────────────────────────────────────────────────────────────
GRADIO_SERVER_NAME=0.0.0.0
GRADIO_SERVER_PORT=7860

# ── Automation trigger HTTP server ─────────────────────────────────────────────
# Set to true to enable the HTTP endpoint that Ghidra can POST to
AUTOMATION_TRIGGER_ENABLED=false
AUTOMATION_TRIGGER_HOST=127.0.0.1
AUTOMATION_TRIGGER_PORT=7861
```

**Validator review level effects:**
- `easy` — passes most outputs; use for exploration.
- `default` — balanced; recommended for normal runs.
- `intermediate` — stricter evidence requirements; rejects weak claims.
- `strict` — highest evidence bar; expect more replanning.

**Shell execution mode effects:**
- `none` — no shell access for agents; safest.
- `ask` — agents can request shell access; a UI modal prompts you to approve each command.
- `full` — agents execute shell commands without prompting.

---

## Running the App

```bash
cd "USR_PATH/Hub_Dev"
source .venv/bin/activate
python multi_agent_wf/main.py
```

The Gradio UI opens at `http://localhost:7860` (or the port set in `.env`).

---

## Rule Sources for capa and YARA

### capa

```bash
cd "USR_PATH/Hub_Dev/MCPServers"
git clone https://github.com/mandiant/capa capa-src
git clone https://github.com/mandiant/capa-rules capa-rules
mkdir -p capa-sigs
cp -R capa-src/sigs/* capa-sigs/
```

This gives you `MCPServers/capa-rules/` and `MCPServers/capa-sigs/` in the layout `capaMCP.py` expects.

### YARA

```bash
cd "USR_PATH/Hub_Dev/MCPServers"
mkdir -p yara_rules
git clone https://github.com/Neo23x0/signature-base yara-signature-base
git clone https://github.com/Yara-Rules/rules yara-rules-community

find yara-signature-base/yara -type f \( -name '*.yar' -o -name '*.yara' \) -exec cp {} yara_rules/ \;
find yara-rules-community -type f \( -name '*.yar' -o -name '*.yara' \) -exec cp {} yara_rules/ \;
```

**Notes:**
- `Neo23x0/signature-base` includes rules that use external LOKI/THOR variables. If plain `yara` reports undefined identifiers, remove or isolate those files.
- Combining corpora introduces duplicate rule names. Start with the curated baseline, then add breadth once scans are stable.

---

## MCP Server Configuration

`MCPServers/servers.json` defines which MCP tool servers the workflow loads. Each entry is:

```json
{
  "server-id": {
    "transport": "stdio",
    "command": "python",
    "args": ["path/to/server_script.py", "--transport", "stdio"]
  }
}
```

Server IDs containing `ghidra` are treated as requiring serial (non-concurrent) tool calls. Server IDs listed in the tool result cache allow-list will have their responses cached by the runtime.

Script paths in `args` are resolved relative to the location of `servers.json`.

---

## Ghidra MCP Extension Build

The Ghidra extension lives in `GhidraMCP/`. It exposes Ghidra analysis data over HTTP so `bridge_mcp_ghidra.py` can relay tool calls to it.

### Prerequisites

- Java/JDK on `PATH`
- Maven on `PATH`
- Ghidra 12.0.2 installed locally (the `pom.xml` is pinned to this version)

### Step 1: Populate `GhidraMCP/lib`

Copy these jars from your Ghidra install into `GhidraMCP/lib/`:

| Jar | Source path in Ghidra install |
|---|---|
| `Base.jar` | `Ghidra/Features/Base/lib/Base.jar` |
| `Decompiler.jar` | `Ghidra/Features/Decompiler/lib/Decompiler.jar` |
| `Docking.jar` | `Ghidra/Framework/Docking/lib/Docking.jar` |
| `Generic.jar` | `Ghidra/Framework/Generic/lib/Generic.jar` |
| `Gui.jar` | `Ghidra/Framework/Gui/lib/Gui.jar` |
| `Project.jar` | `Ghidra/Framework/Project/lib/Project.jar` |
| `SoftwareModeling.jar` | `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar` |
| `Utility.jar` | `Ghidra/Framework/Utility/lib/Utility.jar` |

### Step 2: Build

```bash
cd "USR_PATH/Hub_Dev/GhidraMCP"
mvn clean package assembly:single
```

Output: `target/GhidraMCP-12.0.2-SNAPSHOT.zip`

### Step 3: Install

Install the ZIP into Ghidra via the extension manager, restart Ghidra, and enable the plugin.

---

## Workflow Configuration (JSON files)

All agent behavior is driven by JSON files in `multi_agent_wf/workflow_config/`. You can modify these without touching Python code.

| File | What it controls |
|---|---|
| `architecture_presets.json` | Named agent swarms (role + count per swarm). 8 presets defined. |
| `agent_archetype_specs.json` | Agent role definitions: tool_domain, model, complexity flag. 16 archetypes. |
| `pipeline_presets.json` | Ordered stage sequences with architecture and model per stage. 4+ presets. |
| `stage_kind_metadata.json` | Capability flags per stage kind (tool access, parallel, validation gate, etc.). |
| `base_prompts.json` | Base system prompt templates for static and dynamic agents. |
| `agent_archetype_prompts.json` | Role-specific prompt specializations that extend the base. |
| `stage_manager_prompts.json` | Orchestration instructions for each stage kind. |
| `stage_output_contracts.json` | Expected JSON output format per stage (planner work items, validator gate, etc.). |

### Architecture presets

| Preset | Agents | Use case |
|---|---|---|
| `minimal` | 1× static_generalist | Fast broad pass |
| `balanced` | triage, ghidra, control_flow, obfuscation, string | Normal default |
| `aws_collaboration` | balanced + capability_analyst | Multi-angle investigation |
| `runtime_enriched` | aws_collaboration + runtime_behavior_analyst | Static + dynamic |
| `static_swarm` | 2× control_flow_analyst | Control-flow-heavy samples |
| `ghidra_focused` | 2× ghidra_analyst + type_recovery_analyst | Ghidra-centric work |
| `code_reconstruction` | c/cpp/type recovery specialists | Pseudocode cleanup |
| `ghidra_editing` | code_reconstruction + ghidra_refactor_analyst | Rename/retype proposals |

### Pipeline presets

| Preset | Stages | Use case |
|---|---|---|
| `preflight_direct_answer` | preflight → reporter | Quick metadata lookup |
| `auto_triage` | preflight → presweeps → planner → workers → reporter | Post-Ghidra bootstrap triage |
| `preflight_planner_workers_reporter` | preflight → planner → workers → reporter | Normal analysis |
| `preflight_planner_workers_validators_reporter` | + validators (evidence gate) | Higher-confidence analysis |
| `preflight_planner_workers_dual_validators_reporter` | + 2× validators | Strongest validation |

---

## Automation Trigger (HTTP API)

When `AUTOMATION_TRIGGER_ENABLED=true`, the app starts an HTTP server on `AUTOMATION_TRIGGER_HOST:AUTOMATION_TRIGGER_PORT`.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/automation/ghidra-load` | Trigger analysis from Ghidra or external tooling |
| `GET` | `/automation/health` | Health check (returns 200 OK) |
| `GET` | `/automation/status` | Returns current automation panel HTML (for JS polling) |

### Payload for `/automation/ghidra-load`

```json
{
  "program_key": "registered-program-name",
  "executable_path": "C:\\path\\to\\sample.exe",
  "sha256": "abc123...",
  "ghidra_project_path": "C:\\path\\to\\project.gpr"
}
```

`program_key` must be in the configured allow-list. Unregistered keys are rejected.

---

## Ghidra Change Queue

During analysis, agents may propose Ghidra edits (function renames, type changes, comments). These are queued and blocked from automatic execution.

- The UI displays the pending queue with **Approve** and **Reject** buttons.
- Approved changes are applied via `apply_ghidra_change_proposal_sync()`.
- Rejected changes are removed from the queue.

To enable agents to generate proposals, use the `ghidra_editing` architecture or any architecture containing `ghidra_refactor_analyst`.

---

## Tool Log Files

Each pipeline run writes structured tool logs to:

```
logs/agentToolBench_YYYYMMDD_HHMMSS/<stage_name>.log
```

Format: JSON lines. Each line is one of: `tool_call`, `tool_return`, `tool_cache_hit`, `tool_cache_wait`, `tool_cache_store`.

These logs are the primary data source for efficiency metrics in the experimental testing plan.

---

## Folder Reference

### `GhidraMCP/`
- `pom.xml` — Maven build definition
- `src/assembly/ghidra-extension.xml` — extension ZIP layout
- `lib/` — manually populated Ghidra jars

### `MCPServers/`
- `servers.json` — MCP server manifest
- `bridge_mcp_ghidra.py` — HTTP bridge to Ghidra plugin
- `capaMCP.py`, `flareFlossMCP.py`, `stringMCP.py`, `yaraMCP.py`, `hashDBMCP.py`, `binwalkMCP.py`, `gitleaksMCP.py`, `searchsploitMCP.py`, `trivyMCP.py` — per-tool MCP wrappers

### `multi_agent_wf/`
- `main.py` — entrypoint
- `config.py` — env loading and settings bootstrap
- `workflow_config_loader.py` — JSON config validation and loading
- `runtime.py` — agent runtime, MCP loading, tool caching, auto-triage presweeps
- `pipeline.py` — stage orchestration, planner/validator handling, parallel worker fan-out
- `shared_state.py` — mutable pipeline state, tool logging, UI snapshots, parent input blocking
- `frontend.py` — Gradio UI + automation trigger HTTP server
- `workflow_config/*.json` — all prompt and configuration source of truth
- `assets/frontend_head.html` — JavaScript injected into the Gradio page (polling, timers, queue alerts)

### `skills/`
- One `SKILL.md` per tool: `capa-mcp`, `floss-mcp`, `strings-mcp`, `yara-mcp`, `yara-rule-authoring`
- Loaded by agents to learn safe command construction and tool usage patterns

### `Testing/`
- `TESTING_PLAN.md` — functional and experimental test plan (includes EXP-A through EXP-I)
- `Prototype_Test_Executables/` — original 8-sample regression corpus, Makefile, build scripts
- `Experimental_Test_Executables/` — 8 new difficulty-stratified samples, Makefile, `SAMPLE_INDEX.md`
- `Testing_Documentation/` — screenshots, prompt examples, and evidence from prior runs

### Build the test corpus

```bash
# Prototype samples (MinGW cross-compile)
make -C Testing/Prototype_Test_Executables all-with-gcc

# Experimental samples
make -C Testing/Experimental_Test_Executables all-with-gcc

# Optional: UPX-packed variant for upxmcp smoke test
make -C Testing/Experimental_Test_Executables upx
```
