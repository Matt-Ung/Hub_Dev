# Setup Guide

## Repo Overview

| Folder | Purpose |
|---|---|
| `GhidraMCP/` | Java/Maven Ghidra extension that exposes analysis data over HTTP for the bridge MCP server. |
| `MCPServers/` | Python FastMCP wrappers for capa, FLOSS, strings, YARA, HashDB, the Ghidra bridge, binwalk, UPX, bounded binary patching, alternate model backends, gitleaks, searchsploit, and trivy. |
| `multi_agent_wf/` | Main deep-agent workflow app: config loading, runtime, pipeline orchestration, Gradio frontend, and JSON workflow configuration. |
| `skills/` | Repo-local skill definitions that teach agents safe command construction and tool usage patterns. |
| `Testing/Prototype_Test_Source/` | Original regression sample source corpus: benign Windows PE-focused C samples plus build scripts, manifests, and explicit stripped/packed variant definitions. |
| `Testing/Experimental_Test_Source/` | 8 new difficulty-stratified C samples covering the full MCP server surface including binwalk, hashdb, YARA, and UPX. |
| `Testing/` | Testing harness, quickstart/testing-plan docs, benchmark corpora, and structured results. |

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
- The alternate-model MCP server uses `requests` only; no extra Python dependency is required beyond `requirements.txt`.

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

# ── Generated agent artifacts ─────────────────────────────────────────────────
# Root for generated YARA rules, helper scripts, reports, and Ghidra-supporting files
AGENT_ARTIFACT_DIR=./agent_artifacts

# Optional per-type overrides. Leave blank to use AGENT_ARTIFACT_DIR/<type>
AGENT_YARA_ARTIFACT_DIR=
AGENT_PYTHON_ARTIFACT_DIR=
AGENT_JAVA_ARTIFACT_DIR=
AGENT_REPORT_ARTIFACT_DIR=
AGENT_GHIDRA_ARTIFACT_DIR=

# Base YARA corpus used for scan-time rule loading
YARA_RULES_DIR=

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

# ── Headless Ghidra for the Testing harness ───────────────────────────────────
# Either set the install dir or the explicit analyzeHeadless path.
GHIDRA_INSTALL_DIR=
GHIDRA_HEADLESS=

# Optional dedicated JDK for analyzeHeadless. The testing harness will pass this
# through as JAVA_HOME when preparing bundles.
GHIDRA_JAVA_HOME=

# ── Alternate model MCP defaults ───────────────────────────────────────────────
# openai_compatible | huggingface_inference
ALT_MODEL_DEFAULT_PROVIDER=openai_compatible

# Global fallback alternate model and endpoint. Leave blank if you prefer
# provider-specific values below.
ALT_MODEL_DEFAULT_MODEL=
ALT_MODEL_DEFAULT_ENDPOINT=

# Generation defaults for alternate-model tool calls.
ALT_MODEL_DEFAULT_TIMEOUT_SEC=90
ALT_MODEL_DEFAULT_MAX_TOKENS=768
ALT_MODEL_DEFAULT_TEMPERATURE=0.2
ALT_MODEL_DEFAULT_TOP_P=1.0

# Hugging Face hosted inference settings
HF_MODEL_ID=
HF_INFERENCE_ENDPOINT=
HF_INFERENCE_API_TOKEN=

# OpenAI-compatible inference settings for vLLM / llama.cpp / Runpod / similar
OPENAI_COMPAT_MODEL_ID=
OPENAI_COMPAT_BASE_URL=
OPENAI_COMPAT_API_KEY=

# Generic fallback token if you do not want to use provider-specific token vars
ALT_MODEL_AUTH_TOKEN=
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

**Alternate model MCP notes:**
- `openai_compatible` is the best fit for self-hosted vLLM, llama.cpp HTTP servers, or Runpod/OpenAI-compatible GPU deployments.
- `huggingface_inference` is the best fit for Hugging Face hosted Inference API calls.
- Provider-specific values override the generic `ALT_MODEL_DEFAULT_*` values when supplied.

**Generated artifact path notes:**
- `AGENT_ARTIFACT_DIR` is the shared root for agent-generated files.
- If a per-type override is blank, the repo defaults to `AGENT_ARTIFACT_DIR/yara`, `python`, `java`, `reports`, and `ghidra`.
- `YARA_RULES_DIR` remains the base rule corpus for scanning. Generated YARA rules are written into the generated-artifact YARA directory instead of the base corpus.

**Headless Ghidra notes:**
- `Testing/prepare_bundles.py`, `Testing/run_evaluation.py`, and `Testing/run_experiment_sweep.py` now auto-load these values from the repo `.env`.
- If `analyzeHeadless` cannot find a suitable JDK, set `GHIDRA_JAVA_HOME` to the JDK home directory you want Ghidra to use.

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

### Generated Agent Artifacts

Generated helper files and generated YARA rules now use a standardized root instead of ad hoc tool-local paths.

Default layout:

```text
agent_artifacts/
  yara/
  python/
  java/
  reports/
  ghidra/
```

This is controlled by `artifact_paths.py` plus the `AGENT_ARTIFACT_DIR` / `AGENT_*_ARTIFACT_DIR` environment variables.

Practical division:

- `MCPServers/yara_rules/` or your configured `YARA_RULES_DIR` = curated base YARA corpus for scanning
- `agent_artifacts/yara/` = generated YARA rules written by `yaraWriteRule(...)`
- `agent_artifacts/python/` = Python helpers such as XOR decoders or custom unpackers
- `agent_artifacts/java/` = Java helpers
- `agent_artifacts/ghidra/` = Ghidra-supporting scripts or snippets
- `agent_artifacts/reports/` = future reusable reports or note artifacts

Binwalk scan byproducts now follow the same policy:

- entropy plots and similar binwalk-generated artifacts default to `agent_artifacts/reports/binwalk/`
- override with `BINWALK_OUTPUT_DIR` if you want a different location

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

### Ghidra MCP Fallback

`MCPServers/bridge_mcp_ghidra.py` can now fall back to an artifact bundle when the live Ghidra plugin is unavailable.

Relevant env vars:

```dotenv
GHIDRA_MCP_FALLBACK_MODE=artifact_if_unavailable
GHIDRA_ARTIFACT_BUNDLE_DIR=USR_PATH/Hub_Dev/Testing/generated/bundles/experimental/<sample_slug>
```

Modes:

- `live_only` — require live Ghidra. If the plugin is down or no program is loaded, `ghidramcp` returns the normal live-tool errors.
- `artifact_if_unavailable` — use live Ghidra first, but fall back to the configured artifact bundle when the live bridge reports request-failed or no-program-loaded conditions.
- `artifact_only` — skip the live bridge entirely and always serve from the artifact bundle.

This keeps the `ghidramcp` server ID stable for the rest of the workflow. The main limitation is that artifact-backed mode is read-only: rename/comment/type mutation tools will return read-only errors instead of applying changes.

### Alternate Model MCP

`MCPServers/modelGatewayMCP.py` adds a model-tooling lane that is separate from the main agent model provider. This lets the agent call:

- Hugging Face hosted models
- self-hosted or remote OpenAI-compatible endpoints
- GPU-hosted inference endpoints such as Runpod deployments that expose an OpenAI-compatible API

Available tools:

- `listAltModelBackends()`
- `generateWithAltModel(...)`
- `classifyWithAltModel(...)`
- `compareModelOutputs(...)`
- `recoverDecompilationWithAltModel(...)`

Use this lane when you want:

- a second opinion from an open-weight or specialized model
- malware-family or style classification
- comparison between two competing interpretations
- decompiler cleanup, naming hints, or type suggestions inspired by neural decompilation work such as IDIOMS

Do not treat alternate-model output as direct evidence. It should be cross-checked against Ghidra, strings, FLOSS, capa, imports, xrefs, and other concrete artifacts.

Example configurations:

```dotenv
# Hugging Face hosted inference
ALT_MODEL_DEFAULT_PROVIDER=huggingface_inference
HF_MODEL_ID=bigcode/starcoder2-15b
HF_INFERENCE_API_TOKEN=hf_xxx
```

```dotenv
# Runpod / vLLM / OpenAI-compatible
ALT_MODEL_DEFAULT_PROVIDER=openai_compatible
OPENAI_COMPAT_MODEL_ID=Qwen/Qwen2.5-Coder-7B-Instruct
OPENAI_COMPAT_BASE_URL=https://your-endpoint.example.com/v1
OPENAI_COMPAT_API_KEY=sk-xxx
```

Example usage idea inside the agent workflow:

- use normal Ghidra/static tools to extract a decompiled function and surrounding evidence
- call `recoverDecompilationWithAltModel(...)` for better name/type hypotheses
- validate or reject those suggestions against deterministic artifacts before turning them into findings or Ghidra change proposals

### Agent Artifacts MCP

`MCPServers/agentArtifactsMCP.py` provides a standardized write path for reusable helper files.

Available tools:

- `agentArtifactPaths()`
- `writeTextArtifact(...)`
- `writePythonArtifact(...)`
- `writeJavaArtifact(...)`
- `listAgentArtifacts(...)`
- `agentArtifactHelp()`

Use this lane when you want:

- Python deobfuscation helpers
- Java support utilities
- Ghidra-supporting scripts
- reusable report-like artifacts written to disk

Example Python helper write:

```python
writePythonArtifact(
    content=\"\"\"def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)
\"\"\",
    filename="xor_helper.py",
    subdir="labos",
    description="Single-byte XOR helper derived from recovered logic.",
)
```

Example generated YARA write:

```python
yaraWriteRule(
    rule_text=\"\"\"rule labos_screen_capture {
  strings:
    $s1 = "Available Commands:"
    $s2 = "Invalid command"
  condition:
    all of them
}\"\"\",
    filename="labos_screen_capture.yar",
    overwrite=False,
    validate=True,
)
```

`yaraWriteRule(...)` now writes generated rules into the generated-artifact YARA directory while `yaraScan(...)` defaults to scanning both the base corpus and generated rules when `rules_path` is omitted.

### Binary Patch MCP

`MCPServers/binaryPatchMCP.py` adds a separate patch-emission lane for writing patched output binaries.

Dependencies:

```bash
pip install lief keystone-engine
```

Available tools:

- `binaryPatchHelp()`
- `binaryPatchInspect(...)`
- `binaryPatchBytes(...)`
- `binaryPatchAssemble(...)`

Use this lane when you want:

- a copied patched binary written to disk
- a short instruction patch assembled from text
- a deterministic byte patch at a file offset, RVA, or VA

Do not use this lane as a substitute for Ghidra analysis. The intended workflow is:

- use Ghidra/static tools to decide what to patch
- use `binaryPatchInspect(...)` if you need format/layout confirmation
- use `binaryPatchBytes(...)` or `binaryPatchAssemble(...)` to emit a patched copy

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
- `START_HERE.md` — quickest path to run the maintained testing harness
- `TESTING_PLAN.md` — current testing-plan and evaluation-scope document
- `Prototype_Test_Source/` — original regression source corpus, Makefile, build scripts, and explicit stripped/packed variant definitions
- `Experimental_Test_Source/` — maintained benchmark corpus, sample manifest, and sample-index docs
- `build/` — compiled binaries produced by the testing harness or Makefiles
- `results/runs/` — structured evaluation outputs
- `config/` — sweep, rubric, cost, and launch configuration

### Build the test corpus

```bash
# Prototype samples (MinGW cross-compile)
make -C Testing/Prototype_Test_Source all-with-gcc

# Experimental samples
make -C Testing/Experimental_Test_Source all-with-gcc

# Optional: UPX-packed variant for upxmcp smoke test
make -C Testing/Experimental_Test_Source upx
```

### Run the evaluation workflow

```bash
# End-to-end experimental run
python Testing/run_evaluation.py --corpus experimental

# Reuse existing binaries/bundles and just rerun analysis + judging
python Testing/run_evaluation.py --corpus experimental --skip-build --skip-prepare

# Prototype regression corpus
python Testing/run_evaluation.py --corpus prototype
```
