# Setup Guide

## Repo Overview

This repository is organized around five main areas:

| Folder | Purpose |
| --- | --- |
| `GhidraMCP/` | Java/Maven-based Ghidra extension packaging for the Ghidra-side MCP snapshot/plugin. |
| `MCPServers/` | Python FastMCP wrappers for capa, FLOSS, strings, YARA, HashDB, Ghidra bridge, and other analysis tools. |
| `multi_agent_wf/` | Main deep-agent workflow app: config loading, runtime, pipeline orchestration, Gradio frontend, and JSON workflow configuration. |
| `skills/` | Repo-local skill definitions used by deep agents to explain safe command construction and tool usage patterns. |
| `Test_Executables/` | Synthetic and collected executable samples, build scripts, manifests, and Makefile-driven test corpus generation. |

## Python Environment Setup

In the command examples below, replace `USR_PATH` with the parent directory where you cloned this repository, so the repo root becomes `USR_PATH/Hub_Dev`.

The root [requirements.txt](requirements.txt) is the main dependency file for this repo.

Create and activate a virtual environment:

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

Notes:

- The root `requirements.txt` covers the main `multi_agent_wf` app, the current MCP servers, optional LangChain experiments under `In_Progress/`, and the optional `pyghidra` work-in-progress server.
- `python-dotenv` is required because `multi_agent_wf/config.py` loads `.env`.
- `pydantic-ai-backend` is required because `multi_agent_wf/runtime.py` imports `pydantic_ai_backends`.
- `PyYAML` and `PyGithub` are included to cover bundled maintenance scripts under `MCPServers/capa-rules/.github/scripts`.
- `GhidraMCP/requirements.txt` exists for the narrow Ghidra bridge case, but the root `requirements.txt` is the primary install path for this repo.
- External command-line tools used by the MCP wrappers are separate from Python package installation. You still need the underlying binaries on `PATH` for tools such as `capa`, `floss`, `strings`, `yara`, `binwalk`, `gitleaks`, `searchsploit`, and `trivy`.

## Rule Sources for capa and YARA

### capa

The repo currently expects the standard upstream capa content:

- signatures source: `https://github.com/mandiant/capa`
- rules source: `https://github.com/mandiant/capa-rules`

Typical local layout:

```bash
cd "USR_PATH/Hub_Dev/MCPServers"
git clone https://github.com/mandiant/capa capa-src
git clone https://github.com/mandiant/capa-rules capa-rules
mkdir -p capa-sigs
cp -R capa-src/sigs/* capa-sigs/
```

That gives you:

- `MCPServers/capa-rules/` for rule content
- `MCPServers/capa-sigs/` for signature content copied from the upstream `capa` repo

### YARA

There is no single universally best public baseline, so the safest recommendation is:

1. start with `Neo23x0/signature-base` for a more curated, lower-noise foundation
2. optionally layer `Yara-Rules/rules` on top for broader community coverage

Suggested upstream repos:

- curated baseline: `https://github.com/Neo23x0/signature-base`
- broader community corpus: `https://github.com/Yara-Rules/rules`

Suggested local layout:

```bash
cd "USR_PATH/Hub_Dev/MCPServers"
mkdir -p yara_rules
git clone https://github.com/Neo23x0/signature-base yara-signature-base
git clone https://github.com/Yara-Rules/rules yara-rules-community

find yara-signature-base/yara -type f \\( -name '*.yar' -o -name '*.yara' \\) -exec cp {} yara_rules/ \\;
find yara-rules-community -type f \\( -name '*.yar' -o -name '*.yara' \\) -exec cp {} yara_rules/ \\;
```

Practical note:

- `Neo23x0/signature-base` includes some rules that rely on external variables for tools like LOKI/THOR. If plain `yara` reports undefined identifiers, remove or segregate those files before using them with `yaraMCP.py`.
- If you combine multiple public corpora, expect duplicate rule names, inconsistent tagging, and some noisy/older rules. Start smaller, then add breadth once your scans are stable.

## Ghidra MCP Snapshot Build

The Ghidra extension project lives in [GhidraMCP](GhidraMCP). Its Maven configuration is defined in [pom.xml](GhidraMCP/pom.xml), and the extension ZIP layout is defined in [ghidra-extension.xml](GhidraMCP/src/assembly/ghidra-extension.xml).

### Prerequisites

- Java/JDK installed and available on `PATH`
- Maven installed and available on `PATH`
- A local Ghidra 12.0.2 install, because the `pom.xml` is pinned to `12.0.2`

### Step 1: Populate `GhidraMCP/lib`

The Maven project expects these Ghidra jars to exist in `GhidraMCP/lib/`:

| Jar to copy into `GhidraMCP/lib/` | Expected source path in a stock Ghidra install |
| --- | --- |
| `Base.jar` | `<GHIDRA_INSTALL>/Ghidra/Features/Base/lib/Base.jar` |
| `Decompiler.jar` | `<GHIDRA_INSTALL>/Ghidra/Features/Decompiler/lib/Decompiler.jar` |
| `Docking.jar` | `<GHIDRA_INSTALL>/Ghidra/Framework/Docking/lib/Docking.jar` |
| `Generic.jar` | `<GHIDRA_INSTALL>/Ghidra/Framework/Generic/lib/Generic.jar` |
| `Gui.jar` | `<GHIDRA_INSTALL>/Ghidra/Framework/Gui/lib/Gui.jar` |
| `Project.jar` | `<GHIDRA_INSTALL>/Ghidra/Framework/Project/lib/Project.jar` |
| `SoftwareModeling.jar` | `<GHIDRA_INSTALL>/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar` |
| `Utility.jar` | `<GHIDRA_INSTALL>/Ghidra/Framework/Utility/lib/Utility.jar` |

If your Ghidra layout differs, search the install tree for the exact jar name and copy it into [GhidraMCP/lib](GhidraMCP/lib).

### Step 2: Build the Plugin Snapshot

From the `GhidraMCP/` directory:

```bash
cd "USR_PATH/Hub_Dev/GhidraMCP"
mvn clean package assembly:single
```

What this does:

- builds the plugin jar as `target/GhidraMCP.jar`
- copies runtime dependencies into `target/lib/`
- assembles the extension ZIP as `target/GhidraMCP-12.0.2-SNAPSHOT.zip`

The assembly descriptor places:

- `extension.properties` at the top of the packaged extension folder
- `Module.manifest` at the top of the packaged extension folder
- `GhidraMCP.jar` into `GhidraMCP/lib/` inside the ZIP

### Step 3: Install into Ghidra

Use the generated ZIP from `target/` as the extension artifact to install into Ghidra. After installation, restart Ghidra and enable the extension/plugin as needed.

## Folder Details

## `GhidraMCP/`

Primary contents:

- [pom.xml](GhidraMCP/pom.xml): Maven build definition for the Ghidra extension snapshot
- [src/assembly/ghidra-extension.xml](GhidraMCP/src/assembly/ghidra-extension.xml): packaging layout for the final extension ZIP
- `src/main/resources/`: extension metadata files such as `Module.manifest`, `extension.properties`, and `META-INF/MANIFEST.MF`
- `lib/`: manually populated Ghidra jars referenced as system-scoped dependencies in the Maven build

This folder is for the Ghidra-side plugin packaging workflow, not the main Python UI/runtime.

## `MCPServers/`

Primary contents:

- [servers.json](MCPServers/servers.json): MCP server manifest used by the workflow runtime
- [bridge_mcp_ghidra.py](MCPServers/bridge_mcp_ghidra.py): HTTP bridge from the workflow to the Ghidra-side service
- CLI-style MCP wrappers such as:
  - [capaMCP.py](MCPServers/capaMCP.py)
  - [flareFlossMCP.py](MCPServers/flareFlossMCP.py)
  - [stringMCP.py](MCPServers/stringMCP.py)
  - [yaraMCP.py](MCPServers/yaraMCP.py)
  - [hashDBMCP.py](MCPServers/hashDBMCP.py)
  - [binwalkMCP.py](MCPServers/binwalkMCP.py)
  - [gitleaksMCP.py](MCPServers/gitleaksMCP.py)
  - [searchsploitMCP.py](MCPServers/searchsploitMCP.py)
  - [trivyMCP.py](MCPServers/trivyMCP.py)

This folder is the tool surface the multi-agent workflow actually talks to.

## `multi_agent_wf/`

Primary contents:

- [main.py](multi_agent_wf/main.py): entrypoint
- [config.py](multi_agent_wf/config.py): env loading and workflow config bootstrap
- [runtime.py](multi_agent_wf/runtime.py): deep-agent runtime, MCP loading, tool caching, and stage construction
- [pipeline.py](multi_agent_wf/pipeline.py): pipeline execution, planner/validator handling, and host-managed worker fan-out
- [shared_state.py](multi_agent_wf/shared_state.py): chat state, task board state, validation state, and live UI state
- [frontend.py](multi_agent_wf/frontend.py): Gradio UI
- `workflow_config/*.json`: prompt/configuration source of truth for architectures, stages, archetypes, and output contracts

This folder is the main application.

## `skills/`

Primary contents:

- one `SKILL.md` per tool or workflow, such as:
  - [capa-mcp](skills/capa-mcp/SKILL.md)
  - [floss-mcp](skills/floss-mcp/SKILL.md)
  - [strings-mcp](skills/strings-mcp/SKILL.md)
  - [yara-mcp](skills/yara-mcp/SKILL.md)
  - [yara-rule-authoring](skills/yara-rule-authoring/SKILL.md)

These are used to teach agents how to safely form command strings and how to use the MCP tool wrappers.

## `Test_Executables/`

Primary contents:

- [Makefile](Test_Executables/Makefile): main build entrypoint for the sample corpus
- [build_test_executables.py](Test_Executables/build_test_executables.py): Python-based build/manifest helper
- [BUILD.md](Test_Executables/BUILD.md): build documentation
- [README.md](Test_Executables/README.md): corpus overview
- `RSWE_Samples/`: collected real-world or course/lab samples kept alongside the synthetic corpus

This folder is the testing corpus for validating malware-analysis capabilities across different techniques and tool combinations.
