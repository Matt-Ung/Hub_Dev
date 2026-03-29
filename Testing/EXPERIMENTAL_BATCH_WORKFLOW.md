# Experimental Batch Workflow

## Goal

This workflow removes the manual "open each sample in GUI Ghidra and analyze it one by one" bottleneck for the corpus in `Testing/Experimental_Test_Executables/`.

It does this in two phases:

1. Headless Ghidra exports a structured per-sample analysis bundle.
2. The existing multi-agent pipeline runs against those bundles through an artifact-backed `ghidramcp`, while the other MCP tools still operate on the real sample file.

## Why This Design Fits The Current Repo

The current hub already has:

- MCP server registration in `MCPServers/servers.json`
- a configurable runtime manifest path via `MCP_SERVER_MANIFEST_PATH`
- an `auto_triage` pipeline with deterministic presweeps
- a strong dependency on Ghidra-derived artifacts for metadata, decompilation, and control-flow visibility

The batch path reuses that architecture instead of replacing it:

- the live `ghidramcp` server is swapped for `artifactGhidraMCP.py`
- the rest of the pipeline continues using the existing presweeps, planner, workers, and reporter
- the sample path remains real, so `strings`, `FLOSS`, `capa`, `binwalk`, `UPX`, and `YARA` can still run normally

## What Is Automated

- scanning the experimental sample directory
- computing file identity metadata
- running headless Ghidra export per sample
- building a structured artifact bundle per sample
- generating an automation-style bootstrap payload from the bundle
- spinning a per-sample MCP manifest that points `ghidramcp` at the artifact bundle
- running the existing agent pipeline over each sample
- collecting final reports and tool-usage summaries

## What Is Still Manual

- installing Ghidra and ensuring `analyzeHeadless` is available
- optionally installing CLI tools such as `floss`, `capa`, `yara`, `binwalk`, and `upx`
- reviewing agent output quality and deciding which prompts/pipelines/architectures to benchmark
- any live Ghidra editing workflow; the artifact-backed server is intentionally read-only

## Where `pyghidra` Fits

`pyghidra` is viable in principle for this project, but it is not the best first automation baseline for the current repo.

What `pyghidra` can do:

- start Ghidra APIs from Python
- open or import programs programmatically
- run analysis
- access functions, symbols, strings, and the decompiler
- support headless operation without the GUI

Why this repo uses headless Ghidra export first:

- the current system is already Ghidra-centric and built around structured artifacts plus MCP
- `analyzeHeadless` is simpler to operationalize than a new long-lived `pyghidra` JVM bridge
- the export format creates stable, reusable test fixtures
- the artifact-backed MCP server fits the existing multi-agent workflow with minimal changes

When `pyghidra` would make sense later:

- if you want a fully Python-native batch import/decompile backend
- if you want a new MCP server that performs Ghidra analysis on demand instead of reading precomputed bundles
- if you want tighter control over project reuse, caching, or custom analysis passes inside Python

There is also an in-progress prototype at `In_Progress/pyghidraMCP.py`, but it is not the baseline used by this batch workflow.

## Files Added For This Workflow

- `MCPServers/artifactGhidraMCP.py`
- `Testing/ghidra_headless_export.py`
- `Testing/experimental_batch_utils.py`
- `Testing/Experimental_Test_Executables/sample_manifest.json`
- `Testing/batch_prepare_experimental_samples.py`
- `Testing/run_single_agent_case.py`
- `Testing/batch_run_experimental_agent_tests.py`

## Output Layout

Generated content is written under `Testing/generated/`.

Per-sample analysis bundles:

- `Testing/generated/experimental_analysis/<sample_name>/file_identity.json`
- `Testing/generated/experimental_analysis/<sample_name>/ghidra_analysis.json`
- `Testing/generated/experimental_analysis/<sample_name>/automation_payload.json`
- `Testing/generated/experimental_analysis/<sample_name>/bundle_manifest.json`
- `Testing/generated/experimental_analysis/<sample_name>/tool_outputs/*` when optional CLI tools are available

Per-sample agent results:

- `Testing/generated/experimental_reports/<sample_name>.result.json`
- `Testing/generated/experimental_reports/batch_summary.json`

## Structured Artifacts In The Ghidra Bundle

The headless export writes:

- program metadata
- file hashes from Ghidra
- image base and best-effort entry point
- section summary
- imports and exports
- strings
- function list
- decompilation per function
- disassembly per function
- callers/callees
- global xrefs
- call graph edges
- root-function candidates
- auto-analysis warnings/failures

This is enough to cover the parts of Ghidra you currently depend on most heavily:

- metadata
- decompilation
- symbols and strings
- basic control-flow visibility

## End-To-End Usage

### 1. Prepare Ghidra bundles

Set one of:

- `GHIDRA_INSTALL_DIR`
- `GHIDRA_HEADLESS`

Then run:

```bash
USR_PATH/Hub_Dev/.venv/bin/python Testing/batch_prepare_experimental_samples.py
```

Optional flags:

- `--sample basic_loops_test.exe`
- `--skip-cli-tools`
- `--keep-project`
- `--ghidra-install-dir /path/to/ghidra`
- `--ghidra-headless /path/to/analyzeHeadless`

### 2. Run the agent pipeline over the prepared corpus

```bash
USR_PATH/Hub_Dev/.venv/bin/python Testing/batch_run_experimental_agent_tests.py --prepare-if-missing
```

Useful flags:

- `--pipeline auto_triage`
- `--architecture balanced`
- `--sample anti_analysis_suite_test.exe`
- `--query "Analyze this executable and explain the anti-analysis features."`

### 3. Inspect results

Primary outputs:

- `Testing/generated/experimental_reports/batch_summary.json`
- `Testing/generated/experimental_reports/<sample>.result.json`

Look for:

- `final_report`
- `tool_usage`
- `planned_work_items`
- `ghidra_change_proposals`
- `generated_yara_rules`

## How The Agent Integration Works

`Testing/run_single_agent_case.py` creates a temporary MCP manifest per sample.

That manifest keeps the existing server set, but replaces:

- live `ghidramcp`

with:

- `artifactGhidraMCP.py --bundle-dir <sample_bundle>`

That means:

- Ghidra metadata, strings, xrefs, functions, disassembly, and decompilation come from the precomputed bundle
- other static presweep tools still run against the real executable path from the automation payload

This is why the batch path still exercises your broader MCP/tooling stack rather than turning into a pure fixture replay.

## Recommended Baseline Benchmark Mode

For a stable first pass:

- pipeline: `auto_triage`
- architecture: `balanced`
- validators: omitted by pipeline
- shell execution: `none`

That gives you:

- deterministic presweeps
- bounded worker synthesis
- reporter output
- no live Ghidra GUI dependency

## Limitations

- `artifactGhidraMCP.py` is read-only and does not support live renames/comments/type edits
- headless export quality still depends on Ghidra auto-analysis quality
- the headless exporter is a best-effort Ghidra script, so extremely large binaries or unusual formats may need tuning
- optional tool outputs depend on local tool availability
- true "malware seen before" enrichment still needs external intel sources such as VirusTotal or MalwareBazaar

## Suggested Next Steps

- add corpus-specific benchmark queries for each sample and difficulty bucket
- add scoring scripts that compare observed tool usage against `target_tools` in `sample_manifest.json`
- add a second pass that reuses the stored auto-triage context for follow-up analyst questions
- if needed later, build a true `pyghidra` backend that emits the same artifact schema so the rest of the workflow does not need to change
