# Malware Analysis Hub Testing Plan

## Purpose
This plan is intended to validate the Malware Analysis Hub end to end:

- MCP tool execution
- planner/worker/verifier/reporter orchestration
- Ghidra-assisted static analysis quality
- FLOSS/capa-assisted obfuscation identification
- platform and path handling, especially Windows paths with spaces

The goal is not just "tool runs without crashing." The goal is evidence-based output that correctly describes program purpose, control flow, and concrete obfuscation techniques.

## Core Success Criteria

- The hub selects the correct tools for the sample instead of defaulting to generic malware language.
- The final report names specific artifacts such as functions, APIs, decoded strings, capa rules, mutex names, URLs, registry paths, or addresses.
- The report avoids irrelevant PE boilerplate unless explicitly requested.
- Status logging updates during execution and clearly shows phase transitions.
- Tool calls succeed when sample paths contain spaces.
- Results are materially consistent across compiler variants and platform setups.

## Recommended Sample Corpus

Use 8 primary samples (all implemented in the current repository).

| Sample | Status | Primary techniques | Why it belongs in the corpus | Expected analyst output |
|---|---|---|---|---|
| `test.exe` | Existing | branch-heavy control flow, loop exits, switch/jump table, input-dependent behavior | Baseline control-flow reconstruction test | Report should identify the helper/classify split, switch-based branching, and the main execution path without overcalling it obfuscation |
| `floss_test.exe` | Existing | stack strings, static strings, XOR-decoded runtime strings | Baseline FLOSS/string-recovery sample | Report should recover or reference `cmd.exe /c whoami`, `https://example.com/api/v1/ping`, and decoded `kernel32.dll` evidence |
| `floss_test_stripped.exe` | Existing | stripped symbols plus stack/XOR strings | Tests robustness when symbol metadata is reduced | Report should still recover strings and describe logic without relying on function names |
| `anti_debug_test.exe` | Existing | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, timing probe, analyst-tool marker strings | Anti-debugging and anti-analysis coverage | Report should explicitly cite anti-debug API use and timing-based checks, not just say "anti-debugging present" |
| `winapi_behavior_test.exe` | Existing | `GetProcAddress`, dynamic API resolution, stack string command, mutex creation, URL and registry strings | Good mixed-behavior sample for Ghidra + capa + FLOSS | Report should name `VirtualAlloc`/`VirtualFree` resolution, `Global\\UpdaterMutex`, the URL, registry path, and stack-built command |
| `control_flow_flattened_test.exe` | Existing | dispatcher/state-machine control flow, opaque predicates, indirect dispatch, struct-based flow context | Adds true control-flow obfuscation-style coverage with richer type information | Report should identify a flattened dispatcher pattern and explain the real path through the state machine |
| `api_hash_resolver_test.exe` | Existing | API hashing, delayed import resolution, encoded API names, struct-based resolver/request tables | Adds concrete API-hash resolver behavior beyond plain `GetProcAddress` usage | Report should identify hash-based lookup and associate recovered APIs with resolver behavior |
| `resource_blob_loader_test.exe` | Existing | embedded blob container, staged decode path, struct-based record/header parsing | Adds deterministic unpacking/staging-style behavior with explicit typed container fields | Report should identify the embedded payload container, decode routine, and staged decoded content |

## Secondary Variants

These are not separate primary techniques, but they are valuable regression variants:

- `floss_test_02.exe`: optimized variant for string-recovery drift
- `*_gcc.exe`: GCC-built variants to compare against the default compiler output
- future `x86` builds: useful once you want 32-bit coverage for disassembly and capa differences

For each primary sample that already builds successfully, keep both:

- default executable
- `_gcc.exe` executable

This gives you a simple way to verify that the hub is not overfitting to one compiler fingerprint.

## Platform Test Matrix

The hub should be exercised across both platform and path-shape differences.

| Scenario | Host platform | Sample path style | Why it matters | Required checks |
|---|---|---|---|---|
| Windows native, no-space path | Windows 11 | `C:\Samples\test.exe` | baseline environment | all MCP tools work, orchestration succeeds, report quality is acceptable |
| Windows native, spaced path | Windows 11 | `C:\Users\Analyst\Desktop\Hub Test Space\test.exe` | catches command-string quoting failures in FLOSS/capa calls | FLOSS and capa succeed without manual quoting fixes |
| Windows native, GCC variants | Windows 11 | spaced path | validates compiler sensitivity | outputs remain specific and materially consistent across default and `_gcc.exe` samples |
| macOS host + Windows VM | macOS host, Windows guest | copy sample into guest path with spaces | common development setup for your project | hub can drive analysis reliably when artifacts originate from shared folders |
| UNC/shared-folder stress test | Windows 11 | `\\Mac\Home\Desktop\Thesis Tools\...` | catches path normalization and quoting issues | tools either handle the path directly or fail with actionable error messages |
| Deep-agent mode | Windows 11 | spaced path | validates orchestration mode changes | deep-agent reports are still specific and tool usage remains correct |

## Test Execution Phases

### 1. Build Verification

Run the sample build workflow before analysis testing:

```bash
make -C Test_Executables all-with-gcc
```

Build reference: `Test_Executables/BUILD.md`.

Checks:

- build manifest updates successfully
- all expected executables are present
- `_gcc.exe` variants are produced

If you need a refreshed `build_manifest.json`, run:

```bash
python Test_Executables/build_test_executables.py --also-gcc --gcc-compiler "gcc"
```

### 2. MCP Tool Smoke Tests

For each sample, validate the individual tools before full orchestration:

- Ghidra MCP: program info, imports, call graph, function decompilation
- FLOSS MCP: string recovery, especially stack strings and decoded strings
- capa MCP: compact JSON output with useful rules and reduced verbosity

Checks:

- tool calls work when the sample path contains spaces
- error messages are specific when a call string is malformed
- path quoting examples in tool descriptions are sufficient for the agent to recover

### 3. Orchestration Quality Tests

Run each sample through the full multi-agent workflow.

Checks:

- planner creates tasking aligned to the sample
- workers use the correct tools instead of generic reporting
- verifier rejects low-evidence or boilerplate claims
- reporter produces a concise, evidence-based writeup

Required output qualities:

- control flow is described as a path, not a vague capability list
- obfuscation is described as a mechanism plus evidence
- unknowns are clearly separated from confirmed findings

### 4. Regression Tests for Path Handling

For at least `floss_test.exe`, `anti_debug_test.exe`, and `winapi_behavior_test.exe`, repeat the run from:

- a no-space path
- a path with spaces
- a UNC/shared path if used in your environment

Checks:

- agent crafts quoted tool command strings
- MCP wrappers reject ambiguous unquoted commands with actionable hints
- final results are unchanged except for path formatting

### 5. Platform Regression Tests

After any significant prompt/tool/orchestrator change, rerun:

- Windows native classic orchestration
- Windows native deep-agent orchestration
- macOS host to Windows guest workflow

Checks:

- no regressions in planner stability
- live status updates still stream during long-running analysis
- retry logic behaves predictably for tool-call mistakes

## Sample-Specific Acceptance Criteria

### `test.exe`

- Mentions structured branching and switch-based dispatch
- Describes the main execution path from input to output
- Does not mislabel ordinary control flow as obfuscation

### `floss_test.exe`

- Recovers stack string content
- Identifies XOR-decoded string behavior
- Uses string evidence in the final report

### `floss_test_stripped.exe`

- Produces useful findings even without symbol names
- Avoids generic "packed/obfuscated" claims unless supported

### `anti_debug_test.exe`

- Names `IsDebuggerPresent`
- Names `CheckRemoteDebuggerPresent`
- Mentions timing-based probe logic

### `winapi_behavior_test.exe`

- Identifies dynamic resolution through `GetProcAddress`
- Names resolved APIs `VirtualAlloc` and `VirtualFree`
- Mentions `Global\\UpdaterMutex`
- Mentions the stack-built command string and registry path

### `control_flow_flattened_test.exe`

- Identifies dispatcher/state variable logic
- Reconstructs at least one real path through the flattened routine

### `api_hash_resolver_test.exe`

- Identifies hashing or export-parsing logic
- Associates the resolver with the recovered APIs

### `resource_blob_loader_test.exe`

- Identifies the embedded blob or resource
- Explains the decode/staging routine and its purpose

## Recommended Run Cadence

- On every MCP wrapper change: run tool smoke tests on `floss_test.exe` and `winapi_behavior_test.exe`
- On every orchestration/prompt change: run the full existing corpus
- Before demo/release milestones: run the full corpus on Windows native with spaced paths and on the macOS host plus Windows guest workflow

## Immediate Next Steps

1. Treat all 8 primary samples as the active regression baseline.
2. Keep generating `_gcc.exe` variants for every baseline sample.
3. Add a 32-bit (`x86`) build track for each sample and compare analysis drift versus 64-bit outputs.
4. Record one expected-output checklist per sample so future prompt changes can be judged against concrete signals instead of subjective quality.
5. Add one intentionally malformed-path run (spaces + UNC) per sample to validate quoting and command construction robustness.
