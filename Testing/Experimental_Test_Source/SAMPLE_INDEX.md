# Experimental Test Source — Sample Index

## Overview

11 source samples grouped by analysis difficulty currently produce 15 executable variants in the maintained experimental corpus. The extra variants come from one UPX-packed sample and three explicit stripped hard variants. Compiled outputs are written to `Testing/build/experimental/`. The manifest now defines 24 evaluation tasks across those executables, mixing broad program-analysis prompts with focused recovery, deception-audit, and symbol-light tasks.

All samples are benign. They simulate malware-like analysis patterns without performing destructive, persistent, privileged, or network-active operations.

## Sample Matrix

| # | Executable | Difficulty | Primary Techniques | Target MCP Tools | What It Validates |
|---|---|---|---|---|---|
| 1 | `basic_loops_test.exe` | Easy | For/while/do-while loops, function calls, if/else branching, integer arithmetic | ghidramcp, stringmcp, CapaMCP | Decompilation accuracy baseline. If the pipeline cannot reconstruct this cleanly, nothing else will be trustworthy. |
| 2 | `maintenance_orchestrator_test.exe` | Hard | Misleading names, cleartext decoy labels, dormant decoded strings, dispatcher with live/dead entries, deterministic local report generation | ghidramcp, stringmcp, flareflossmcp, CapaMCP | Deception-resistance benchmark with moderate answer leakage. Tests whether agents separate threatening surface cues from the real benign snapshot/report workflow. |
| 3 | `maintenance_orchestrator_test_stripped.exe` | Hard | Stripped symbols, deceptive strings, dormant decoded notices, live/dead dispatcher entries | ghidramcp, stringmcp, flareflossmcp, CapaMCP | Symbol-light control for the same deception task. Measures whether the analysis can recover the real behavior without preserved symbol names. |
| 4 | `callback_dispatch_test.exe` | Medium | Function pointer table, struct command descriptors, indirect calls, state machine, error handling | ghidramcp, CapaMCP, stringmcp | Indirect-call resolution. Tests whether Ghidra/agents can resolve function pointers through a dispatch table. |
| 5 | `config_decoder_test.exe` | Medium | Single-byte XOR config blob, key=value parsing, stack buffer decode, validation branching | flareflossmcp, stringmcp, ghidramcp, CapaMCP | Simplest non-trivial decode-and-parse sample. FLOSS should recover concrete config values and the planner should separate decode from parser logic. |
| 6 | `signal_router_report_test.exe` | Medium | Deceptive cleartext labels, small opcode dispatcher, XOR-decoded routing plan, runtime-decoded output path | ghidramcp, stringmcp, CapaMCP | Mid-tier deception sample where strings alone overstate the threat model. Tests behavior grounding from the live routing logic. |
| 7 | `stack_notice_scheduler_test.exe` | Medium | Stack-built decoy strings, dormant decoded notices, XOR-decoded schedule data, insertion sort | flareflossmcp, ghidramcp, stringmcp, CapaMCP | FLOSS-overtrust control. Tests whether the agent can separate recovered decoy strings from the actual local scheduling behavior. |
| 8 | `multilayer_encode_test.exe` | Hard | Two-layer encoding (ROL + XOR), encoded URLs / commands, per-entry metadata, magic header | flareflossmcp, stringmcp, ghidramcp, CapaMCP, yaramcp | Multi-layer decode challenge. Tests whether the analysis recovers both layers instead of collapsing the sample into simple XOR. |
| 9 | `hash_dispatch_test.exe` | Hard | DJB2 hash algorithm, hash-to-handler dispatch table, stack-built command strings, dead/decoy entries, indirect call | ghidramcp, hashdbmcp, flareflossmcp, CapaMCP, stringmcp | Hash-based dispatch and concrete hash mapping recovery. |
| 10 | `hash_dispatch_test_stripped.exe` | Hard | Stripped symbols, DJB2 hashing, stack strings, hash-to-handler dispatch, dead entries | ghidramcp, hashdbmcp, flareflossmcp, CapaMCP, stringmcp | Symbol-light hash-dispatch control. Separates algorithm/data-flow recovery from name recovery. |
| 11 | `embedded_payload_test.exe` | Hard | Embedded blob with structured header, rolling checksum, per-record XOR keys, staged extraction | binwalkmcp, flareflossmcp, stringmcp, ghidramcp, CapaMCP, upxmcp | Dropper/loader pattern. Tests blob detection, staged decode reasoning, and checksum recovery. |
| 12 | `embedded_payload_test_upx.exe` | Hard | UPX packing layered over embedded blob extraction | upxmcp, binwalkmcp, flareflossmcp, stringmcp, ghidramcp, CapaMCP | Packed-wrapper control. Separates packing evidence from underlying payload-loader behavior. |
| 13 | `branch_weave_snapshot_test.exe` | Hard | Encoded operation stream, misleading names, minimal true-behavior strings, live/dead dispatcher entries, dormant notices | ghidramcp, flareflossmcp, stringmcp, CapaMCP | Low-leakage deception benchmark. True behavior should not be recoverable mainly from strings/FLOSS. |
| 14 | `branch_weave_snapshot_test_stripped.exe` | Hard | Stripped symbols, low true-behavior string leakage, encoded operation stream, deceptive notices | ghidramcp, flareflossmcp, stringmcp, CapaMCP | Hardest symbol-light deception variant in the maintained corpus. |
| 15 | `anti_analysis_suite_test.exe` | Hard | Anti-debug APIs, timing probe, environment fingerprinting, rotating-key XOR config, dead code, misleading names | ghidramcp, CapaMCP, flareflossmcp, stringmcp, yaramcp, hashdbmcp | Composite anti-analysis sample requiring broad tool coordination. |

## MCP Server Coverage

| MCP Server | Directly Exercised By | Coverage Notes |
|---|---|---|
| **ghidramcp** | All 11 source samples / all 15 executable variants | Decompilation, call graph, xrefs, dispatcher recovery, and control/data-flow analysis |
| **stringmcp** | All 11 source samples / all 15 executable variants | Cleartext decoy-label extraction, residual literals, and report-format hints |
| **flareflossmcp** | `maintenance_orchestrator*`, `config_decoder_test`, `stack_notice_scheduler_test`, `multilayer_encode_test`, `hash_dispatch*`, `embedded_payload_test*`, `branch_weave_snapshot_test*`, `anti_analysis_suite_test` | Stack strings, dormant decoded notices, XOR-decoded config/data recovery |
| **CapaMCP** | All 11 source samples / all 15 executable variants | Structural rule matching (decode helpers, indirect calls, anti-analysis, packing-adjacent behavior) |
| **hashdbmcp** | `hash_dispatch*`, `anti_analysis_suite_test` | Hash algorithm identification and concrete hash lookup |
| **binwalkmcp** | `embedded_payload_test`, `embedded_payload_test_upx` | Embedded blob / magic signature detection |
| **upxmcp** | `embedded_payload_test_upx` | Packing detection and unpacking |
| **yaramcp** | `multilayer_encode_test`, `anti_analysis_suite_test` | Pattern matching on decoded indicators and anti-debug API names |
| **gitleaksmcp** | — | Not applicable to standalone binary samples |
| **searchsploitmcp** | — | Not applicable without a vulnerable-library or CVE-oriented target |
| **trivymcp** | — | Not applicable to standalone PE-style binaries |

### Gap Analysis

Three MCP servers remain intentionally uncovered by this corpus:

- **gitleaksmcp**: repository-scanning tool, not a binary-analysis tool.
- **searchsploitmcp**: requires a vulnerability-oriented target rather than a synthetic standalone benchmark binary.
- **trivymcp**: requires a container or filesystem/package target, not a PE-style executable.

## Build Instructions

### Prerequisites

- **Full PE output**: `x86_64-w64-mingw32-gcc` (MinGW-w64 cross-compiler)
- **Fallback**: native `gcc` or `clang` on macOS/Linux
- **UPX variant**: `upx` on `PATH` for `make upx`

### Build commands

```bash
# Build all baseline and stripped variants
make -C Testing/Experimental_Test_Source all

# Build GCC-variant binaries for the unstripped source samples
make -C Testing/Experimental_Test_Source all-gcc

# Build both sets
make -C Testing/Experimental_Test_Source all-with-gcc

# Build the UPX-packed embedded_payload variant
make -C Testing/Experimental_Test_Source upx

# Clean all generated binaries
make -C Testing/Experimental_Test_Source clean
```

### Platform notes

- `anti_analysis_suite_test.c` uses Windows APIs. On non-Windows platforms, safe stubs preserve code structure and analysis signals.
- `config_decoder_test` is compiled at `-O0` to preserve the decode loop structure.
- All other maintained samples compile at `-O2`.
- The explicit stripped hard variants are compiled with `-s` so symbol recovery is intentionally reduced without changing source behavior.

## Difficulty Rationale

### Easy

Decompilation baseline only. This tier exists to catch integration failures early.

### Medium

The medium tier now includes both ordinary non-trivial analysis and deception-oriented midpoint cases:

- **callback_dispatch_test**: indirect-call resolution and state tracking
- **config_decoder_test**: decode-plus-parse reconstruction
- **signal_router_report_test**: deceptive cleartext labels with recoverable live behavior
- **stack_notice_scheduler_test**: FLOSS-recoverable decoys that do not reflect the true scheduling logic

### Hard

The hard tier now mixes multiple distinct failure modes:

- **maintenance_orchestrator_test** and **maintenance_orchestrator_test_stripped**: deception with moderate answer leakage
- **multilayer_encode_test**: layered decoding
- **hash_dispatch_test** and **hash_dispatch_test_stripped**: hash-based dispatch and symbol-light recovery
- **embedded_payload_test** and **embedded_payload_test_upx**: staged extraction and packing separation
- **branch_weave_snapshot_test** and **branch_weave_snapshot_test_stripped**: low true-behavior string leakage, requiring control/data-flow recovery
- **anti_analysis_suite_test**: broad anti-analysis coordination problem

## Expected Scoring Ranges (Automated Judge, 0-100)

These are approximate ranges using the maintained baseline configuration (`auto_triage`, balanced architecture, default validator review):

| Difficulty | Expected score range | Notes |
|---|---|---|
| Easy | 80-100 | Should remain near-perfect. Large drops usually indicate tooling or harness regressions. |
| Medium | 60-88 | Medium now includes deception-oriented cases, so simple string-led summaries should separate more cleanly from behavior-grounded reports. |
| Hard | 35-80 | Wide variance is expected. Stripped and low-leakage variants are intended to reduce trivial full-credit outcomes. |

## Task Coverage Notes

The experimental manifest now mixes:

- 15 broad `default_analysis` tasks, one per executable variant
- 9 focused tasks that emphasize more discriminative evaluation modes:
  - config value recovery (`config_decoder_test.exe`)
  - actual-behavior recovery and decoy-signal audit (`maintenance_orchestrator_test.exe`)
  - routing behavior recovery (`signal_router_report_test.exe`)
  - decoy-string auditing with FLOSS surfaces (`stack_notice_scheduler_test.exe`)
  - hash-to-behavior mapping recovery (`hash_dispatch_test.exe`)
  - packing/tool-triage and behavior classification (`embedded_payload_test_upx.exe`)
  - low-leakage program-decode recovery (`branch_weave_snapshot_test.exe`)

This gives the maintained sweep broader discriminative coverage across:

- extraction accuracy vs. generic summarization
- behavior grounding vs. trust in deceptive strings/names
- symbol-light recovery vs. symbol-assisted recovery
- FLOSS-overtrust vs. control-flow-based reasoning
- packed-wrapper analysis vs. underlying payload behavior
