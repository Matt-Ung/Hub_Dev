# Experimental Test Source — Sample Index

## Overview

8 source samples grouped by analysis difficulty, producing 9 executable variants in the experimental build corpus because `embedded_payload_test` also has a UPX-packed variant. Compiled outputs are written to `Testing/build/experimental/`. The manifest now defines 13 evaluation tasks across those executables so the benchmark includes both broad program-analysis prompts and a small number of focused recovery/tool-triage prompts.

All samples are benign — they simulate malware techniques without performing any destructive or network-active operations.

## Sample Matrix

| # | Executable | Difficulty | Primary Techniques | Target MCP Tools | What It Validates |
|---|---|---|---|---|---|
| 1 | `basic_loops_test.exe` | Easy | For/while/do-while loops, function calls, if/else branching, integer arithmetic | ghidramcp, stringmcp, CapaMCP | Decompilation accuracy baseline.  If the pipeline can't cleanly reconstruct this, nothing else will work. |
| 2 | `string_table_test.exe` | Easy | Global strings, string pointer table, index-based lookup, stack buffer copy | stringmcp, flareflossmcp, ghidramcp, CapaMCP | String extraction baseline.  Every string is cleartext.  Tools should find all of them. |
| 3 | `callback_dispatch_test.exe` | Medium | Function pointer table, struct command descriptors, indirect calls, state machine, error handling | ghidramcp, CapaMCP, stringmcp | Indirect call resolution.  Tests whether Ghidra/agents can resolve function pointers through a dispatch table. |
| 4 | `config_decoder_test.exe` | Medium | Single-byte XOR config blob, key=value parsing, stack buffer decode, validation branching | flareflossmcp, stringmcp, ghidramcp, CapaMCP | Simplest non-trivial encoding.  FLOSS should recover decoded config strings.  Planner should decompose decode vs. parse. |
| 5 | `multilayer_encode_test.exe` | Hard | Two-layer encoding (ROL + XOR), encoded C2 URLs / registry paths / shell commands, per-entry metadata, magic header | flareflossmcp, stringmcp, ghidramcp, CapaMCP, yaramcp | Multi-layer decode challenge.  Tests whether FLOSS handles ROL+XOR.  YARA may match decoded indicators. |
| 6 | `hash_dispatch_test.exe` | Hard | DJB2 hash algorithm, hash-to-handler dispatch table, stack-built command strings, dead/decoy hash entries, indirect call | ghidramcp, hashdbmcp, flareflossmcp, CapaMCP, stringmcp | API hashing pattern.  Tests hash algorithm identification, hashdb lookup, and stack string recovery. |
| 7 | `embedded_payload_test.exe` | Hard | Embedded blob with structured header, rolling checksum, per-record XOR keys, dead/padding records, staged extraction | binwalkmcp, flareflossmcp, stringmcp, ghidramcp, CapaMCP, upxmcp | Dropper/loader pattern.  Tests blob detection (binwalk), checksum identification, staged decode analysis.  UPX variant exercises upxmcp. |
| 8 | `anti_analysis_suite_test.exe` | Hard | IsDebuggerPresent, timing probe, environment fingerprinting, rotating-key XOR config, dead code, misleading function names, stack strings | ghidramcp, CapaMCP, flareflossmcp, stringmcp, yaramcp, hashdbmcp | Composite anti-analysis.  Forces multi-tool coordination.  Misleading names test whether agents reason about behavior, not symbols. |

## MCP Server Coverage

| MCP Server | Directly Exercised By | Coverage Notes |
|---|---|---|
| **ghidramcp** | All 8 source samples / all 9 executable variants | Decompilation, call graph, xrefs, function pointer resolution |
| **stringmcp** | All 8 source samples / all 9 executable variants | Cleartext string extraction from .rdata / .rodata |
| **flareflossmcp** | 2, 4, 5, 6, 7, 8 | Stack strings, XOR-decoded strings, encoded blob recovery |
| **CapaMCP** | All 8 source samples / all 9 executable variants | Behavioral rule matching (XOR decode, anti-debug, indirect call, etc.) |
| **hashdbmcp** | 6, 8 | DJB2 hash value lookup, hash algorithm identification |
| **binwalkmcp** | 7 | Embedded blob / magic signature detection |
| **upxmcp** | 7 (UPX variant) | Packing detection and unpacking.  Requires `make upx` to produce packed binary. |
| **yaramcp** | 5, 8 | Pattern matching on decoded C2 indicators, anti-debug API names |
| **gitleaksmcp** | — | Not applicable to binary analysis.  Designed for source/repo scanning. |
| **searchsploitmcp** | — | Not applicable.  Requires known CVE/vulnerability patterns.  A future sample embedding a known vulnerable library version could cover this. |
| **trivymcp** | — | Not applicable.  Requires container images or filesystem vulnerability scanning.  Not exercisable by standalone PE samples. |

### Gap Analysis

Three MCP servers are not directly exercised by any binary sample:

- **gitleaksmcp**: Operates on git repositories, not binaries.  Not feasible to exercise with a compiled sample.
- **searchsploitmcp**: Operates on CVE/exploit database lookups.  A future sample linking against a known-vulnerable library (e.g., an old OpenSSL version) could trigger relevant results.
- **trivymcp**: Operates on container images and filesystem vulnerability scanning.  Would require a Docker image or package manifest as the analysis target, not a PE binary.

## Build Instructions

### Prerequisites

- **Full PE output**: `x86_64-w64-mingw32-gcc` (MinGW-w64 cross-compiler)
- **Fallback**: Native `gcc` or `clang` on macOS/Linux.  Compiles everything except real Windows API calls (uses stubs instead).
- **UPX variant**: `upx` on PATH for `make upx`

### Build commands

```bash
# Build all baseline binaries
make -C Testing/Experimental_Test_Source all

# Build GCC-variant binaries
make -C Testing/Experimental_Test_Source all-gcc

# Build both sets
make -C Testing/Experimental_Test_Source all-with-gcc

# Build UPX-packed variant of embedded_payload_test
make -C Testing/Experimental_Test_Source upx

# Clean all binaries
make -C Testing/Experimental_Test_Source clean
```

### Platform notes

- `anti_analysis_suite_test.c` uses Windows APIs (IsDebuggerPresent, QueryPerformanceCounter, etc.).  On non-Windows, stubs return "not detected" defaults.  The code structure and string patterns are preserved for analysis regardless.
- `config_decoder_test` is compiled at `-O0` to preserve the XOR decode loop structure.  At higher optimization levels, the compiler may partially unroll or vectorize the loop.
- All other samples compile at `-O2`.

## Difficulty Rationale

### Easy

Intended as decompilation and string-extraction baselines.  If the pipeline scores poorly on these, the issue is in the tool integration or fundamental agent behavior, not in the sample's analysis challenge.

### Medium

Realistic complexity: indirect calls, state management, simple encoding.  These test whether the planner correctly decomposes work items and whether Ghidra agents follow function pointers through data.

### Hard

Deliberately challenging patterns drawn from real malware:
- **multilayer_encode_test**: Multi-pass encoding defeats single-pass FLOSS recovery.  Agents must identify the layered decode from Ghidra and correlate with FLOSS output.
- **hash_dispatch_test**: Hash-based dispatch hides command names.  Agents must identify the algorithm and correlate with hashdb.
- **embedded_payload_test**: Staged extraction with per-record keys.  Tests whether the pipeline handles blob-within-binary patterns.
- **anti_analysis_suite_test**: Composite sample requiring coordination across Ghidra, capa, FLOSS, YARA, and strings.  Misleading function names test whether agents trust behavior over symbols.

## Expected Scoring Ranges (Automated Judge, 0–100)

These are approximate ranges using the current automated baseline configuration (balanced architecture, `auto_triage` pipeline, default validator review level):

| Difficulty | Expected score range | Notes |
|---|---|---|
| Easy | 80–100 | Should score near-perfect. Anything below roughly 70 usually indicates a tool, bundle, or integration problem rather than sample difficulty. |
| Medium | 65–90 | Indirect-call resolution and XOR/config recovery may reduce specificity or coverage modestly. |
| Hard | 45–80 | Wide variance is expected. Multi-layer encoding, hash dispatch, packing, and anti-analysis behaviors are genuine challenges. |

## Task Coverage Notes

The experimental manifest now mixes:

- 9 broad `default_analysis` tasks, one per executable variant
- 3 focused tasks that emphasize more discriminative evaluation modes:
  - concrete decoded-value recovery (`config_decoder_test.exe`)
  - hash-to-behavior mapping recovery (`hash_dispatch_test.exe`)
  - packing evidence + tool-triage reasoning (`embedded_payload_test_upx.exe`)

This keeps the default sweep broad enough to test high-level analysis quality while adding a small number of tasks that are better at separating:

- extraction accuracy vs. general explanation quality
- control-flow/dispatch reasoning vs. simple summarization
- tool-selection/orchestration quality vs. final narrative quality
