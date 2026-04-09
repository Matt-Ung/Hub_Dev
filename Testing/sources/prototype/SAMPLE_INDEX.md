# Prototype Test Source — Sample Index

## Overview

The prototype regression corpus contains 7 source files that currently produce
15 executable variants in `Testing/build/prototype/`.

This corpus is intentionally smaller and simpler than the experimental corpus.
It exists to catch harness regressions early: baseline control-flow recovery,
string recovery, anti-debug recognition, API-resolution reasoning, blob-loader
analysis, stripped-symbol recovery, and UPX-aware continuation.

The harness consumes [sample_manifest.json](sample_manifest.json) directly for:

- sample metadata
- difficulty labels
- judge anchors (`expected_evidence`, `acceptance_targets`)
- task definitions

There are no separate per-sample judge reference files for this corpus. The
manifest is the maintained source of truth.

## Sample Matrix

| # | Executable | Difficulty | Primary Techniques | Target MCP Tools | What It Validates |
|---|---|---|---|---|---|
| 1 | `test.exe` | Easy | Branch-heavy control flow, switch/jump table, integer decision logic | ghidramcp, CapaMCP | Baseline control-flow recovery. |
| 2 | `floss_test.exe` | Easy | Stack strings, XOR-decoded runtime strings | flareflossmcp, stringmcp, ghidramcp | Straightforward string-recovery baseline. |
| 3 | `floss_test_02.exe` | Medium | Same string logic under a different compiler layout | flareflossmcp, stringmcp, ghidramcp | Checks whether recovery survives layout changes. |
| 4 | `floss_test_stripped.exe` | Medium | Stripped symbols, stack strings, XOR-decoded strings | flareflossmcp, stringmcp, ghidramcp | Symbol-light string recovery. |
| 5 | `test_easy_stripped.exe` | Easy | Stripped symbols, control flow, switch dispatch | ghidramcp, CapaMCP | Control-flow recovery without symbols. |
| 6 | `anti_debug_test.exe` | Medium | Anti-debug APIs, timing checks | ghidramcp, CapaMCP, stringmcp | Debugger-detection recovery. |
| 7 | `anti_debug_medium_stripped.exe` | Medium | Stripped anti-debug and timing logic | ghidramcp, CapaMCP, stringmcp | Symbol-light anti-analysis recovery. |
| 8 | `winapi_behavior_test.exe` | Medium | Dynamic resolution, mutex, registry/URL artifacts | ghidramcp, CapaMCP, stringmcp | Program-level WinAPI behavior grounding. |
| 9 | `control_flow_flattened_test.exe` | Hard | Flattened dispatcher/state-machine pattern | ghidramcp, CapaMCP | Recovery of flattened control flow. |
| 10 | `api_hash_resolver_test.exe` | Hard | API hashing and delayed import resolution | ghidramcp, hashdbmcp, CapaMCP | Hash-based resolver reasoning. |
| 11 | `resource_blob_loader_test.exe` | Hard | Embedded blob, staged decode path | ghidramcp, binwalkmcp, CapaMCP | Payload-container and staged extraction analysis. |
| 12 | `resource_blob_loader_hard_stripped.exe` | Hard | Stripped blob-loader behavior | ghidramcp, binwalkmcp, CapaMCP | Symbol-light staged extraction recovery. |
| 13 | `test_easy_upx.exe` | Easy | UPX packing over baseline control flow | upxmcp, ghidramcp, CapaMCP | Packed-wrapper control-flow continuation. |
| 14 | `anti_debug_medium_upx.exe` | Medium | UPX packing over anti-debug logic | upxmcp, ghidramcp, CapaMCP, stringmcp | Packed anti-analysis continuation. |
| 15 | `resource_blob_loader_hard_upx.exe` | Hard | UPX packing over staged blob extraction | upxmcp, ghidramcp, binwalkmcp, CapaMCP | Separation of packing from underlying payload-loader logic. |

## Task Coverage Notes

The prototype corpus now uses the same manifest convention as the experimental
corpus:

- one explicit `default_analysis` task per executable variant
- explicit `expected_evidence`
- explicit `acceptance_targets`

Unlike the experimental corpus, the prototype corpus intentionally does not add
many focused follow-up tasks. It is a smoke and regression corpus first.

## Build Commands

```bash
make -C Testing/sources/prototype all-with-gcc
make -C Testing/sources/prototype upx
make -C Testing/sources/prototype clean
```

## Coverage Intent

Use the prototype corpus when you want to answer questions like:

- Is the harness running end to end?
- Are bundle preparation and judging healthy?
- Did a change break basic control-flow or string-recovery analysis?
- Are stripped and packed variants still being handled consistently?

Use the experimental corpus when you need broader and more discriminative
evaluation tasks.
