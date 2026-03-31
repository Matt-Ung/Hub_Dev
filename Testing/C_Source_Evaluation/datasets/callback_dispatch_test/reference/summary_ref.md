# Callback Dispatch Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This sample implements an array-backed function-pointer dispatcher that walks five handlers in order, updates an ExecContext, and aborts early if any indirect handler returns an error.

## Why It Matters

- Indirect calls through function pointer tables are a common source of incomplete or incorrect Ghidra decompilation.  The decompiler may show `(*pfn)(arg)` without resolving which function is called. This tests whether the analysis pipeline's agents can: (a) identify the dispatch table in .rdata (b) enumerate the concrete target functions (c) explain the state machine that sequences commands capa should flag "dispatch function by index" or similar behavioral rules.  The error-handling branches add realistic control-flow complexity that planners must decompose into work items.

## Primary Techniques

- COMMAND_TABLE pairs INIT/LOAD/TRANSFORM/VALIDATE/FINALIZE with concrete handler pointers
- run_dispatch performs an indirect call through COMMAND_TABLE[i].handler
- cmd_load fails if arg < 0 and cmd_validate fails if result_acc is outside 0..100000
- trace_push records execution order as pipe-delimited tokens such as init|load|transform|validate|finalize

## Expected Analysis Signals

- Recover the five dispatch entries and their corresponding handlers
- Explain the IDLE -> RUNNING -> DONE / ERROR state progression
- Note that argc changes the LOAD argument from 10 to 42
- Describe the indirect call site rather than treating handlers as unrelated functions

## Autodetected Key Functions

- `trace_push`: trace or state-logging helper
- `cmd_init`: dispatch handler
- `cmd_load`: dispatch handler
- `cmd_transform`: dispatch handler
- `cmd_validate`: dispatch handler
- `cmd_finalize`: dispatch handler
- `run_dispatch`: main execution or dispatch routine
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `CapaMCP`
- `stringmcp`
- `flareflossmcp`

## Related Binary Variants

- `callback_dispatch_test.exe`
