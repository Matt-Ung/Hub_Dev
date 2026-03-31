# Control Flow Flattened Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This prototype control-flow sample implements a flattened state machine with an opaque predicate and trace tokens that reveal which states were traversed.

## Primary Techniques

- run_flattened switches over ctx->state and continues until state 99 or steps reach 40
- opaque_predicate mixes input, steps, and branch_mask to choose path_a or path_b
- trace tokens include entry, dispatch, path_a, path_b, loop, final, and invalid

## Expected Analysis Signals

- Recover the dispatcher/state-machine pattern rather than narrating it as linear control flow
- Identify the opaque predicate as the branch selector between path_a and path_b
- Explain the loop state that rotates branch_mask and may return to dispatch

## Autodetected Key Functions

- `trace_push`: trace or state-logging helper
- `opaque_predicate`: dead code or opaque predicate
- `run_flattened`: main execution or dispatch routine
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `CapaMCP`

## Related Binary Variants

- `control_flow_flattened_test.exe`
