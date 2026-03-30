# Basic Loops Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This baseline sample computes the sum 1..N, classifies that result into buckets, accumulates an integer array until a -1 sentinel is seen, and then runs a countdown loop.

## Why It Matters

- This sample establishes the decompilation-accuracy baseline. If the analysis pipeline cannot cleanly reconstruct this sample, something is fundamentally wrong with the Ghidra integration or the planner's work-item targeting.  It also provides a floor for the Quality Score (QS) metric: every experimental condition should score >= QS of this sample.

## Primary Techniques

- compute_sum performs a simple 1..N summation loop
- classify_value maps totals into -1/0/1/2/3 via an if/else ladder
- accumulate stops early when it encounters the sentinel value -1
- main calls compute_sum, classify_value, accumulate, and then a separate countdown while-loop

## Expected Analysis Signals

- Call graph: main -> compute_sum, classify_value, accumulate
- The sample array is {5, 10, 15, -1, 99, 200} and accumulate should stop at -1
- If argc > 1 then base=20, otherwise base=10
- No encoding, packing, or anti-analysis behavior should be claimed

## Autodetected Key Functions

- `compute_sum`: computation helper
- `classify_value`: classification helper
- `accumulate`: computation helper
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `stringmcp`
- `CapaMCP`

## Related Binary Variants

- `basic_loops_test.exe`
