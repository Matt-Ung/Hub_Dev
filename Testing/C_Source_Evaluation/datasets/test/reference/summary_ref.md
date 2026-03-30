# Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This prototype sample exercises simple branch reconstruction: helper handles negative and zero specially, classify uses a switch on v & 7, and main prints low/mid/high before applying a final parity-based +/-3 adjustment.

## Primary Techniques

- helper iterates from i=0 to i<x, alternately adding and subtracting i and breaking early if acc > 50
- classify returns 10 through 17 via a switch on (v & 7)
- main prints 'neg', 'low', 'mid', or 'high' before printing the final adjusted integer

## Expected Analysis Signals

- Identify the switch/jump-table style classification on v & 7
- Note the early break in helper when acc > 50
- Explain the final ternary-like parity adjustment: odd -> c+3, even -> c-3

## Autodetected Key Functions

- `helper`: autodetected helper function
- `classify`: classification helper
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `CapaMCP`
- `upxmcp`

## Related Binary Variants

- `test.exe`
- `test_easy_stripped.exe`
- `test_easy_upx.exe`
