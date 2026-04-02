# Signal Router Report Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This medium deception sample decodes a small XOR-protected routing plan, updates four local counters, computes a simple checksum/peak summary, and writes a local bar-style report while threatening labels remain inert.

## Why It Matters

- This sample is meant to sit between the obvious baseline binaries and the harder low-leakage deception cases. It checks whether an agent can avoid over-claiming from strings like wipe_restore_chain or ship_token_archive while still recovering the actual behavior from the live routing logic. The true behavior is not hidden behind heavy obfuscation. A careful analyst can recover it through ordinary decompilation and control-flow reasoning, but not by reading strings alone.

## Primary Techniques

- decode_signal_plan XOR-decodes eight 4-byte operations with key 0x3C
- wipe_restore_chain increments one lane, seed_remote_beacon applies a floor, and collect_credential_rows splits a delta across adjacent lanes
- fold_noise_labels preserves cleartext decoy labels as inert referenced data
- write_signal_report writes the runtime-decoded signal_router_report.txt path locally

## Expected Analysis Signals

- Recover the four-lane local counter model and the final totals 8,5,11,4
- Identify wipe_restore_chain and ship_token_archive as misleading labels rather than destructive behavior
- Separate the dead 0x91 / 0xA2 handler family from the live routing opcodes
- Describe the bar-style local report output rather than inventing network or credential behavior

## Autodetected Key Functions

- `clamp_lane`: autodetected helper function
- `wipe_restore_chain`: autodetected helper function
- `seed_remote_beacon`: autodetected helper function
- `collect_credential_rows`: autodetected helper function
- `drop_recovery_chain`: autodetected helper function
- `ship_token_archive`: autodetected helper function
- `fold_noise_labels`: autodetected helper function
- `decode_report_path`: decode or deobfuscation helper
- `decode_signal_plan`: decode or deobfuscation helper
- `run_signal_plan`: main execution or dispatch routine
- `summarize_lanes`: autodetected helper function
- `write_signal_report`: autodetected helper function
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `stringmcp`
- `CapaMCP`

## Related Binary Variants

- `signal_router_report_test.exe`
