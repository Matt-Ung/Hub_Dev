# Branch Weave Snapshot Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This low-leakage hard deception sample XOR-decodes a compact drawing program, applies it to an 8x8 local grid, computes terse summary fields, and writes a short local report while threat-themed labels remain misleading or dormant.

## Why It Matters

- This sample is intended to be harder than the earlier deception binaries. A strings-only pass should recover the threatening decoys, but it should not recover enough to narrate the real behavior confidently. Recovering the program's purpose requires following the decoded instruction stream and the live grid-update handlers.

## Primary Techniques

- decode_branch_program XOR-decodes ten 4-byte operations with key 0x4D
- flush_ticket_vault, ship_shadow_bundle, drop_recovery_mesh, and erase_domain_secrets are misleadingly named live handlers that mutate the local 8x8 grid
- write_grid_report writes the runtime-decoded bw_grid_report.txt path using terse fields such as d=, o=, c=, and g:
- emit_false_notices and the 0x91 / 0xA2 / 0xB3 handler family preserve decoy strings and dead behavior for analysis without affecting the live grid path

## Expected Analysis Signals

- Recover the 8x8 local-grid behavior and short report-writing path even though the sample has minimal explanatory strings
- Identify the live opcodes 0x11, 0x22, 0x33, and 0x44 as the actual program family
- Call out strings such as flush_ticket_vault and ship_shadow_bundle as deceptive labels rather than destructive behavior
- Separate the dormant decoded notices and dead handler family from the live execution path

## Autodetected Key Functions

- `clamp_shade`: autodetected helper function
- `flush_ticket_vault`: autodetected helper function
- `ship_shadow_bundle`: autodetected helper function
- `drop_recovery_mesh`: autodetected helper function
- `erase_domain_secrets`: autodetected helper function
- `disable_boot_catalog`: output or logging
- `export_ticket_queue`: autodetected helper function
- `seed_reboot_branch`: autodetected helper function
- `fold_false_labels`: autodetected helper function
- `decode_report_path`: decode or deobfuscation helper
- `recover_notice`: autodetected helper function
- `false_notice_gate`: autodetected helper function
- `emit_false_notices`: autodetected helper function
- `decode_branch_program`: decode or deobfuscation helper
- `run_branch_program`: main execution or dispatch routine
- `summarize_grid`: autodetected helper function
- `write_grid_report`: autodetected helper function
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `flareflossmcp`
- `stringmcp`
- `CapaMCP`

## Related Binary Variants

- `branch_weave_snapshot_test.exe`
- `branch_weave_snapshot_test_stripped.exe`
