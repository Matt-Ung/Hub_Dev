# Maintenance Orchestrator Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This deceptive-surface sample decodes a fixed XOR-protected operation script, renders a 12x8 in-memory snapshot, computes a checksum and row sums, and writes a local maintenance report while surrounding that flow with threatening but inert labels and decoy handlers.

## Primary Techniques

- unlock_quarantine_schedule XOR-decodes eight 4-byte SnapshotOp records with key 0x5A
- install_boot_autorun, wipe_shadow_catalog, stage_domain_cache, and queue_remote_archive actually manipulate the local 12x8 cell grid
- export_credential_sheet computes checksum, nonzero count, max value, and row sums over the rendered grid
- ship_archive_to_control writes maintenance_snapshot_report.txt locally, while audit_quarantine_manifest and prime_recovery_notices only preserve threatening labels as inert noise or dead-branch decoys

## Expected Analysis Signals

- Recover maintenance_snapshot_report.txt as the real local output path
- Identify the live opcodes 0x11, 0x22, 0x33, and 0x44 as the ones present in the decoded script
- Call out strings such as wipe_restore_points and schedule_hidden_boot_task as misleading labels rather than evidence of executed malicious behavior
- Separate the dormant 0x90/0x91/0x92 handler family and the query_recovery_slot branch from the live snapshot-rendering path

## Autodetected Key Functions

- `clamp_cell_value`: autodetected helper function
- `install_boot_autorun`: autodetected helper function
- `wipe_shadow_catalog`: output or logging
- `stage_domain_cache`: autodetected helper function
- `queue_remote_archive`: autodetected helper function
- `disable_recovery_checkpoints`: autodetected helper function
- `export_credential_cache`: autodetected helper function
- `schedule_reboot_persistence`: autodetected helper function
- `audit_quarantine_manifest`: anti-analysis or debug-related
- `recover_notice_block`: autodetected helper function
- `query_recovery_slot`: autodetected helper function
- `prime_recovery_notices`: autodetected helper function
- `unlock_quarantine_schedule`: anti-analysis or debug-related
- `run_maintenance_cycle`: main execution or dispatch routine
- `export_credential_sheet`: autodetected helper function
- `ship_archive_to_control`: autodetected helper function
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `stringmcp`
- `flareflossmcp`
- `CapaMCP`

## Related Binary Variants

- `maintenance_orchestrator_test.exe`
- `maintenance_orchestrator_test_stripped.exe`
