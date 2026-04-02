# Stack Notice Scheduler Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This FLOSS-focused deception sample decodes eight minute offsets with XOR key 0x27, sorts them into local schedule windows, computes earliest/latest/gap summaries, and writes schedule_window_digest.txt while stack-built threat labels remain decoys.

## Why It Matters

- This sample is designed for the specific failure mode where an analysis over-trusts FLOSS output. Recovering the threatening labels is useful, but those labels are not the program's real behavior. A good report should identify the stack strings as decoys and describe the actual schedule decode, sort, and summary pipeline instead.

## Primary Techniques

- stage_recovery_queue decodes ENCODED_WINDOWS with key 0x27 and base minute 480
- collect_browser_cache is an insertion sort over the eight decoded schedule entries
- seed_watchlist_labels folds stack-built strings such as wipe_wallet_cache and schedule_hidden_sync into inert noise
- emit_recovery_notices contains dormant XOR-decoded notices behind a false gate

## Expected Analysis Signals

- Recover the real scheduling behavior rather than narrating the sample from FLOSS-decoded threat strings
- Recover the sorted schedule windows 485,500,515,530,545,560,575,600
- Identify schedule_window_digest.txt as the real local output path
- Call out the dormant decoded notices and stack-built labels as deceptive surfaces rather than live behavior

## Autodetected Key Functions

- `stage_recovery_queue`: autodetected helper function
- `collect_browser_cache`: autodetected helper function
- `summarize_windows`: autodetected helper function
- `ship_archive_manifest`: autodetected helper function
- `seed_watchlist_labels`: autodetected helper function
- `recover_notice`: autodetected helper function
- `false_watchlist_gate`: autodetected helper function
- `emit_recovery_notices`: autodetected helper function
- `main`: entry point and orchestration

## Recommended Tooling

- `flareflossmcp`
- `ghidramcp`
- `stringmcp`
- `CapaMCP`

## Related Binary Variants

- `stack_notice_scheduler_test.exe`
