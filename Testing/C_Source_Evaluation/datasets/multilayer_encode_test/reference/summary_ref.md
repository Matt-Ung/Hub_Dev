# Multilayer Encode Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This hard sample stores four strings behind a two-stage decode path: each byte is first rotated left by 3 and then XORed with 0x7E, while runtime recovery reverses the XOR and then rotates right.

## Why It Matters

- Single-byte XOR is the simplest encoding pattern and is well-handled by FLOSS.  This sample tests whether the pipeline can handle a slightly more complex scheme where FLOSS may partially recover strings (after XOR) but the ROL layer may cause garbled output. The analysis agents should: (a) identify the two-stage decode routine via Ghidra (b) use FLOSS to attempt string recovery (c) flag the C2-style indicators for YARA / capa matching This also tests whether YARA rules fire on the decoded content (they won't unless the binary is run or strings are extracted).

## Primary Techniques

- BLOB_MAGIC is 0xCAFED00D and is validated before any decode
- decode_entry reverses XOR_KEY 0x7E and ROL_BITS 3 for each entry
- The encoded strings include a C2 URL, a registry Run path, a schtasks persistence command, and an AppData temp path
- Entry metadata stores offset, length, rotation amount, and XOR key for each plaintext

## Expected Analysis Signals

- Recover https://c2.example.net/beacon/checkin
- Recover HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- Recover cmd.exe /c schtasks /create /sc minute /mo 15 /tn Updater
- Explain both encoding layers instead of flattening the sample into a simple XOR decoder

## Autodetected Key Functions

- `rol8`: autodetected helper function
- `ror8`: autodetected helper function
- `encode_string`: autodetected helper function
- `decode_entry`: decode or deobfuscation helper
- `init_blob`: initialization or configuration
- `main`: entry point and orchestration

## Recommended Tooling

- `flareflossmcp`
- `stringmcp`
- `ghidramcp`
- `CapaMCP`
- `yaramcp`

## Related Binary Variants

- `multilayer_encode_test.exe`
