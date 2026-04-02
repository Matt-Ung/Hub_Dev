# Hash Dispatch Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This sample hashes stack-built command strings with DJB2 and resolves them through a hash-to-handler dispatch table that mixes live entries with dead decoy hashes.

## Why It Matters

- API hashing is one of the most common obfuscation techniques in real malware.  This sample tests whether: (a) Ghidra agents can identify the hash algorithm (DJB2 variant) (b) hashdb MCP can look up known hash values (c) FLOSS can recover the stack-built command strings (d) capa flags "resolve function by hash" behavioral rules (e) the planner produces work items that cover both the hash algorithm and the dispatch table The dead/decoy entries test whether the analysis avoids false positives from unused hash values.

## Primary Techniques

- djb2_hash starts at 5381 and updates h = h*33 + c
- DISPATCH_TABLE maps HASH_PING, HASH_EXEC, HASH_EXFIL, and HASH_SLEEP to live handlers
- HASH_DEAD_1 0xDEADBEEF and HASH_DEAD_2 0xFEEDFACE intentionally map to nop_handler
- build_and_dispatch copies command characters into a local buffer before hashing and indirect dispatch

## Expected Analysis Signals

- Map 0x7C9C4733 to ping and 0x7C967DAA to exec
- Recover the stack-built command strings ping, exec, exfil, and sleep
- Identify the decoy dead entries separately from the live commands
- Explain the indirect call through the resolved function pointer

## Autodetected Key Functions

- `djb2_hash`: resolution or hash-processing helper
- `cmd_ping`: dispatch handler
- `cmd_exec`: dispatch handler
- `cmd_exfil`: dispatch handler
- `cmd_sleep`: dispatch handler
- `nop_handler`: callback or event handler
- `resolve_command`: resolution or hash-processing helper
- `build_and_dispatch`: main execution or dispatch routine
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `hashdbmcp`
- `flareflossmcp`
- `CapaMCP`
- `stringmcp`

## Related Binary Variants

- `hash_dispatch_test.exe`
- `hash_dispatch_test_stripped.exe`
