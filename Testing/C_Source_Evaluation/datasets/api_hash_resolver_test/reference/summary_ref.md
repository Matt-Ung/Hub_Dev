# Api Hash Resolver Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This prototype API-resolution sample decodes API names from XOR-protected buffers, hashes them with case-insensitive FNV-1a, and resolves Sleep, GetTickCount, and GetCurrentProcessId.

## Primary Techniques

- fnv1a_ci starts at 2166136261 and multiplies by 16777619 after XORing each lowercased byte
- decode_name XOR-decodes API names using key 0x33
- resolve_api_by_hash resolves Sleep, GetTickCount, and GetCurrentProcessId from kernel32.dll or local stubs

## Expected Analysis Signals

- Recover the API names Sleep, GetTickCount, and GetCurrentProcessId
- Identify the FNV-1a style hashing loop
- Explain that the sample delays import resolution until the decoded hash is matched

## Autodetected Key Functions

- `stub_Sleep`: autodetected helper function
- `stub_GetTickCount`: autodetected helper function
- `stub_GetCurrentProcessId`: autodetected helper function
- `resolve_stub_proc`: resolution or hash-processing helper
- `fnv1a_ci`: autodetected helper function
- `decode_name`: decode or deobfuscation helper
- `resolve_api_by_hash`: resolution or hash-processing helper
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `hashdbmcp`
- `CapaMCP`

## Related Binary Variants

- `api_hash_resolver_test.exe`
