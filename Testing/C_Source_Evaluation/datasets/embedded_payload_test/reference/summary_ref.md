# Embedded Payload Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This sample builds an embedded payload blob with a PLOD header, validates a rolling checksum, and then decodes multiple XOR-protected records representing a path, a URL, and configuration data while skipping dead padding records.

## Why It Matters

- This exercises the full chain of binary analysis tools: (a) binwalk should detect the embedded blob via magic signature (b) strings/FLOSS should recover decoded record contents (c) Ghidra should reconstruct the header parsing, checksum algorithm, and per-record decode loop (d) capa should flag "embedded payload", "decode data", "validate checksum" The UPX MCP server can be exercised by packing this binary post-compilation (the Makefile includes a UPX target). The multi-record structure tests whether the planner generates separate work items for header analysis vs. payload analysis.

## Primary Techniques

- PAYLOAD_MAGIC is 0x504C4F44 ('PLOD') and PAYLOAD_VERSION is 2
- rolling_checksum rotates the accumulator left by 5, XORs the next byte, and adds 0x9E3779B9
- Record 0 decodes to C:\Windows\Temp\stage2.dll, record 1 decodes to https://dl.example.org/payload/v3, and record 3 decodes to interval=300;retry=5;jitter=30
- Records with type 0xFF are dead padding and should be ignored rather than treated as live payloads

## Expected Analysis Signals

- Recover the PLOD header or magic 0x504C4F44
- Explain the staged order: magic check -> checksum check -> per-record decode
- Separate live PATH/URL/CONFIG records from dead 0xFF padding records
- Recognize the per-record XOR keys 0xAA, 0x55, and 0x37

## Autodetected Key Functions

- `rolling_checksum`: checksum helper
- `xor_encode`: decode or deobfuscation helper
- `xor_decode`: decode or deobfuscation helper
- `init_payload`: initialization or configuration
- `extract_and_decode`: decode or deobfuscation helper
- `main`: entry point and orchestration

## Recommended Tooling

- `binwalkmcp`
- `flareflossmcp`
- `stringmcp`
- `ghidramcp`
- `CapaMCP`
- `upxmcp`

## Related Binary Variants

- `embedded_payload_test.exe`
- `embedded_payload_test_upx.exe`
