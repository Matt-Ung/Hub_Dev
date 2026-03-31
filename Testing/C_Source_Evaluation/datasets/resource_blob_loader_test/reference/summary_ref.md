# Resource Blob Loader Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This prototype loader sample validates a blob header, XOR-decodes a staged payload string, and computes a rolling checksum over the decoded content.

## Primary Techniques

- BlobHeader.magic must equal 0xB10B5EED
- decode_record XORs the payload with key 0x5A and computes a rolling checksum seeded at 0xABCDEF01
- The decoded payload string is STAGED: cmd.exe /c echo loader

## Expected Analysis Signals

- Recover the blob magic 0xB10B5EED
- Recover the decoded payload string STAGED: cmd.exe /c echo loader
- Explain that checksum is calculated after decode

## Autodetected Key Functions

- `rolling_checksum`: checksum helper
- `decode_record`: decode or deobfuscation helper
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `binwalkmcp`
- `CapaMCP`
- `upxmcp`

## Related Binary Variants

- `resource_blob_loader_test.exe`
- `resource_blob_loader_hard_stripped.exe`
- `resource_blob_loader_hard_upx.exe`
