# Floss Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This prototype string-recovery sample combines a static URL, a stack-built command string, and a runtime XOR-decoded library name.

## Primary Techniques

- The static literal is STATIC: https://example.com/api/v1/ping
- The stack-built string is STACK: cmd.exe /c whoami
- xor_decode recovers DECODED: kernel32.dll from bytes XORed with 0x55

## Expected Analysis Signals

- Recover all three concrete strings
- Distinguish the static, stack-built, and XOR-decoded storage styles
- Identify xor_decode as the helper that produces the decoded library name

## Autodetected Key Functions

- `xor_decode`: decode or deobfuscation helper
- `main`: entry point and orchestration

## Recommended Tooling

- `flareflossmcp`
- `stringmcp`
- `ghidramcp`

## Related Binary Variants

- `floss_test.exe`
- `floss_test_02.exe`
- `floss_test_stripped.exe`
