---
name: binary-patch-mcp
description: Use when the task requires emitting a patched binary copy through the local MCP tool lane, especially for short instruction patches or explicit byte replacements.
---

# Binary Patch MCP

Use this skill when the user explicitly wants a patched output binary on disk.

## Tool Surface

- `binaryPatchHelp()`
- `binaryPatchInspect(...)`
- `binaryPatchBytes(...)`
- `binaryPatchAssemble(...)`

## Best-Fit Tasks

- Patch a copied binary at a known file offset, RVA, or VA
- Replace a short instruction sequence with assembled bytes
- Validate expected original bytes before applying a patch
- Keep reverse engineering and emitted patching as separate steps

## Guidance

- Prefer Ghidra for understanding the binary and deciding what to patch.
- Prefer `binaryPatchInspect(...)` before patching when the target addressing needs confirmation.
- Prefer writing to a new `output_path`, not overwriting the original sample.
- Use `expected_original_hex` when you know the original bytes and want a guardrail.
- Treat this as an output-emission tool, not an analysis tool.
