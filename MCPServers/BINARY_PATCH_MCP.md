# Binary Patch MCP

## Purpose

`binaryPatchMCP.py` adds a bounded binary-rewrite tool lane to the repo.

Use it when you need to emit a patched output binary on disk. Do not use it as
a replacement for Ghidra's reverse-engineering workflow.

## Dependencies

- `lief`
- `keystone-engine`

Install through the repo `requirements.txt`, or install them manually:

```bash
pip install lief keystone-engine
```

## Tool Surface

- `binaryPatchHelp()`
- `binaryPatchInspect(...)`
- `binaryPatchBytes(...)`
- `binaryPatchAssemble(...)`

## Intended Use

Good fits:

- write a patched copy to a new output path
- replace a short instruction sequence with assembled bytes
- apply a known byte patch at a file offset, RVA, or VA
- preserve a clear distinction between analysis and emitted patch output

Bad fits:

- replacing Ghidra for decompilation, names, comments, or type recovery
- open-ended binary rewriting without a clear target address and patch intent
- patching in place without an explicit copied output path

## Addressing Model

Patch tools support:

- `file_offset`
- `rva`
- `va`

Use `file_offset` when you want the most deterministic behavior.

## Safety Notes

- The server writes patched copies to `output_path`.
- It can overwrite an existing output only with `force=true`.
- It supports `expected_original_hex` so you can verify the original bytes before writing the patch.

## Example

Replace a function prologue with `xor eax, eax; ret` at a VA:

```text
binaryPatchAssemble(
  file_path="/path/to/input.exe",
  output_path="/path/to/patched.exe",
  assembly="xor eax, eax; ret",
  address="0x140001000",
  address_kind="va",
  architecture="x86_64",
  patch_size=4,
  pad_mode="nop"
)
```

Apply raw bytes at a file offset:

```text
binaryPatchBytes(
  file_path="/path/to/input.exe",
  output_path="/path/to/patched.exe",
  hex_bytes="90 90 90 90",
  address="0x4010",
  address_kind="file_offset"
)
```
