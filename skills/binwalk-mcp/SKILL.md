---
name: binwalk-mcp
description: Use when a task needs the local `binwalkScan`, `listBinwalkExtraction`, or `binwalkHelp` MCP tools to scan a file for embedded content, optionally extract it, or inspect extraction results.
---

# Binwalk MCP

## Tool Surface

- `binwalkScan(file_path, extract=False, entropy=False, hexdump=False, matryoshka=False, timeout_sec=300)`
- `listBinwalkExtraction(extraction_path, max_files=200)`
- `binwalkHelp(timeout_sec=5)`

## Argument Guidance

- `file_path`: local file to scan.
- `extract=True`: unpack discovered content into a generated extraction directory.
- `entropy=True`: include entropy output.
- `hexdump=True`: include hexdump-style output.
- `matryoshka=True`: recurse into nested embedded content.

## Typical Pattern

1. Run `binwalkScan(...)`.
2. If extraction was enabled, inspect `extraction_path`.
3. Use `listBinwalkExtraction(...)` to enumerate extracted files.
