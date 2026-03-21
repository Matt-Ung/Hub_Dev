---
name: strings-mcp
description: Use when a task needs the local `callStrings` MCP tool to run the `strings` utility on a file and get a quick preview of extracted strings.
---

# Strings MCP

## Tool Surface

- `callStrings(file_path, min_len=4)`

## Argument Guidance

- `file_path`: local sample path.
- `min_len`: minimum candidate string length.

## Notes

- This wrapper returns only a short preview of the strings output.
- Use it for quick pivots, not for exhaustive string recovery.
- For deeper string recovery, prefer the FLOSS workflow when appropriate.
