---
name: floss-mcp
description: Use when a task needs FLOSS through the local `runFloss` or `flossHelp` MCP tools, especially when forming a valid FLOSS command string, choosing flags, or handling quoted paths.
---

# FLOSS MCP

Use this skill when working with the local `runFloss(...)` wrapper.

## Workflow

1. Call `flossHelp()` before building a new command string.
2. Reuse the exact validated sample path verbatim.
3. Wrap paths with spaces in double quotes.
4. Prefer `--` before the target path.
5. Pass the complete FLOSS command as one string.

## Tool Surface

- `runFloss(command, timeout_sec=300)`
- `flossHelp(timeout_sec=5)`

## Command Rules

- `argv[0]` must be `floss` or `floss.exe`.
- Do not use placeholder/example paths.
- Prefer JSON output when machine-readable recovered strings or metadata are needed.
- The wrapper strips FLOSS progress-bar noise, so focus on the meaningful output.

## Example

```text
runFloss(
  command='floss --json -- "C:\\Samples\\example.exe"'
)
```

## Avoid

- Split, unquoted paths with spaces.
- Running FLOSS before checking `flossHelp()` when you are unsure about flags.
- Treating placeholder paths as real targets.
