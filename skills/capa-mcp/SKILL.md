---
name: capa-mcp
description: Use when a task needs Mandiant capa through the local `runCapa` or `capaHelp` MCP tools, especially when forming a valid capa command string, choosing output mode, or avoiding path-quoting mistakes.
---

# capa MCP

Use this skill when working with the local `runCapa(...)` wrapper.

## Workflow

1. If you need flags, call `capaHelp()` first.
2. Reuse the exact validated sample path verbatim.
3. Wrap paths with spaces in double quotes.
4. Prefer `--` before the target path.
5. Pass the full capa command as one string to `runCapa(command=...)`.

## Tool Surface

- `runCapa(command, rules_dir=None, timeout_sec=300, output_mode="json_compact", max_rules=...)`
- `capaHelp(timeout_sec=5)`

## Command Rules

- `argv[0]` must be `capa` or `capa.exe`.
- Do not invent placeholder paths.
- Prefer `output_mode="json_compact"` unless the task explicitly needs full JSON or raw text.
- The server may auto-inject `-r <rules_dir>` and capa signatures if they are available locally.
- Add a `-t` tag when it helps organize intent, for example `-t analysis`.

## Example

```text
runCapa(
  command='capa -t analysis -- "C:\\Samples\\example.exe"',
  output_mode="json_compact"
)
```

## Avoid

- Unquoted sample paths with spaces.
- Raw text mode unless the task truly needs the full CLI view.
- Reusing example paths like `C:\path\to\your\program.exe`.
