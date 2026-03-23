---
name: trivy-mcp
description: Use when a task needs the local `trivyScan` or `trivyHelp` MCP tools to scan a filesystem path, repo, config, SBOM, or image for vulnerabilities and misconfigurations.
---

# Trivy MCP

## Tool Surface

- `trivyScan(target, scan_type="filesystem", severity=None, ignore_unfixed=False, timeout_sec=600, output_mode="json_compact")`
- `trivyHelp(timeout_sec=5)`

## Argument Guidance

- `target`: local path for `filesystem`, `repo`, `config`, or `sbom`; image reference for `image`.
- `scan_type`: one of `image`, `filesystem`, `repo`, `config`, `sbom`.
- `severity`: optional list such as `["HIGH", "CRITICAL"]`.
- `ignore_unfixed=True`: suppress unfixed issues.
- `output_mode="json_compact"`: best default for summaries.

## Notes

- Use `json_full` only when the task needs the full Trivy document.
- Use `text` only when a raw CLI-style view is specifically needed.
