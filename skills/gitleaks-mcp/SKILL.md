---
name: gitleaks-mcp
description: Use when a task needs the local `gitleaksScan`, `gitleaksScanContent`, or `gitleaksHelp` MCP tools to scan repositories, directories, or inline content for exposed secrets.
---

# Gitleaks MCP

## Tool Surface

- `gitleaksScan(target_path, no_git=False, timeout_sec=300)`
- `gitleaksScanContent(content, timeout_sec=120)`
- `gitleaksHelp(timeout_sec=5)`

## Argument Guidance

- `target_path`: repository or directory to scan.
- `no_git=True`: scan raw files/directories instead of relying on Git history/repo handling.
- `content`: inline text for quick single-buffer scans.

## Notes

- Prefer `gitleaksScan` for a real folder or repo.
- Prefer `gitleaksScanContent` for short pasted material or generated text.
- Findings are already masked by the wrapper, so use the structured result fields rather than asking for the raw secret.
