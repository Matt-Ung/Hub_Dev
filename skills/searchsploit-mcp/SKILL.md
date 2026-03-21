---
name: searchsploit-mcp
description: Use when a task needs the local `searchsploitSearch`, `searchsploitExamine`, or `searchsploitHelp` MCP tools to search Exploit-DB offline or inspect a specific exploit entry.
---

# SearchSploit MCP

## Tool Surface

- `searchsploitSearch(query, exact=False, exclude=None, timeout_sec=60)`
- `searchsploitExamine(edb_id, timeout_sec=30, max_chars=20000)`
- `searchsploitHelp(timeout_sec=5)`

## Argument Guidance

- `query`: required search string.
- `exact=True`: stricter match behavior.
- `exclude`: list of terms to exclude from the search.
- `edb_id`: Exploit-DB ID for a specific exploit.

## Typical Pattern

1. Use `searchsploitSearch(...)` to find candidate EDB IDs.
2. Use `searchsploitExamine(...)` on the most relevant result.
