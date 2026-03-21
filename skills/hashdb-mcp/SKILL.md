---
name: hashdb-mcp
description: Use when a task needs the local `resolve_hash_in_hashdb_to_plain` MCP tool to look up hashed API names or constants in HashDB.
---

# HashDB MCP

## Tool Surface

- `resolve_hash_in_hashdb_to_plain(algorithm, hash_value)`

## Argument Guidance

- `algorithm`: HashDB algorithm name such as `crc32`, `fnv1a_32`, or another supported identifier.
- `hash_value`: integer, decimal string, hex string, or `0x...` string.

## Notes

- Prefer exact algorithm names; do not guess loosely.
- If the algorithm is uncertain, say so instead of forcing a lookup.
- Use this tool to corroborate hashed-import or hashed-string hypotheses, not as standalone proof.
