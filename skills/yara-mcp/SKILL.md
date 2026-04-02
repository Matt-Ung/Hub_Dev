---
name: yara-mcp
description: Use when a task needs the local YARA MCP tools `yaraScan`, `yaraScanInline`, `yaraWriteRule`, `yaraListRules`, or `yaraHelp`, including choosing whether to scan with a saved rule file, inline rule text, or persist a rule into the standardized generated-artifact YARA directory.
---

# YARA MCP

Use this skill for structured YARA scanning through the local MCP server.

## Tool Surface

- `yaraScan(target_path, rules_path="", recursive=True, show_strings=False, timeout_sec=300)`
- `yaraScanInline(target_path, rule_text, recursive=True, show_strings=False, timeout_sec=300)`
- `yaraListRules(max_rules=200)`
- `yaraWriteRule(rule_text, filename="", overwrite=False, validate=True, timeout_sec=15)`
- `yaraHelp(timeout_sec=5)`

## When To Use Which Tool

- Use `yaraScan` when you already have a saved `.yar` or `.yara` rule file.
- Use `yaraScanInline` for one-off rule text that should not be persisted.
- Use `yaraWriteRule` when you want to persist a rule into the standardized generated-artifact YARA directory and make it available to default YARA scans.
- Use `yaraListRules` to inspect both the base YARA rules and the generated YARA rules.
- Use `yaraHelp` when you need raw CLI help output.

## Argument Guidance

- `target_path`: file or directory to scan.
- `rules_path`: optional saved rule file; omit it to use the default combined base-plus-generated rule set.
- `recursive`: mainly matters for directory targets.
- `show_strings=True`: include string match details when the task needs them.
- `filename`: optional simple file name for `yaraWriteRule`; otherwise the first rule name is used.
- `validate=True`: syntax-check the rule before writing when `yara` is installed.

## Notes

- Base rules come from the configured `YARA_RULES_DIR`.
- If `YARA_RULES_DIR` is unset, this repo prefers `./third_party/signature-base`.
- `MCPServers/yara_rules` is only a legacy fallback path.
- Generated rules default to `AGENT_ARTIFACT_DIR/yara`.
- `yaraWriteRule` refreshes `index.yar` in the generated-rules directory, and default scans include both the base rules and generated rules when `rules_path` is omitted.
- Prefer concise, specific rules over broad noisy conditions.
