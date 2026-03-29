---
name: yara-rule-authoring
description: Use when writing, reviewing, or explaining YARA rule syntax, or when preparing `rule_text` for `yaraScanInline` or `yaraWriteRule` so the rule can be saved into the standardized generated-artifact YARA directory.
---

# YARA Rule Authoring

Use this skill when the task is to produce valid YARA rule text, not just to run YARA.

Read [references/quick-syntax.md](references/quick-syntax.md) for the skeletons and examples.

## Workflow

1. Pick a stable rule name with lowercase words and underscores.
2. Include `meta`, `strings`, and `condition`.
3. Keep the condition readable and directly tied to the intended detection logic.
4. If the rule is for PE-specific logic, use `import "pe"` and explicit `pe.*` checks.
5. Return a complete rule block that can be saved directly as a `.yar` file.

## Output Rules

- If the user wants a rule, output ready-to-save YARA text.
- If the user wants explanation, keep the explanation brief and still show the final rule.
- Avoid undefined modules, undefined string identifiers, or conditions that cannot compile.

## Repository Context

- This repository already has `yaraScanInline(...)` for one-off scans.
- This repository now also has `yaraWriteRule(...)` for persisting validated rule text into the standardized generated-artifact YARA directory.
- The same rule text should work for both inline scans and persistent rule files.
