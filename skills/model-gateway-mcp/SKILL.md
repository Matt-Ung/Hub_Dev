---
name: model-gateway-mcp
description: Use when a task would benefit from a secondary model call through the local MCP tool lane, especially for Hugging Face or OpenAI-compatible inference, decompilation cleanup, classification, or comparing competing interpretations.
---

# Model Gateway MCP

Use this skill when the workflow should call a non-default model through MCP rather than relying only on the main agent model.

## Tool Surface

- `listAltModelBackends()`
- `generateWithAltModel(...)`
- `classifyWithAltModel(...)`
- `compareModelOutputs(...)`
- `recoverDecompilationWithAltModel(...)`

## Best-Fit Tasks

- Decompiler cleanup and source-like rewriting from deterministic Ghidra output
- Better naming or type hypotheses for a decompiled snippet
- Malware-family or style classification
- Comparing two candidate explanations or reports
- Getting a second opinion from an open-weight or specialized model

## Guidance

- Prefer deterministic tools first for facts.
- Use the alternate model as an advisory assistant, not as the primary evidence source.
- If the alternate model suggests names or types, validate them against imports, strings, xrefs, disassembly, decompilation, and call patterns before presenting them as findings or queueing edits.
- `recoverDecompilationWithAltModel(...)` is the best fit when the task resembles neural decompilation or type/name recovery work.
