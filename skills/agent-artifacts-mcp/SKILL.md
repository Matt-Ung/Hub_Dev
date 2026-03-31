---
name: agent-artifacts-mcp
description: Use when a task should persist reusable helper files such as Python deobfuscation scripts, Java helpers, reports, or Ghidra-supporting snippets into the standardized agent artifact directory tree.
---

# Agent Artifacts MCP

Use this skill when generated helper code should be written to disk in a predictable repo-aware location instead of being left only inline in the response.

## Tool Surface

- `agentArtifactPaths()`
- `writeTextArtifact(artifact_type, content, filename="", overwrite=False, subdir="", description="")`
- `writePythonArtifact(content, filename="", overwrite=False, subdir="", description="", ghidra_script=False)`
- `writeJavaArtifact(content, filename="", overwrite=False, subdir="", description="", ghidra_script=False)`
- `listAgentArtifacts(artifact_type="", max_results=200)`
- `agentArtifactHelp()`

## When To Use Which Tool

- Use `writePythonArtifact` for deobfuscation helpers, decoders, unpackers, or standalone analysis utilities.
- Use `writeJavaArtifact` for Java helpers or Java-based Ghidra support code.
- Set `ghidra_script=True` when the helper is meant to live under the `ghidra/` artifact directory instead of the generic `python/` or `java/` directory.
- Use `writeTextArtifact` for generic reports or future typed text artifacts.
- Use `agentArtifactPaths` when you need to confirm where the configured artifact root and typed subdirectories currently resolve.

## Argument Guidance

- `filename`: simple file name only; do not pass a path.
- `subdir`: optional nested grouping under the typed artifact directory, for example a sample slug like `labos`.
- `overwrite=True`: only when replacing a previous generated helper intentionally.
- `description`: short note about why the helper was generated.

## Notes

- Artifact output is controlled by `AGENT_ARTIFACT_DIR` and optional per-type overrides in `.env`.
- Generated YARA rules should still go through `yaraWriteRule` so they can be validated and indexed correctly.
