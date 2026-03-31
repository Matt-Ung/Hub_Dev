# Agent Artifacts MCP

`MCPServers/agentArtifactsMCP.py` provides a standardized write path for reusable agent-generated files.

## Purpose

Use this MCP server when the agent should persist helper artifacts instead of leaving them only inline in the chat or report. Typical outputs:

- Python deobfuscation helpers
- Java helpers
- Ghidra-supporting scripts
- Generated reports or notes

Generated YARA rules should still be written with `yaraWriteRule(...)` from `yaraMCP.py`, but they use the same shared artifact-root policy.

## Directory Layout

The shared path logic lives in `artifact_paths.py`.

Default layout:

```text
agent_artifacts/
  yara/
  python/
  java/
  reports/
  ghidra/
```

Env overrides:

```dotenv
AGENT_ARTIFACT_DIR=./agent_artifacts
AGENT_YARA_ARTIFACT_DIR=
AGENT_PYTHON_ARTIFACT_DIR=
AGENT_JAVA_ARTIFACT_DIR=
AGENT_REPORT_ARTIFACT_DIR=
AGENT_GHIDRA_ARTIFACT_DIR=
```

If a per-type override is blank, the server falls back to `AGENT_ARTIFACT_DIR/<type>`.

## Tools

- `agentArtifactPaths()`
- `writeTextArtifact(artifact_type, content, filename="", overwrite=False, subdir="", description="")`
- `writePythonArtifact(content, filename="", overwrite=False, subdir="", description="", ghidra_script=False)`
- `writeJavaArtifact(content, filename="", overwrite=False, subdir="", description="", ghidra_script=False)`
- `listAgentArtifacts(artifact_type="", max_results=200)`
- `agentArtifactHelp()`

## Examples

Write a Python XOR helper:

```python
writePythonArtifact(
    content=\"\"\"def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)
\"\"\",
    filename="xor_helper.py",
    subdir="labos",
    description="Helper for testing single-byte XOR decoding on recovered blobs.",
)
```

Write a Java helper intended for Ghidra support:

```python
writeJavaArtifact(
    content=\"\"\"public class XorHelper {
    public static byte[] xor(byte[] data, byte key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte)(data[i] ^ key);
        return out;
    }
}
\"\"\",
    filename="XorHelper.java",
    ghidra_script=True,
    description="Java helper for adapting XOR decoding logic into a Ghidra-side workflow.",
)
```

## Notes

- Filenames are sanitized and must be simple file names, not arbitrary paths.
- Optional `subdir` lets you group artifacts by sample or workflow, such as `labos/` or `rswe/task2/`.
- Directories are created automatically.
