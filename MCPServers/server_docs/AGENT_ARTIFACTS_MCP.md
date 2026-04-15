# Agent Artifacts MCP

`MCPServers/agentArtifactsMCP.py` provides a standardized write path for reusable agent-generated files.

## Purpose

Use this MCP server when the agent should persist helper artifacts instead of leaving them only inline in the chat or report. Typical outputs:

- Python deobfuscation helpers
- Java helpers
- Ghidra-supporting scripts
- Generated reports or notes

Generated YARA rules should still be written with `yaraWriteRule(...)` from `yaraMCP.py`, but they use the same shared artifact-root policy.

The server can also generate structured malware analysis report bundles that
include:

- normalized JSON input
- filled Markdown report output
- rendered PDF deliverable

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

Security note:

- `AGENT_ARTIFACT_DIR` defines the only allowed artifact root.
- Per-type overrides are allowed only if they still resolve under that root.
- Relative escapes such as `../..` and absolute paths outside the root are rejected server-side.
- The server will not silently fall back to the Desktop, Home directory, or current working directory.

## Tools

- `agentArtifactPaths()`
- `writeTextArtifact(artifact_type, content, filename="", overwrite=False, subdir="", description="")`
- `writePythonArtifact(content, filename="", overwrite=False, subdir="", description="", ghidra_script=False)`
- `writeJavaArtifact(content, filename="", overwrite=False, subdir="", description="", ghidra_script=False)`
- `malwareReportSchema()`
- `generateMalwareReport(report, filename="", overwrite=False, subdir="", emit_json=True, emit_markdown=True, emit_pdf=True)`
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

Generate a malware analysis report bundle:

```python
generateMalwareReport(
    report={
        "title": "Malware Analysis Report",
        "sample_name": "sample.exe",
        "analyst": "Hub_Dev",
        "executive_summary": "Packed Windows payload with encoded strings and HTTP beaconing.",
        "file_details": {
            "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "family": "ExampleFamily",
            "packer": "UPX",
        },
        "stage_descriptions": [
            {
                "title": "Stage 1 - Loader",
                "description": "Unpacks and resolves imports dynamically.",
                "evidence": ["Recovered stack strings for WinINet imports."],
            }
        ],
        "command_and_control": {
            "urls": ["http://example[.]com/gate.php"],
        },
        "conclusion": "Static evidence supports staged delivery and beaconing behavior.",
    },
    filename="sample_report",
    subdir="engagement_alpha",
)
```

Typical output bundle:

```text
agent_artifacts/reports/engagement_alpha/malware_reports/sample_report/
  report.json
  report.md
  report.pdf
```

## Notes

- Filenames are sanitized and must be simple file names, not arbitrary paths.
- Optional `subdir` lets you group artifacts by sample or workflow, such as `labos/` or `rswe/task2/`.
- Directories are created automatically.
- The server enforces the artifact root in code; prompts or client conventions are not trusted as the security boundary.
- `generateMalwareReport(...)` validates the payload against a structured schema before writing anything.
- Missing sections are omitted from the generated Markdown and PDF instead of emitting blank placeholders.
- PDF rendering requires `fpdf2` in the active Python environment.
