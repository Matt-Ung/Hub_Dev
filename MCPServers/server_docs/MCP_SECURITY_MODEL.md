# MCP Security Model

This document describes the current trust boundary for the local MCP servers in this repository.

Primary rule: prompts, client conventions, and agent intent are not treated as the security boundary for side effects. Servers with write or mutation capabilities enforce their own restrictions in code.

## Capability Matrix

| Server | Active path | Capability class | Side effects | Current enforcement |
| --- | --- | --- | --- | --- |
| `ghidramcp` (`bridge_mcp_ghidra.py`) | Active via `MCPServers/servers.json` | Binary-analysis read + optional live mutation | Live rename/comment/type edits against a running Ghidra session; managed UPX unpack + import into the active project; HTTP requests | Read tools always allowed. State-changing tools, including managed unpack/import, are disabled by default and require `GHIDRA_MCP_ALLOW_MUTATIONS=1` or `--allow-mutations`. Remote Ghidra endpoints are disabled by default and require `GHIDRA_MCP_ALLOW_REMOTE_SERVER=1` or `--allow-remote-server`. |
| `artifactGhidraMCP.py` | Active through harness artifact-backed manifests | Read-only analysis artifacts | None | Read-only by design. Mutation tools return explicit errors. |
| `stringmcp` | Active | Read-only subprocess | Executes `strings` | No shell execution. Reads caller-specified files only. |
| `flareflossmcp` | Active | Bounded subprocess | Executes `floss` | Requires argv[0] to be `floss`/`floss.exe`, uses `shell=False`, rejects obvious placeholder paths. Still trusts FLOSS to behave safely. |
| `CapaMCP` | Active | Bounded subprocess | Executes `capa` | Requires argv[0] to be `capa`/`capa.exe`, uses `shell=False`, injects rules/signatures when available. Still trusts capa itself. |
| `hashdbmcp` | Active | Network read | Outbound HTTP to HashDB | No local writes. Trust boundary is the configured HashDB endpoint. |
| `sdhashmcp` | Present but not enabled in `servers.json` | Read-only subprocess | Executes `sdhash`; may write temporary digest files for file-vs-file comparisons | Not active by default. If enabled later, it uses `shell=False`, reads caller-specified files only, and limits convenience comparison writes to process-scoped temporary files. |
| `binwalkmcp` | Active | Read + extraction output | Executes `binwalk`; writes scan/extraction outputs | Output root is enforced server-side under the configured artifact root. Absolute or relative escapes are rejected. |
| `upxmcp` | Active | Read + write output | Executes `upx`; writes unpacked copy | Output path is enforced server-side under the configured UPX output root. Absolute or relative escapes are rejected. |
| `yaramcp` | Active | Read + controlled rule writes | Executes `yara`; writes generated rules and temporary validation/composite files | Generated rules and temporary files are written only under the generated-YARA artifact directory. Filenames cannot contain path separators. |
| `agentartifactsmcp` | Active | Controlled writes | Writes reusable text/python/java/ghidra artifacts and report bundles (JSON/Markdown/PDF) | All writes stay under `AGENT_ARTIFACT_DIR`. Per-type overrides must still resolve under that root. PDF generation is local in-process through the Python runtime; no shell-outs are used for report rendering. |
| `gitleaksmcp` | Active | Read + report output | Executes `gitleaks`; writes JSON reports and temporary scan-content files | Report and temporary-file output roots are enforced server-side under the configured artifact root. |
| `searchsploitmcp` | Active | Read-only subprocess | Executes `searchsploit` | No local writes by server code. |
| `trivymcp` | Active | Read + cache/network side effects | Executes `trivy`; may update/cache vulnerability DB | Server forces `TRIVY_CACHE_DIR` under the configured artifact root. Network/database-update behavior is still delegated to Trivy. |
| `binarypatchmcp` | Active | Read + write patched binaries | Writes patched copies of binaries | Output path is enforced server-side under the configured binary-patch output root. Absolute or relative escapes are rejected. |
| `modelGatewayMCP.py` | Present but not enabled in `servers.json` | Network generation | Outbound requests to configured model endpoint | Not active by default. If enabled later, treat the configured endpoint as a high-trust boundary. |

## Server-Side Write Boundaries

Shared path enforcement lives in [`artifact_paths.py`](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/artifact_paths.py).

The enforced policy is:

- `AGENT_ARTIFACT_DIR` is the root for agent-written artifacts.
- Per-type artifact overrides must still remain under that root.
- Tool-specific output roots for `binwalk`, `gitleaks`, `upx`, `binary_patch`, and `trivy` must remain under that same root.
- Live Ghidra unpack artifacts created by `ghidramcp` are written under the repo-managed Ghidra artifact root, typically `./agent_artifacts/ghidra/unpacked_binaries/...`.
- Relative paths are resolved against the scoped root, not against the current working directory.
- Absolute paths outside the scoped root are rejected.
- Escapes like `../..` are rejected after normalization.
- Rejections are explicit errors; the server does not silently choose a fallback path.

## What Is Explicitly Not Trusted

- Prompt instructions such as "write under the configured output directory"
- Client-side path conventions
- Agent intent
- Relative paths that happen to look harmless
- Per-tool environment overrides that point outside the configured artifact root

## Residual Risks

- Subprocess-based tools still trust the underlying external tool after argument validation. For example, Trivy can still perform network activity and maintain its own cache contents inside the enforced cache root.
- The live Ghidra bridge still trusts the launched Ghidra HTTP service when read tools are used.
- Network-only servers such as HashDB and any future model-gateway enablement still trust their configured remote endpoints.

## Recommended Operational Policy

- Keep `AGENT_ARTIFACT_DIR` set to a dedicated repo-local directory such as `./agent_artifacts`.
- Leave Ghidra mutation tools disabled unless you explicitly want a live reverse-engineering session to be stateful.
- Do not enable remote Ghidra endpoints unless you intend to trust that remote service.
- Treat `modelGatewayMCP.py` as disabled until you are ready to define a stricter endpoint policy for it.
