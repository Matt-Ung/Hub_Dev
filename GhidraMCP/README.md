# GhidraMCP Extension

This directory contains the live Ghidra plugin used by Hub_Dev's `ghidramcp`
bridge.

## Lineage

This work is based on LaurieWired's original GhidraMCP project:

- Upstream repo: [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP)

The Hub_Dev fork keeps the original live-bridge idea and extends it for this
repo's workflow, including:

- Hub_Dev automation trigger hooks
- guarded mutation controls
- artifact/fallback integration on the Python bridge side
- managed UPX unpack plus import into the active Ghidra project

## Managed Unpack Workflow

When the live bridge's `upx_unpack_current_program` tool is used:

- the current program's executable path is read from the active Ghidra session
- UPX writes the unpacked copy under the repo-managed artifact root:
  - `agent_artifacts/ghidra/unpacked_binaries/<sample>_<sha12>/`
- the original executable is preserved
- the unpacked copy is imported into the current Ghidra project under an
  `unpacked/` project folder by default
- the imported unpacked program can be opened as the current program so
  follow-on Ghidra analysis operates on the unpacked target directly

The unpack/import path is treated as a state-changing action and stays behind
the same mutation guard used for other live Ghidra edits.
