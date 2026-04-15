# Hub_Dev

This repo has two active core development areas:

- [`multi_agent_wf/`](multi_agent_wf/): the main multi-agent reverse-engineering application
- [`Testing/`](Testing/): the maintained binary-analysis evaluation harness

If you are new to the repo, start with the section that matches your goal instead of exploring everything at once.

## Start Here

1. Choose your platform setup guide:
   - [`docs/setup/README.md`](docs/setup/README.md)
   - [`docs/setup/macos.md`](docs/setup/macos.md)
   - [`docs/setup/ubuntu_debian.md`](docs/setup/ubuntu_debian.md)
   - [`docs/setup/kali_linux.md`](docs/setup/kali_linux.md)
   - [`docs/setup/windows.md`](docs/setup/windows.md)
2. Pick your workflow:
   - App runtime: [`SETUP_GUIDE.md`](SETUP_GUIDE.md), [`multi_agent_wf/README.md`](multi_agent_wf/README.md)
   - Testing harness: [`Testing/docs/quickstart.md`](Testing/docs/quickstart.md), [`Testing/README.md`](Testing/README.md)
3. Use deeper references only after the basic environment works:
   - [`Testing/docs/evaluation_design.md`](Testing/docs/evaluation_design.md)
   - [`multi_agent_wf/extension_tutorial.md`](multi_agent_wf/extension_tutorial.md)
   - [`docs/agent_run_dataflow.md`](docs/agent_run_dataflow.md)

The platform setup docs are the source of truth for fresh-machine installation.
The quickstarts below assume your OS prerequisites are already satisfied.

## Repo Map

```text
.
  multi_agent_wf/           # main agent runtime, pipeline, frontend, workflow config
  MCPServers/               # MCP server entrypoints, manifest, support docs, and helper modules
  Testing/                  # evaluation harness, corpora, config, generated results
  skills/                   # repo-local Codex skills for tool usage
  third_party/              # optional external rule/signature corpora
  docs/                     # diagrams and implementation-grounded architecture docs
  GhidraMCP/                # live Ghidra bridge plugin, based on LaurieWired/GhidraMCP and extended here
  agent_artifacts/          # generated artifacts written by analysis tools
  logs/                     # tool and worker logs produced during runs
```

## What Is Active vs Historical

Active and maintained:

- `multi_agent_wf/`
- `Testing/`
- `MCPServers/`
- `skills/`
- `docs/`

Mostly supporting or historical:

- `GhidraMCP/` is still used for the live Ghidra bridge, but not for the artifact-backed testing path
  - this repo's version is based on LaurieWired's original GhidraMCP project and extends it for Hub_Dev workflows
- `In_Progress/` is not part of the main runtime or testing workflow

## Mental Model

The app and the harness are related but different:

- `multi_agent_wf` is the runtime under test
- `Testing` builds corpora, prepares bundles, runs the workflow, judges outputs, and aggregates experiment results

That means many files in `Testing/` exist to observe or compare the behavior of `multi_agent_wf`, not to duplicate its logic.

## Documentation Hierarchy

1. Root overview:
   - [`README.md`](README.md)
2. Platform setup:
   - [`docs/setup/README.md`](docs/setup/README.md)
   - platform-specific setup guides under [`docs/setup/`](docs/setup)
3. Subsystem overviews:
   - [`multi_agent_wf/README.md`](multi_agent_wf/README.md)
   - [`Testing/README.md`](Testing/README.md)
4. Task-oriented quickstarts:
   - [`SETUP_GUIDE.md`](SETUP_GUIDE.md)
   - [`Testing/docs/quickstart.md`](Testing/docs/quickstart.md)
5. Deep-dive design and extension docs:
   - [`Testing/docs/evaluation_design.md`](Testing/docs/evaluation_design.md)
   - [`multi_agent_wf/extension_tutorial.md`](multi_agent_wf/extension_tutorial.md)
   - [`docs/agent_run_dataflow.md`](docs/agent_run_dataflow.md)
