# Setup Overview

Use this directory when you are starting from a fresh machine or VM.

The repo has two distinct workflows:

- `multi_agent_wf/`
  - the Gradio-based reverse-engineering application
- `Testing/`
  - the maintained evaluation harness, corpus builds, bundle preparation, and experiment tooling

Both workflows share the same Python environment, but the testing harness has
more OS-level prerequisites:

- `make`
- a C/C++ toolchain
- `x86_64-w64-mingw32-gcc` for the maintained Windows PE corpus
- Java plus a local Ghidra installation for bundle preparation
- optional CLI tools such as `upx`
  - `upx` is also used by the live Ghidra bridge if you want managed unpack +
    import of packed executables into the current project

There is currently no maintained Docker-first setup path. The documented and
tested path is direct installation on the host OS or inside a Linux VM.

## Choose Your Platform

- macOS:
  - [`macos.md`](macos.md)
- Ubuntu or Debian:
  - [`ubuntu_debian.md`](ubuntu_debian.md)
- Kali Linux:
  - [`kali_linux.md`](kali_linux.md)
- Windows:
  - [`windows.md`](windows.md)

## Recommended Reading Order

1. Complete the platform guide for your OS.
2. For app-only startup, continue with [`../../SETUP_GUIDE.md`](../../SETUP_GUIDE.md).
3. For the evaluation harness, continue with [`../../Testing/docs/quickstart.md`](../../Testing/docs/quickstart.md).

## Shared Concepts

These concepts apply on every platform:

- Python:
  - the repo expects Python `3.10+`
- Virtual environment:
  - use one repo-local virtual environment and keep the harness and app on the
    same interpreter
- Shell model:
  - most harness commands assume a POSIX shell such as `bash` or `zsh`
  - PowerShell examples are provided only where they are a first-class path
- Environment file:
  - the app and harness both read repo `.env`
- Ghidra:
  - app startup does not require Ghidra
  - bundle preparation and most maintained harness workflows do
- MinGW-w64:
  - the maintained benchmark corpus targets Windows PE binaries, so the
    cross-compiler is required for canonical builds

## Common Verification Checks

Run these from the repo root after finishing your platform setup:

```bash
python3 --version
python3 -m venv --help >/dev/null
python3 -m pip --version
```

If you plan to use the maintained testing harness, also verify:

```bash
x86_64-w64-mingw32-gcc --version
java -version
```

Then activate your virtual environment and install Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows PowerShell, use:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Common Failure Modes

- `python3 -m venv` fails:
  - install your platform's `venv` package
- `x86_64-w64-mingw32-gcc` is missing:
  - install MinGW-w64 before trying to build the benchmark corpus
- `analyzeHeadless` cannot be found:
  - set `GHIDRA_INSTALL_DIR` or `GHIDRA_HEADLESS`
- Java exists but Ghidra still fails:
  - point `GHIDRA_JAVA_HOME` at the JDK used by your Ghidra installation
- `make all-exes` works on one shell but not another:
  - check that `PATH` is set in the same shell you use for the harness

## VM Note

If you are using a Linux VM:

- allocate enough RAM for Java + Ghidra + Python subprocesses
- avoid running the full browser/UI stack on a very constrained VM if you only
  need headless harness execution
- prefer a normal POSIX shell inside the VM for the documented commands
