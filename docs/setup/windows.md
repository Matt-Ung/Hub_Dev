# Windows Setup

This guide is for native Windows.

## Recommendation

Native Windows can work for the app quickstart, but it is not the cleanest
environment for the full maintained harness.

If your goal is the complete testing flow, prefer:

- WSL2 with Ubuntu, or
- a Linux VM such as Ubuntu/Debian/Kali

Reasons:

- most harness docs and scripts are written around a POSIX shell
- Ghidra + headless tooling + MinGW-w64 path handling is simpler on Linux
- many troubleshooting steps assume `bash`/`zsh`, `make`, and Unix-style paths

## Native Windows Scope

Native Windows is most reasonable for:

- launching the Gradio app
- limited local development
- reading results

For the full maintained harness on native Windows, expect more manual PATH and
toolchain work.

## Prerequisites

Install:

- Python `3.10+`
- Git
- Java/JDK compatible with your Ghidra version
- Ghidra
- MinGW-w64 toolchain or an equivalent Windows-accessible `x86_64-w64-mingw32-gcc`
- `make` via MSYS2, Git Bash, or another Unix-like environment

Optional:

- UPX

## Python Environment

In PowerShell from the repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Environment Variables

Set these in the shell where you launch the harness:

```powershell
$env:GHIDRA_INSTALL_DIR="C:\tools\ghidra_12.0.2_PUBLIC"
$env:GHIDRA_HEADLESS="$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat"
$env:GHIDRA_JAVA_HOME="C:\Path\To\JDK"
```

Also ensure the MinGW cross-compiler is on `PATH`.

## Verification

```powershell
python --version
python -m pip --version
java -version
```

Check that the cross-compiler resolves:

```powershell
x86_64-w64-mingw32-gcc --version
```

## Practical Advice

- For the app:
  - continue with [`../../SETUP_GUIDE.md`](../../SETUP_GUIDE.md)
- For the harness:
  - prefer WSL2 or a Linux VM instead of native Windows

## Troubleshooting

- PowerShell refuses `Activate.ps1`
  - enable script execution for your user or activate from `cmd.exe`
- `make` is missing
  - use MSYS2, Git Bash, or run the harness from WSL2 instead
- path quoting becomes inconsistent
  - use one shell consistently rather than mixing PowerShell, `cmd.exe`, and
    MSYS2 for the same run
