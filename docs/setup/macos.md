# macOS Setup

This guide is for a fresh macOS machine.

## What Works Well On macOS

- `multi_agent_wf` app startup
- testing harness orchestration
- Ghidra-based bundle preparation
- browser-based result inspection

## What Needs Extra Attention

- the maintained corpus builds Windows PE binaries, so you still need the
  MinGW-w64 cross-compiler
- some reverse-engineering helper tools may not be available from stock macOS
  packages and remain optional

## Prerequisites

Install these first:

- Xcode Command Line Tools
- Homebrew
- Python `3.10+`
- Java/JDK compatible with your Ghidra version
- Ghidra installed locally

Suggested command sequence:

```bash
xcode-select --install
brew update
brew install python make mingw-w64 openjdk
```

Optional but useful:

```bash
brew install upx
```

Install Ghidra manually, then set:

```bash
export GHIDRA_INSTALL_DIR="/Applications/ghidra_12.0.2_PUBLIC"
export GHIDRA_HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
export GHIDRA_JAVA_HOME="$(/usr/libexec/java_home)"
```

Persist those variables in your shell profile if you plan to use the harness
regularly.

## Python Environment

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Minimum Verification

```bash
python3 --version
python3 -m pip --version
x86_64-w64-mingw32-gcc --version
java -version
test -x "$GHIDRA_HEADLESS" && echo "GHIDRA_HEADLESS ok"
```

If you only want the app, continue with:

- [`../../SETUP_GUIDE.md`](../../SETUP_GUIDE.md)

If you want the maintained testing harness, continue with:

- [`../../Testing/docs/quickstart.md`](../../Testing/docs/quickstart.md)

## Troubleshooting

- `brew: command not found`
  - install Homebrew first
- `x86_64-w64-mingw32-gcc: command not found`
  - ensure `brew install mingw-w64` finished and your shell can see Homebrew's
    bin directory
- `analyzeHeadless` exists but the harness cannot find it
  - check `GHIDRA_INSTALL_DIR` and `GHIDRA_HEADLESS` in the same shell that
    launches the harness
- Java mismatch errors from Ghidra
  - point `GHIDRA_JAVA_HOME` at the JDK version required by your installed
    Ghidra release
