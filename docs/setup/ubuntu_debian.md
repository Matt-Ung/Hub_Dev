# Ubuntu / Debian Setup

This guide is the reference Linux path for a fresh Ubuntu or Debian machine.

## What This Covers

- repo Python environment
- maintained Windows PE corpus build prerequisites
- Ghidra bundle-preparation prerequisites
- basic verification before using the harness quickstart

## System Packages

From a fresh machine:

```bash
sudo apt update
sudo apt install -y \
  git \
  python3 \
  python3-venv \
  python3-pip \
  build-essential \
  make \
  mingw-w64 \
  default-jdk \
  unzip \
  curl
```

Optional but useful:

```bash
sudo apt install -y upx-ucl
```

Optional analysis enrichers:

```bash
sudo apt install -y ssdeep
```

Notes:

- `python3-venv` is required for `python3 -m venv`
- `mingw-w64` provides `x86_64-w64-mingw32-gcc`
- `default-jdk` is for Ghidra; match it to your installed Ghidra version if you
  are managing Java manually
- `ssdeep` enables the optional `ssdeepmcp` fuzzy-hashing server

## Clone And Enter The Repo

```bash
git clone <your-repo-url> "Hub_Dev"
cd "Hub_Dev"
```

## Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Ghidra

Install Ghidra manually in a stable location such as `/opt` or `$HOME/tools`.

Example environment variables:

```bash
export GHIDRA_INSTALL_DIR="/opt/ghidra_12.0.2_PUBLIC"
export GHIDRA_HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
export GHIDRA_JAVA_HOME="/usr/lib/jvm/default-java"
```

The app can launch without Ghidra, but the maintained harness workflow should
be treated as incomplete until `GHIDRA_HEADLESS` works.

## Verification

```bash
python3 --version
python3 -m pip --version
x86_64-w64-mingw32-gcc --version
java -version
test -x "$GHIDRA_HEADLESS" && echo "GHIDRA_HEADLESS ok"
```

Optional Python dependency check after activating `.venv`:

```bash
python -m pip show gradio pandas matplotlib pydantic-ai pydantic-deep >/dev/null
```

## Next Steps

- App runtime:
  - [`../../SETUP_GUIDE.md`](../../SETUP_GUIDE.md)
- Testing harness:
  - [`../../Testing/docs/quickstart.md`](../../Testing/docs/quickstart.md)

## Troubleshooting

- `No module named venv`
  - install `python3-venv`
- `x86_64-w64-mingw32-gcc` missing
  - install `mingw-w64`
- `Permission denied` running Ghidra from `/opt`
  - fix ownership or install Ghidra in a user-writable tools directory
- `matplotlib` install issues inside the venv
  - upgrade `pip` first, then rerun `pip install -r requirements.txt`
- shell commands work in `bash` but not another shell
  - make sure your `PATH`, `GHIDRA_*`, and venv activation are set in the shell
    you actually use for the harness
