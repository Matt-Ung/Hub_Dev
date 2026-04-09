# Kali Linux Setup

This guide treats a Kali Linux VM as a supported development and harness
environment.

## Bottom Line

Kali works well for:

- the maintained Python environment
- corpus builds with MinGW-w64
- headless Ghidra bundle preparation
- harness execution and result aggregation

Kali is less ideal for:

- long-running GUI-heavy workflows in a small VM
- live Ghidra plugin development if the VM is underprovisioned

For the maintained benchmark path, a Kali VM is acceptable as long as you give
it enough RAM, CPU, and disk for Java + Ghidra + Python subprocesses.

## Recommended VM Baseline

Minimum practical starting point:

- `4` vCPUs
- `8 GB` RAM
- `60+ GB` free disk

If you plan to run Ghidra interactively inside the VM, more RAM is better.

## System Packages

From a fresh Kali VM:

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

Optional but recommended:

```bash
sudo apt install -y upx-ucl
```

Optional analysis enrichers:

```bash
sudo apt install -y ssdeep
```

Why these matter:

- `python3-venv`
  - required for the repo-local virtual environment
- `build-essential` and `make`
  - required for the corpus build flow
- `mingw-w64`
  - required for canonical Windows PE sample builds
- `default-jdk`
  - required for Ghidra-based bundle preparation
- `upx-ucl`
  - only needed if you want packed-sample workflows or `--prefer-unpacked-upx`
- `ssdeep`
  - enables the optional `ssdeepmcp` fuzzy-hashing server used for similarity
    triage and analyst-side clustering workflows

## Clone The Repo

```bash
git clone <your-repo-url> "Hub_Dev"
cd "Hub_Dev"
```

## Python Environment

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Ghidra On Kali

Install Ghidra manually in a stable path, for example:

```bash
sudo mkdir -p /opt
sudo chown "$USER":"$USER" /opt
```

Then unpack Ghidra under `/opt` or under your home directory and set:

```bash
export GHIDRA_INSTALL_DIR="/opt/ghidra_12.0.2_PUBLIC"
export GHIDRA_HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
export GHIDRA_JAVA_HOME="/usr/lib/jvm/default-java"
```

Persist those in `~/.zshrc` or `~/.bashrc`.

Notes:

- the maintained harness mostly needs headless Ghidra, not the live plugin path
- if you are in a lightweight VM, prefer the headless bundle-preparation flow
  over keeping Ghidra GUI open during long sweeps

## Verification

Run these before touching the harness quickstart:

```bash
python3 --version
python3 -m pip --version
x86_64-w64-mingw32-gcc --version
java -version
test -x "$GHIDRA_HEADLESS" && echo "GHIDRA_HEADLESS ok"
```

Then activate the venv and verify the main Python stack:

```bash
source .venv/bin/activate
python -m pip show gradio pandas matplotlib pydantic-ai pydantic-deep >/dev/null
```

## VM-Specific Caveats

- Shared folders:
  - avoid running large sweeps directly from slow host-shared mounts if you can
    keep the repo on the VM disk instead
- Display stack:
  - app/browser workflows are fine in Kali with a desktop environment, but
    headless harness execution is often more stable in small VMs
- Permissions:
  - if Ghidra is unpacked under `/opt`, make sure your user can read and execute
    the install tree
- Shell behavior:
  - the docs assume a normal POSIX shell such as `bash` or `zsh`

## Recommended First Validation

After the OS-level checks above:

1. Continue with [`../../Testing/docs/quickstart.md`](../../Testing/docs/quickstart.md).
2. Run the launch doctor before any paid sweep:

```bash
python Testing/scripts/run_launch_doctor.py --bundle-only
```

3. If that passes, continue with the normal harness quickstart.

## Troubleshooting

- `python3 -m venv` fails
  - install `python3-venv`
- `make all-exes` fails immediately
  - verify `x86_64-w64-mingw32-gcc --version`
- `run_launch_doctor.py` reports missing Ghidra
  - export `GHIDRA_INSTALL_DIR`, `GHIDRA_HEADLESS`, and `GHIDRA_JAVA_HOME` in
    the same shell before launching the doctor
- Ghidra GUI is slow or unstable
  - use headless bundle prep and avoid interactive Ghidra work inside a small VM
- Browser or Gradio UI is sluggish
  - keep the harness run in Kali, but consider using a host browser session or a
    less GUI-heavy workflow if the VM is resource constrained
