# Final Round Source Corpus

This directory contains the maintained final-round source corpus for producing
opaque Windows executables plus grounded reference material for evaluation.

The active harness-facing manifest for this corpus is:

- [sample_manifest.json](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/final_round/sample_manifest.json)

Evaluator-side scoring notes live under:

- [evaluation/README.md](/Users/matthewung/Desktop/Thesis%20Tools/Hub_Dev/Testing/sources/final_round/evaluation/README.md)

## Goals

- Build all final samples in a release-oriented form.
- Strip symbols explicitly.
- Pack the final executables explicitly with UPX.
- Rename final deliverables to opaque names:
  - `sample1.exe`
  - `sample2.exe`
  - `sample3.exe`
  - `sample4.exe`
  - `sample5.exe`
- Preserve traceability through generated manifests and per-sample reference files instead of descriptive filenames.

## Environment Assumptions

This Makefile assumes:

- GNU `make`
- a POSIX-like shell environment on Windows such as MSYS2 or Git Bash
- a MinGW-w64 toolchain available on `PATH`
- `upx` available on `PATH`

It does **not** assume `cmd.exe` batch semantics.

For MSYS2, the intended install is:

```bash
pacman -S mingw-w64-x86_64-toolchain
```

The Makefile now derives `STRIP` from the active compiler via
`$(CC) -print-prog-name=strip`, so it will use the strip binary that ships
with the installed MinGW toolchain instead of requiring a separately named
override.

## Build Command

From this directory:

```bash
make final-round
```

Or from the repo root:

```bash
make deepseek-final
```

## Tool Overrides

If your VM uses different executable names, override them explicitly:

```bash
make deepseek-final \
  UPX_BIN=/full/path/to/upx.exe
```

Or from this directory:

```bash
make final-round \
  OUT_DIR=../build/deepseek_final \
  CXX=x86_64-w64-mingw32-g++ \
  CC=x86_64-w64-mingw32-gcc \
  UPX_BIN=upx \
  PYTHON=python
```

## Output Layout

All final-round artifacts are written under `Testing/build/deepseek_final/` by default.

- `Testing/build/deepseek_final/release/`
  - release-oriented intermediate PE files with descriptive names
- `Testing/build/deepseek_final/stripped/`
  - explicitly stripped intermediates
- `Testing/build/deepseek_final/output/`
  - final packed opaque executables `sample1.exe` through `sample5.exe`
- `Testing/build/deepseek_final/final_test_manifest.json`
  - full metadata manifest, including hashes and sample mapping
- `Testing/build/deepseek_final/sample_name_mapping.json`
  - direct opaque-name to source-sample mapping
- `Testing/build/deepseek_final/reference/`
  - one JSON and one Markdown reference file per final sample

## Stable Mapping

The mapping is intentionally fixed:

- `sample1.exe` -> Emotet
- `sample2.exe` -> QakBot
- `sample3.exe` -> TrickBot
- `sample4.exe` -> WannaCry
- `sample5.exe` -> PlugX

Do not rename the outputs by hand after build. The manifest is the source of truth.

## How Stripping Works

The build first produces release intermediates, then copies them into `Testing/build/deepseek_final/stripped/` and runs:

```text
$(CC) -print-prog-name=strip --strip-all
```

In an MSYS2 MinGW shell this normally resolves to the `strip` binary shipped
with `mingw-w64-x86_64-toolchain`. If stripping fails for any sample, the
build stops immediately.

## How Packing Works

The stripped intermediates are copied into `Testing/build/deepseek_final/output/` under their opaque names and then packed in place with:

```text
upx --best --lzma --force
```

If packing fails for any sample, the build stops immediately and removes the incomplete final artifact rather than silently continuing.

## Reference Packaging

The final-round reference dataset is checked into this directory and copied into
the build output after the packed executables are produced.

The copied files are:

- `final_test_manifest.json`
- `sample_name_mapping.json`
- `reference/sampleN.json`
- `reference/sampleN.md`

The reference material is grounded in the checked-in source code and
configuration only. It is not generated dynamically at build time.

The maintained judge consumes the checked-in `reference/sampleN.json` files as
evaluator-only grounding during final-round scoring. Those references stay out
of the model-visible runtime sample metadata.

## What The References Are Good For

The generated references are intended for evaluation and judging:

- sample metadata
- intended simulated capability set
- static-analysis anchors
- configuration / resource expectations
- relationship notes across helper files
- expected reporting points for a strong triage system
- candidate detection opportunities where the source supports them

## Important Caveats

- These are simulation samples, not live malware.
- Some families include structural hooks for resources or embedded payloads, but the repository does not contain actual `.rc` files or embedded payload blobs for every sample.
- The reference files call those gaps out explicitly rather than pretending the behaviors are fully implemented.
- The PlugX sample intentionally uses a deterministic one-byte shellcode stub in `Plugx/plugx_shellcode.c` so the final build remains portable and reproducible.
- The final-round workflow ships a single opaque executable per family. It does not emit a separate DLL sideloading package for PlugX.
- The DeepSeek child Makefile now follows the same repo convention as the prototype and experimental corpora: the repo-root `Makefile` is the primary entrypoint, and build products land under `Testing/build/`.
- If the checked-in reference files change, update them intentionally in source control rather than relying on a build-time generator.

## Cleaning

To remove final-round outputs and legacy build leftovers:

```bash
make clean
```

This removes:

- `Testing/build/deepseek_final/`
- legacy `bin/`
- legacy `malware_simulations.zip`
