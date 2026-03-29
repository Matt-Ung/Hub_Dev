# Test Executables Build Guide

This directory contains benign Windows executables used to test the Malware Analysis Hub.

## Coverage Set

The build workflow compiles these samples:

| Source | Output | Primary coverage |
|---|---|---|
| `test.c` | `test.exe` | baseline branching and switch-heavy control flow |
| `floss_test.c` | `floss_test.exe` | static/stack/XOR strings |
| `floss_test.c` | `floss_test_02.exe` | optimized string-analysis variant |
| `floss_test.c` | `floss_test_stripped.exe` | stripped binary string-analysis variant |
| `anti_debug_test.c` | `anti_debug_test.exe` | anti-debug checks and timing probe |
| `winapi_behavior_test.c` | `winapi_behavior_test.exe` | dynamic API resolution and WinAPI behavior |
| `control_flow_flattened_test.c` | `control_flow_flattened_test.exe` | flattened state-machine style control flow with opaque predicate behavior |
| `api_hash_resolver_test.c` | `api_hash_resolver_test.exe` | API hash lookup and runtime resolver flow |
| `resource_blob_loader_test.c` | `resource_blob_loader_test.exe` | embedded blob container and staged decode path |

The three newer coverage files intentionally use more complex data types (`struct`-heavy layouts) to improve type-recovery and data-flow test quality.

## Build Commands (Makefile Standard)

Build baseline binaries:

```bash
make -C Test_Executables all
```

Build GCC-suffixed variants:

```bash
make -C Test_Executables all-gcc
```

Build both baseline and GCC-suffixed variants in one run:

```bash
make -C Test_Executables all-with-gcc
```

Override compilers when needed:

```bash
make -C Test_Executables all CC=x86_64-w64-mingw32-gcc
make -C Test_Executables all-gcc GCC_CC=gcc
make -C Test_Executables all-with-gcc CC=x86_64-w64-mingw32-gcc GCC_CC=gcc
```

This produces additional binaries named like `*_gcc.exe`.

## Optional Python Build Script

If you want `build_manifest.json` generated from a scripted run, you can still use:

```bash
python3 Test_Executables/build_test_executables.py --also-gcc --gcc-compiler "gcc"
```

## Build Manifest

Each run writes `build_manifest.json` with:

- primary compiler command
- per-sample build command, status, size, and SHA256
- optional `extra_builds` block for GCC variant outputs

Use the manifest as the source of truth for regression test baselines.
