# Prototype Test Source Build Guide

This directory contains benign Windows executables used to test the Malware Analysis Hub.

## Coverage Set

The build workflow compiles these samples:

| Source | Output | Primary coverage |
|---|---|---|
| `test.c` | `test.exe` | baseline branching and switch-heavy control flow |
| `floss_test.c` | `floss_test.exe` | static/stack/XOR strings |
| `floss_test.c` | `floss_test_02.exe` | optimized string-analysis variant |
| `floss_test.c` | `floss_test_stripped.exe` | stripped binary string-analysis variant |
| `test.c` | `test_easy_stripped.exe` | explicit easy stripped control-flow sample |
| `anti_debug_test.c` | `anti_debug_test.exe` | anti-debug checks and timing probe |
| `anti_debug_test.c` | `anti_debug_medium_stripped.exe` | explicit medium stripped anti-debug sample |
| `winapi_behavior_test.c` | `winapi_behavior_test.exe` | dynamic API resolution and WinAPI behavior |
| `control_flow_flattened_test.c` | `control_flow_flattened_test.exe` | flattened state-machine style control flow with opaque predicate behavior |
| `api_hash_resolver_test.c` | `api_hash_resolver_test.exe` | API hash lookup and runtime resolver flow |
| `resource_blob_loader_test.c` | `resource_blob_loader_test.exe` | embedded blob container and staged decode path |
| `resource_blob_loader_test.c` | `resource_blob_loader_hard_stripped.exe` | explicit hard stripped staged loader sample |

Optional UPX-packed coverage variants:

| Base output | Packed output | Difficulty |
|---|---|---|
| `test.exe` | `test_easy_upx.exe` | easy |
| `anti_debug_test.exe` | `anti_debug_medium_upx.exe` | medium |
| `resource_blob_loader_test.exe` | `resource_blob_loader_hard_upx.exe` | hard |

The three newer coverage files intentionally use more complex data types (`struct`-heavy layouts) to improve type-recovery and data-flow test quality.

## Build Commands (Makefile Standard)

Build baseline binaries:

```bash
make -C Testing/Prototype_Test_Source all
```

Build GCC-suffixed variants:

```bash
make -C Testing/Prototype_Test_Source all-gcc
```

Build both baseline and GCC-suffixed variants in one run:

```bash
make -C Testing/Prototype_Test_Source all-with-gcc
```

Build the explicit easy/medium/hard packed variants:

```bash
make -C Testing/Prototype_Test_Source upx
```

Override compilers when needed:

```bash
make -C Testing/Prototype_Test_Source all CC=x86_64-w64-mingw32-gcc
make -C Testing/Prototype_Test_Source all-gcc GCC_CC=gcc
make -C Testing/Prototype_Test_Source all-with-gcc CC=x86_64-w64-mingw32-gcc GCC_CC=gcc
```

This produces binaries under `Testing/build/prototype/`, including the stripped variants above and additional `*_gcc.exe` variants. The `upx` target additionally writes the explicit packed easy/medium/hard variants and requires `upx` on `PATH`.

## Optional Python Build Script

If you want `build_manifest.json` generated from a scripted run, you can still use:

```bash
python3 Testing/Prototype_Test_Source/build_test_executables.py --also-gcc --gcc-compiler "gcc" --output-dir Testing/build/prototype
```

That scripted path now attempts the packed variants by default too. If `upx` is unavailable, the manifest records those packed-build attempts as failed optional builds while still succeeding overall if the required non-packed binaries were built.

## Build Manifest

Each run writes `Testing/build/prototype/build_manifest.json` with:

- primary compiler command
- per-sample build command, status, size, and SHA256
- optional `extra_builds` block for GCC variant outputs

Use the manifest as the source of truth for regression test baselines.
