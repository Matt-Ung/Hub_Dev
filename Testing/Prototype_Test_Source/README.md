# Prototype Test Source

This folder contains the C source for the prototype regression corpus, including easy/medium/hard stripped and UPX-packed variant definitions.

Compiled outputs are written to `Testing/build/prototype/`.

## Build

From this directory, writing into the shared build output:

```bash
python3 build_test_executables.py --output-dir ../build/prototype
```

Optional:

```bash
python3 build_test_executables.py --compiler x86_64-w64-mingw32-gcc --output-dir ../build/prototype
python3 build_test_executables.py --also-gcc --output-dir ../build/prototype
```

The build writes `Testing/build/prototype/build_manifest.json` with command lines, success/failure, sizes, and SHA-256 hashes. It also attempts to produce the UPX-packed variants by default; if `upx` is unavailable, those entries are recorded as failed optional packed builds.

## Samples

- `test.c` -> control flow and switch/jump-table style logic.
- `floss_test.c` -> static + stack + XOR-decoded strings.
- `anti_debug_test.c` -> debugger checks and anti-analysis marker strings.
- `winapi_behavior_test.c` -> WinAPI imports, dynamic `GetProcAddress`, mutex creation, and suspicious-looking strings.
- Additional build variants cover explicit easy/medium/hard stripped binaries and easy/medium/hard UPX-packed binaries for regression sweeps.

## Notes

- These are intentionally benign test programs.
- A Windows cross-compiler is required on macOS/Linux (for example: `x86_64-w64-mingw32-gcc`).
