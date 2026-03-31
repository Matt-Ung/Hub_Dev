# Winapi Behavior Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This prototype WinAPI behavior sample dynamically resolves VirtualAlloc and VirtualFree from kernel32.dll, creates a named mutex, and exposes URL, registry, and stack-command indicators.

## Primary Techniques

- GetProcAddress resolves VirtualAlloc and VirtualFree at runtime from kernel32.dll
- CreateMutexA references Global\\UpdaterMutex
- The sample contains https://updates.example.net/checkin, Software\\Microsoft\\Windows\\CurrentVersion\\Run, and the stack-built command CMD: cmd.exe /c echo hello

## Expected Analysis Signals

- Explain the dynamic resolution of VirtualAlloc/VirtualFree
- Recover the mutex, URL, registry path, and stack-built command
- Note the temporary allocation and free sequence on a 0x1000-byte region

## Autodetected Key Functions

- `build_stack_string`: autodetected helper function
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `CapaMCP`
- `stringmcp`

## Related Binary Variants

- `winapi_behavior_test.exe`
