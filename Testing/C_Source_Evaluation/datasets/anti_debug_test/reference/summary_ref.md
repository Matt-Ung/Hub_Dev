# Anti Debug Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This prototype anti-debug sample calls IsDebuggerPresent and CheckRemoteDebuggerPresent, runs a QueryPerformanceCounter-based timing probe, and prints common tool markers associated with analyst workstations.

## Primary Techniques

- timing_probe measures a busy loop using QueryPerformanceFrequency and QueryPerformanceCounter
- main prints local_debugger and remote_debugger status values
- The sample emits x64dbg.exe, ollydbg.exe, procmon.exe, and wireshark.exe marker strings

## Expected Analysis Signals

- Identify both anti-debug APIs
- Explain the timing-based probe logic
- Recover the four analyst-tool marker strings

## Autodetected Key Functions

- `timing_probe`: timing or anti-analysis helper
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `CapaMCP`
- `stringmcp`
- `upxmcp`

## Related Binary Variants

- `anti_debug_test.exe`
- `anti_debug_medium_stripped.exe`
- `anti_debug_medium_upx.exe`
