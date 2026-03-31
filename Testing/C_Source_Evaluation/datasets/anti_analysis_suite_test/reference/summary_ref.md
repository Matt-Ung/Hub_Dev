# Anti Analysis Suite Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This kitchen-sink hard sample combines anti-debug APIs, a timing probe, environment fingerprinting, a rotating-key XOR config, and opaque dead code behind misleading helper names.

## Why It Matters

- This sample forces the analysis pipeline to coordinate across multiple tool domains:
- Ghidra for control flow and function decompilation
- capa for anti-debug and anti-analysis behavioral rules
- FLOSS for stack string recovery
- strings for cleartext indicator extraction
- YARA for rule-based pattern matching on anti-debug APIs The misleading function names test whether agents reason about actual behavior rather than trusting symbol names.  The dead code branches test whether the report distinguishes reachable from unreachable paths. On non-Windows platforms, the Windows API calls are replaced with stubs that return safe defaults, so the binary compiles and runs everywhere.  The analysis challenge remains because the code structure, strings, and control flow are identical.

## Primary Techniques

- update_display is a misleadingly named debugger check that uses stack-built strings for IsDebuggerPresent and CheckRemoteDebuggerPresent
- timing_probe measures a busy loop with QueryPerformanceCounter / QueryPerformanceFrequency and flags values above 100000 microseconds
- env_fingerprint checks USERNAME/USER and COMPUTERNAME/HOSTNAME for sandbox-style identifiers
- decrypt_config reverses a rotating XOR scheme whose key starts at 0x1F and increments by 0x07 for each byte

## Expected Analysis Signals

- Recover IsDebuggerPresent and CheckRemoteDebuggerPresent as anti-debug behaviors despite misleading naming
- Recover c2=https://update.example.net/api;sleep=600;id=AA-0042 from the encrypted config
- Identify never_called / opaque_false style dead-code behavior as unreachable or misleading
- Explain that multiple independent anti-analysis signals contribute to the total score

## Autodetected Key Functions

- `GetCurrentProcess`: process introspection API
- `IsDebuggerPresent`: anti-debug detection API
- `CheckRemoteDebuggerPresent`: anti-debug detection API
- `QueryPerformanceFrequency`: timing / anti-analysis API
- `QueryPerformanceCounter`: timing / anti-analysis API
- `append_finding`: output or logging
- `update_display`: output or logging
- `timing_probe`: timing or anti-analysis helper
- `env_fingerprint`: output or logging
- `init_config`: initialization or configuration
- `decrypt_config`: decode or deobfuscation helper
- `never_called`: dead code or opaque predicate
- `opaque_false`: dead code or opaque predicate
- `main`: entry point and orchestration

## Recommended Tooling

- `ghidramcp`
- `CapaMCP`
- `flareflossmcp`
- `stringmcp`
- `yaramcp`
- `hashdbmcp`

## Related Binary Variants

- `anti_analysis_suite_test.exe`
