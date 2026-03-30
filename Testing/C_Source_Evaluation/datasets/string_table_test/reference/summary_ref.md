# String Table Test

> Status: reviewed_concrete_anchor_v1
> Concrete reviewed anchors intended for stable evaluation and reproducible judging.

## Program Summary

This baseline string sample stores cleartext status strings, a pointer-backed message table, and a stack-built greeting so the analysis can distinguish ordinary string storage from obfuscation.

## Why It Matters

- Establishes the string-extraction baseline.  Every string in this binary is stored in cleartext.  If FLOSS, strings, or capa miss any of them, the tool integration has a bug.  This sample also gives the scoring rubric a "specificity floor" -- the report should name every string and its storage location.

## Primary Techniques

- Global status strings and banner live in cleartext
- MESSAGES is an array of const char * pointers with indexed lookup
- lookup_message returns '(unknown message index)' for out-of-range values
- build_greeting formats 'Hello, %s! Welcome to the test harness.' into a stack buffer

## Expected Analysis Signals

- Recover the banner '=== String Table Test Executable v1.0 ==='
- Recover multiple table strings such as msg[0] and msg[7]
- Explain that the strings are stored in cleartext rather than encoded
- Note the out-of-bounds fallback string '(unknown message index)'

## Autodetected Key Functions

- `print_status`: output or logging
- `build_greeting`: autodetected helper function
- `main`: entry point and orchestration

## Recommended Tooling

- `stringmcp`
- `flareflossmcp`
- `ghidramcp`
- `CapaMCP`

## Related Binary Variants

- `string_table_test.exe`
