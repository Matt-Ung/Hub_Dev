/**
 * plugx_shellcode.c - Position-Independent Shellcode
 * Simulates PlugX's modular shellcode loader [citation:9]
 */
#include <windows.h>

/*
 * The original sketch used compiler-specific naked inline assembly, which is
 * brittle across modern MinGW toolchains and x64 targets. For the final test
 * round we keep the shellcode relationship visible but use a deterministic
 * one-byte `ret` stub so the overall sample still builds reproducibly.
 */
BYTE ShellcodeEntry[] = {0xC3};
DWORD ShellcodeSize = sizeof(ShellcodeEntry);
