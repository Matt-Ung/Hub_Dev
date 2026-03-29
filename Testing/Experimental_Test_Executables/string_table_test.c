/*
 * File:       string_table_test.c
 * Purpose:    Baseline string-extraction sample.  Contains a variety of
 *             string storage patterns (global const, local stack arrays,
 *             string pointer tables) that string-recovery tools should
 *             find without difficulty.
 *
 * Difficulty: EASY
 *
 * Techniques:
 *   - Global const string literals
 *   - Local (stack) string arrays initialized from literals
 *   - String pointer table (array of const char *)
 *   - printf / puts with format strings
 *   - Index-based table lookup (no obfuscation)
 *
 * Why it matters for testing:
 *   Establishes the string-extraction baseline.  Every string in this
 *   binary is stored in cleartext.  If FLOSS, strings, or capa miss
 *   any of them, the tool integration has a bug.  This sample also
 *   gives the scoring rubric a "specificity floor" -- the report should
 *   name every string and its storage location.
 *
 * Expected analysis signals:
 *   - All string literals recovered by stringmcp / flareflossmcp
 *   - Ghidra decompilation shows clean table index logic
 *   - No false claims about encoding or obfuscation
 *   - capa may flag "reference function by name" or similar benign rules
 *
 * Recommended MCP servers / tools:
 *   - stringmcp       : primary tool; should recover every string
 *   - flareflossmcp   : should confirm no encoded/stack strings beyond
 *                        the literal stack arrays here
 *   - ghidramcp       : decompilation of lookup_message and format usage
 *   - CapaMCP         : benign-only capability fingerprint
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------
 * Global constant strings.
 * These live in the .rdata / .rodata section and are the easiest
 * class of string for any extraction tool to find.
 * --------------------------------------------------------------- */
static const char *STATUS_OK    = "STATUS: operation completed successfully";
static const char *STATUS_WARN  = "STATUS: non-fatal warning encountered";
static const char *STATUS_ERR   = "STATUS: critical error, aborting";
static const char *BANNER       = "=== String Table Test Executable v1.0 ===";

/* ---------------------------------------------------------------
 * String pointer table.
 * Stored as a contiguous array of pointers in the data section.
 * The analyst should see an array of relocated pointers, each
 * referencing a string literal in .rdata.
 * --------------------------------------------------------------- */
static const char *MESSAGES[] = {
    "msg[0]: initializing subsystem alpha",
    "msg[1]: loading configuration from disk",
    "msg[2]: establishing network connection",
    "msg[3]: handshake complete, session active",
    "msg[4]: data transfer in progress",
    "msg[5]: finalizing and writing audit log",
    "msg[6]: shutdown sequence initiated",
    "msg[7]: cleanup finished, exiting normally",
};

#define MSG_COUNT ((int)(sizeof(MESSAGES) / sizeof(MESSAGES[0])))

/*
 * lookup_message -- index-based table access.
 * The bounds check produces a simple branch.  Out-of-range indices
 * return a default string, which the analyst should also recover.
 */
static const char *lookup_message(int idx)
{
    if (idx < 0 || idx >= MSG_COUNT)
        return "(unknown message index)";
    return MESSAGES[idx];
}

/*
 * print_status -- selects a status string by code.
 * Tests that the decompiler reconstructs the if/else mapping
 * between integer codes and global string pointers.
 */
static void print_status(int code)
{
    const char *s;
    if (code == 0)
        s = STATUS_OK;
    else if (code == 1)
        s = STATUS_WARN;
    else
        s = STATUS_ERR;
    printf("[status %d] %s\n", code, s);
}

/*
 * build_greeting -- local stack buffer built from a string literal.
 * The strncpy produces a bounded copy that FLOSS should still see as
 * a static string reference (the source literal is in .rdata).
 */
static void build_greeting(const char *name)
{
    char greeting[128];
    snprintf(greeting, sizeof(greeting), "Hello, %s! Welcome to the test harness.", name);
    puts(greeting);
}

int main(int argc, char **argv)
{
    puts(BANNER);

    /* Print every table entry so the strings are referenced and not
     * dead-stripped by the linker. */
    for (int i = 0; i < MSG_COUNT; i++) {
        printf("  %s\n", lookup_message(i));
    }

    /* Out-of-bounds access to exercise the default path */
    printf("  %s\n", lookup_message(99));

    /* Status codes */
    print_status(0);
    print_status(1);
    print_status(2);

    /* Stack-based greeting */
    const char *user = (argc > 1) ? argv[1] : "analyst";
    build_greeting(user);

    puts("marker:string_table_baseline");
    return 0;
}
