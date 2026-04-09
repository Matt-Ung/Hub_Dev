/*
 * File:       hash_dispatch_test.c
 * Purpose:    Hash-based command dispatch where function selection is
 *             performed by hashing a command name string and matching
 *             against a table of precomputed hashes.  This is the
 *             pattern used by malware to avoid storing cleartext API
 *             or command names.
 *
 * Difficulty: HARD
 *
 * Techniques:
 *   - DJB2 hash algorithm for command name hashing
 *   - Dispatch table keyed by hash value (not by string)
 *   - Stack-built command name strings (avoids .rdata references)
 *   - Indirect call through hash-to-function-pointer resolution
 *   - Dead/decoy hash entries that map to no-op handlers
 *   - Struct-based dispatch record with hash + function pointer
 *
 * Why it matters for testing:
 *   API hashing is one of the most common obfuscation techniques in
 *   real malware.  This sample tests whether:
 *     (a) Ghidra agents can identify the hash algorithm (DJB2 variant)
 *     (b) hashdb MCP can look up known hash values
 *     (c) FLOSS can recover the stack-built command strings
 *     (d) capa flags "resolve function by hash" behavioral rules
 *     (e) the planner produces work items that cover both the hash
 *         algorithm and the dispatch table
 *
 *   The dead/decoy entries test whether the analysis avoids false
 *   positives from unused hash values.
 *
 * Expected analysis signals:
 *   - Ghidra shows the hash computation loop (DJB2: h = h*33 + c)
 *   - hashdb may match known DJB2 hashes for common strings
 *   - FLOSS recovers stack strings: "ping", "exec", "exfil", "sleep"
 *   - Dispatch table visible in .rdata with hash + function pointer pairs
 *   - Dead entries (hash 0xDEADBEEF, 0xFEEDFACE) map to nop_handler
 *   - capa: "resolve function by hash", "use indirect call"
 *
 * Recommended MCP servers / tools:
 *   - ghidramcp       : decompilation of djb2_hash, resolve_command,
 *                        and the dispatch table structure
 *   - hashdbmcp       : lookup of precomputed DJB2 hashes
 *   - flareflossmcp   : stack string recovery for command names
 *   - CapaMCP         : hash-based resolution behavioral rules
 *   - stringmcp       : format strings and handler output messages
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------
 * djb2_hash -- Daniel J. Bernstein's hash function.
 * This is one of the most common hashing algorithms found in
 * malware for API name resolution.  The characteristic constant
 * is 5381 (initial seed) and the multiplier is 33.
 *
 * A reverse engineer should recognize the pattern:
 *   h = 5381
 *   for each char c: h = h * 33 + c
 * or equivalently:
 *   h = (h << 5) + h + c
 * --------------------------------------------------------------- */
static uint32_t djb2_hash(const char *s)
{
    uint32_t h = 5381;
    int c;
    while ((c = (unsigned char)*s++) != 0) {
        h = ((h << 5) + h) + (uint32_t)c;  /* h * 33 + c */
    }
    return h;
}

/* ---------------------------------------------------------------
 * Handler function type.
 * Each handler receives an opaque argument and returns a status.
 * --------------------------------------------------------------- */
typedef int (*CmdHandler)(int arg);

/*
 * DispatchRecord -- one entry in the hash-to-handler table.
 * `name_hash` is a precomputed DJB2 hash of the command name.
 * `handler` is the function pointer to invoke.
 * `tag` is a cleartext label for debugging output (would not
 * exist in real malware, but aids test verification).
 */
typedef struct {
    uint32_t    name_hash;
    CmdHandler  handler;
    const char *tag;
} DispatchRecord;

/* ---------------------------------------------------------------
 * Handler implementations.
 * Each simulates a different malware capability.
 * --------------------------------------------------------------- */

static int cmd_ping(int arg)
{
    printf("  [ping] sending heartbeat (seq=%d)\n", arg);
    return 0;
}

static int cmd_exec(int arg)
{
    printf("  [exec] executing payload stage %d\n", arg);
    return 0;
}

static int cmd_exfil(int arg)
{
    printf("  [exfil] exfiltrating data block %d\n", arg);
    return 0;
}

static int cmd_sleep(int arg)
{
    printf("  [sleep] sleeping for %d intervals\n", arg);
    return 0;
}

/*
 * nop_handler -- dead/decoy entry.
 * Maps to intentionally unused hash values.  Tests whether the
 * analysis correctly identifies these as unreachable.
 */
static int nop_handler(int arg)
{
    (void)arg;
    return 0;
}

/* ---------------------------------------------------------------
 * Precomputed hashes.
 * These are DJB2 hashes of the command name strings:
 *   djb2("ping")  = 0x7C9C4733
 *   djb2("exec")  = 0x7C967DAA
 *   djb2("exfil") = 0x0F66385D
 *   djb2("sleep") = 0x105CF61E
 *
 * The dead entries use obviously fake hashes that won't match
 * any real input, simulating decoy/padding entries.
 * --------------------------------------------------------------- */
#define HASH_PING   0x7C9C4733u
#define HASH_EXEC   0x7C967DAAu
#define HASH_EXFIL  0x0F66385Du
#define HASH_SLEEP  0x105CF61Eu
#define HASH_DEAD_1 0xDEADBEEFu
#define HASH_DEAD_2 0xFEEDFACEu

static const DispatchRecord DISPATCH_TABLE[] = {
    { HASH_PING,   cmd_ping,    "ping"   },
    { HASH_DEAD_1, nop_handler, "dead-1" },
    { HASH_EXEC,   cmd_exec,    "exec"   },
    { HASH_EXFIL,  cmd_exfil,   "exfil"  },
    { HASH_DEAD_2, nop_handler, "dead-2" },
    { HASH_SLEEP,  cmd_sleep,   "sleep"  },
};

#define TABLE_SIZE ((int)(sizeof(DISPATCH_TABLE) / sizeof(DISPATCH_TABLE[0])))

/* ---------------------------------------------------------------
 * resolve_command -- walks the dispatch table looking for a hash
 * match.  Returns the handler on match, NULL on miss.
 *
 * This is the indirect resolution site.  Ghidra will show a
 * loop over the table with a hash comparison and an indirect
 * call through the matched record's function pointer.
 * --------------------------------------------------------------- */
static CmdHandler resolve_command(uint32_t target_hash)
{
    for (int i = 0; i < TABLE_SIZE; i++) {
        if (DISPATCH_TABLE[i].name_hash == target_hash) {
            printf("  resolved hash 0x%08X -> %s\n",
                   target_hash, DISPATCH_TABLE[i].tag);
            return DISPATCH_TABLE[i].handler;
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------
 * build_and_dispatch -- builds a command name on the stack (to
 * avoid a .rdata string reference), hashes it, resolves the
 * handler, and calls it.
 *
 * The stack string construction is the pattern FLOSS is designed
 * to detect and recover.
 * --------------------------------------------------------------- */
static int build_and_dispatch(const char stack_chars[], int len, int arg)
{
    /* Copy from caller's stack array into a local null-terminated buffer.
     * This forces a memory copy that FLOSS can trace. */
    char cmd[32];
    if (len >= (int)sizeof(cmd))
        len = (int)sizeof(cmd) - 1;
    memcpy(cmd, stack_chars, (size_t)len);
    cmd[len] = '\0';

    uint32_t h = djb2_hash(cmd);
    printf("command '%s' -> hash 0x%08X\n", cmd, h);

    CmdHandler fn = resolve_command(h);
    if (!fn) {
        printf("  ERROR: no handler for hash 0x%08X\n", h);
        return -1;
    }

    /* INDIRECT CALL through resolved function pointer */
    return fn(arg);
}

int main(int argc, char **argv)
{
    (void)argv;

    puts("=== Hash Dispatch Test ===");

    /* Build command names as stack character arrays.
     * Each array is initialized with individual character literals
     * to avoid a single string constant in .rdata.
     * FLOSS should recover these through stack-string analysis. */

    char c_ping[]  = {'p', 'i', 'n', 'g'};
    char c_exec[]  = {'e', 'x', 'e', 'c'};
    char c_exfil[] = {'e', 'x', 'f', 'i', 'l'};
    char c_sleep[] = {'s', 'l', 'e', 'e', 'p'};

    int seq = (argc > 1) ? 5 : 1;

    build_and_dispatch(c_ping,  4, seq);
    build_and_dispatch(c_exec,  4, seq + 1);
    build_and_dispatch(c_exfil, 5, seq + 2);
    build_and_dispatch(c_sleep, 5, seq + 3);

    /* Try a command that won't resolve -- exercises the NULL path */
    char c_bad[] = {'n', 'o', 'p', 'e'};
    build_and_dispatch(c_bad, 4, 0);

    puts("marker:hash_dispatch");
    puts("marker:djb2_resolution");
    return 0;
}
