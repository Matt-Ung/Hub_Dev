/*
 * File:       anti_analysis_suite_test.c
 * Purpose:    Composite anti-analysis sample combining debugger detection,
 *             timing probes, environment fingerprinting, encrypted config,
 *             dead code branches, and misleading function names.  This is
 *             the "kitchen sink" hard sample that exercises the broadest
 *             set of MCP tools simultaneously.
 *
 * Difficulty: HARD
 *
 * Techniques:
 *   - IsDebuggerPresent / CheckRemoteDebuggerPresent (Windows API)
 *   - QueryPerformanceCounter timing probe
 *   - Environment variable fingerprinting (USERNAME, COMPUTERNAME)
 *   - Encrypted configuration blob (XOR with rotating key)
 *   - Dead code branches guarded by opaque predicates
 *   - Misleading function names (e.g., "update_display" does anti-debug)
 *   - Stack strings for sensitive API names
 *   - Conditional behavior: different execution paths depending on
 *     whether debugger/sandbox is detected
 *
 * Why it matters for testing:
 *   This sample forces the analysis pipeline to coordinate across
 *   multiple tool domains:
 *     - Ghidra for control flow and function decompilation
 *     - capa for anti-debug and anti-analysis behavioral rules
 *     - FLOSS for stack string recovery
 *     - strings for cleartext indicator extraction
 *     - YARA for rule-based pattern matching on anti-debug APIs
 *
 *   The misleading function names test whether agents reason about
 *   actual behavior rather than trusting symbol names.  The dead code
 *   branches test whether the report distinguishes reachable from
 *   unreachable paths.
 *
 *   On non-Windows platforms, the Windows API calls are replaced with
 *   stubs that return safe defaults, so the binary compiles and runs
 *   everywhere.  The analysis challenge remains because the code
 *   structure, strings, and control flow are identical.
 *
 * Expected analysis signals:
 *   - capa: "check for debugger", "reference anti-debugging API",
 *     "query performance counter", "reference environment variable"
 *   - FLOSS recovers stack strings: "IsDebuggerPresent",
 *     "CheckRemoteDebuggerPresent", "kernel32.dll"
 *   - Ghidra shows opaque predicate branches and dead code
 *   - YARA may match anti-debug API name patterns
 *   - Report should note that "update_display" actually performs
 *     debugger detection (misleading name)
 *   - Report should identify the encrypted config blob and its
 *     rotating-key XOR decode routine
 *
 * Recommended MCP servers / tools:
 *   - ghidramcp       : decompilation, control flow analysis, function
 *                        naming anomalies
 *   - CapaMCP         : anti-debug, anti-analysis behavioral rules
 *   - flareflossmcp   : stack string recovery for API names
 *   - stringmcp       : cleartext indicators, environment var names
 *   - yaramcp         : anti-debug API pattern matching
 *   - hashdbmcp       : if any hashes appear in the anti-debug logic
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------
 * Platform abstraction.
 * On Windows, use real WinAPI calls.  On other platforms, provide
 * stubs that return "not detected" so the binary compiles and the
 * code structure is preserved for analysis.
 * --------------------------------------------------------------- */
#if defined(_WIN32)
#include <windows.h>
#else
/* Stub types and functions for non-Windows compilation */
typedef int BOOL;
typedef unsigned long DWORD;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void (*FARPROC)(void);
#define FALSE 0
#define TRUE  1
#define WINAPI

static HANDLE GetCurrentProcess(void) { return (HANDLE)0; }
static BOOL IsDebuggerPresent(void) { return FALSE; }
static BOOL CheckRemoteDebuggerPresent(HANDLE h, BOOL *pb) {
    (void)h; *pb = FALSE; return TRUE;
}

typedef struct { long long QuadPart; } LARGE_INTEGER;
static BOOL QueryPerformanceFrequency(LARGE_INTEGER *f) {
    f->QuadPart = 1000000LL; return TRUE;
}
static BOOL QueryPerformanceCounter(LARGE_INTEGER *c) {
    static long long tick = 0;
    c->QuadPart = tick++; return TRUE;
}

static char *getenv_stub(const char *name) {
    (void)name; return NULL;
}
#define getenv getenv_stub
#endif

/* ---------------------------------------------------------------
 * AnalysisContext -- shared state across all detection checks.
 * Accumulates a detection score.  Higher score = more evidence
 * of analysis environment.
 * --------------------------------------------------------------- */
typedef struct {
    int  debugger_score;
    int  timing_score;
    int  env_score;
    int  total_score;
    char findings[512];
    int  findings_len;
} AnalysisContext;

static void append_finding(AnalysisContext *ctx, const char *msg)
{
    int mlen = (int)strlen(msg);
    if (ctx->findings_len + mlen + 2 >= (int)sizeof(ctx->findings))
        return;
    if (ctx->findings_len > 0)
        ctx->findings[ctx->findings_len++] = ';';
    memcpy(ctx->findings + ctx->findings_len, msg, (size_t)mlen);
    ctx->findings_len += mlen;
    ctx->findings[ctx->findings_len] = '\0';
}

/* ---------------------------------------------------------------
 * MISLEADING FUNCTION NAME: update_display
 * Despite its innocent name, this function performs debugger
 * detection using IsDebuggerPresent and CheckRemoteDebuggerPresent.
 *
 * The API names are built as stack strings to avoid cleartext
 * references in .rdata.  FLOSS should recover them.
 *
 * A good analysis report should note the name/behavior mismatch.
 * --------------------------------------------------------------- */
static int update_display(AnalysisContext *ctx)
{
    /* Stack-build "IsDebuggerPresent" to hide from naive string scan */
    char api1[] = {'I','s','D','e','b','u','g','g','e','r',
                   'P','r','e','s','e','n','t','\0'};

    /* Stack-build "CheckRemoteDebuggerPresent" */
    char api2[] = {'C','h','e','c','k','R','e','m','o','t','e',
                   'D','e','b','u','g','g','e','r',
                   'P','r','e','s','e','n','t','\0'};

    printf("  [update_display] checking: %s\n", api1);
    if (IsDebuggerPresent()) {
        ctx->debugger_score += 10;
        append_finding(ctx, "IsDebuggerPresent=true");
    }

    printf("  [update_display] checking: %s\n", api2);
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) {
        ctx->debugger_score += 10;
        append_finding(ctx, "RemoteDebugger=true");
    }

    return ctx->debugger_score;
}

/* ---------------------------------------------------------------
 * timing_probe -- measures execution time of a busy loop.
 * Under a debugger or single-step tracer, the elapsed time will
 * be much larger than normal.
 *
 * Threshold: if > 100000 microseconds for a simple loop, flag it.
 * --------------------------------------------------------------- */
static int timing_probe(AnalysisContext *ctx)
{
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    /* Busy loop -- the volatile prevents optimization */
    volatile int sink = 0;
    for (int i = 0; i < 3000000; i++) {
        sink += i;
    }

    QueryPerformanceCounter(&end);

    long long elapsed_us = 0;
    if (freq.QuadPart > 0) {
        elapsed_us = ((end.QuadPart - start.QuadPart) * 1000000LL)
                     / freq.QuadPart;
    }

    printf("  [timing_probe] elapsed=%lld us\n", elapsed_us);

    if (elapsed_us > 100000) {
        ctx->timing_score += 5;
        append_finding(ctx, "timing_anomaly");
    }

    return ctx->timing_score;
}

/* ---------------------------------------------------------------
 * env_fingerprint -- checks environment variables for known
 * sandbox/analysis indicators.
 *
 * Checks: USERNAME for common sandbox usernames, COMPUTERNAME
 * for known VM identifiers.
 * --------------------------------------------------------------- */
static int env_fingerprint(AnalysisContext *ctx)
{
    /* Known sandbox/analysis usernames */
    static const char *SUSPECT_USERS[] = {
        "sandbox", "malware", "virus", "analyst",
        "john", "test", "admin", "user", NULL
    };

    /* Known VM/sandbox computer names */
    static const char *SUSPECT_HOSTS[] = {
        "SANDBOX", "VIRUS", "MALWARE", "TEQUILA",
        "PC-", "WIN-", "DESKTOP-", NULL
    };

    const char *username = getenv("USERNAME");
    if (!username)
        username = getenv("USER");

    const char *hostname = getenv("COMPUTERNAME");
    if (!hostname)
        hostname = getenv("HOSTNAME");

    if (username) {
        printf("  [env] USERNAME=%s\n", username);
        for (int i = 0; SUSPECT_USERS[i]; i++) {
            /* Case-insensitive substring match */
            const char *u = username;
            const char *s = SUSPECT_USERS[i];
            int slen = (int)strlen(s);
            while (*u) {
                int match = 1;
                for (int j = 0; j < slen && u[j]; j++) {
                    char uc = u[j];
                    char sc = s[j];
                    if (uc >= 'A' && uc <= 'Z') uc += 32;
                    if (sc >= 'A' && sc <= 'Z') sc += 32;
                    if (uc != sc) { match = 0; break; }
                }
                if (match) {
                    ctx->env_score += 3;
                    append_finding(ctx, "suspect_username");
                    break;
                }
                u++;
            }
        }
    }

    if (hostname) {
        printf("  [env] COMPUTERNAME=%s\n", hostname);
        for (int i = 0; SUSPECT_HOSTS[i]; i++) {
            if (strstr(hostname, SUSPECT_HOSTS[i])) {
                ctx->env_score += 3;
                append_finding(ctx, "suspect_hostname");
                break;
            }
        }
    }

    return ctx->env_score;
}

/* ---------------------------------------------------------------
 * Encrypted configuration blob with rotating XOR key.
 *
 * Plaintext: "c2=https://update.example.net/api;sleep=600;id=AA-0042"
 * Key rotation: key starts at 0x1F, increments by 0x07 each byte.
 *
 * This is harder for FLOSS than a fixed-key XOR because the key
 * changes per byte.  The agent should identify the rotation pattern
 * from Ghidra decompilation.
 * --------------------------------------------------------------- */
/* Actual config encoding done at runtime for source readability */
static uint8_t g_encrypted_config[128];
static int     g_encrypted_config_len;

static void init_config(void)
{
    const char *plain =
        "c2=https://update.example.net/api;sleep=600;id=AA-0042";
    int len = (int)strlen(plain);
    uint8_t key = 0x1F;

    for (int i = 0; i < len; i++) {
        g_encrypted_config[i] = (uint8_t)plain[i] ^ key;
        key = (uint8_t)(key + 0x07);
    }
    g_encrypted_config_len = len;
}

static void decrypt_config(char *out, const uint8_t *enc, int len)
{
    uint8_t key = 0x1F;
    for (int i = 0; i < len; i++) {
        out[i] = (char)(enc[i] ^ key);
        key = (uint8_t)(key + 0x07);
    }
    out[len] = '\0';
}

/* ---------------------------------------------------------------
 * DEAD CODE: never_called -- guarded by an opaque predicate that
 * always evaluates to false.  The purpose is to test whether the
 * analysis correctly identifies this as unreachable.
 * --------------------------------------------------------------- */
static void never_called(void)
{
    puts("DECOY: this function should never execute");
    puts("DECOY: if you see this, the opaque predicate failed");
}

/* ---------------------------------------------------------------
 * opaque_false -- returns 0 always, but the computation is complex
 * enough that the compiler/decompiler cannot trivially prove it.
 *
 * Identity: for any integer x, (x*x + x) is always even, so
 * ((x*x + x) % 2) == 0 always.
 * --------------------------------------------------------------- */
static int opaque_false(int x)
{
    int v = x * x + x;
    return (v % 2) != 0;  /* always false */
}

int main(int argc, char **argv)
{
    (void)argv;

    puts("=== Anti-Analysis Suite Test ===");

    /* Initialize encrypted config */
    init_config();

    AnalysisContext ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Run detection checks -- note the misleading function name */
    printf("[phase 1: display update]\n");
    update_display(&ctx);

    printf("[phase 2: timing calibration]\n");
    timing_probe(&ctx);

    printf("[phase 3: environment setup]\n");
    env_fingerprint(&ctx);

    /* Aggregate score */
    ctx.total_score = ctx.debugger_score + ctx.timing_score + ctx.env_score;
    printf("\ndetection score: %d (dbg=%d timing=%d env=%d)\n",
           ctx.total_score, ctx.debugger_score,
           ctx.timing_score, ctx.env_score);

    if (ctx.findings_len > 0) {
        printf("findings: %s\n", ctx.findings);
    }

    /* Conditional behavior: if analysis detected, skip config decode.
     * This simulates malware that refuses to run in a sandbox. */
    if (ctx.total_score >= 10) {
        puts("WARNING: analysis environment detected, aborting config load");
    } else {
        /* Decrypt and display config */
        char config[128];
        decrypt_config(config, g_encrypted_config, g_encrypted_config_len);
        printf("config: %s\n", config);
    }

    /* Dead code branch -- opaque predicate ensures this never runs.
     * The analysis should identify this as unreachable. */
    if (opaque_false(argc)) {
        never_called();
    }

    puts("marker:anti_analysis_suite");
    puts("marker:debugger_detection");
    puts("marker:environment_fingerprint");
    return 0;
}
