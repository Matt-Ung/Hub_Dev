/*
 * File:       callback_dispatch_test.c
 * Purpose:    Function-pointer dispatch table with error handling paths
 *             and state transitions.  Represents a realistic command
 *             dispatcher pattern found in protocol handlers, plugin
 *             loaders, and event-driven systems.
 *
 * Difficulty: MEDIUM
 *
 * Techniques:
 *   - Function pointer table (array of typed callback pointers)
 *   - Struct-based command descriptors
 *   - State transitions driven by callback return values
 *   - Error handling paths (bad opcode, handler failure, overflow guard)
 *   - Indirect calls that Ghidra must resolve through data-flow analysis
 *
 * Why it matters for testing:
 *   Indirect calls through function pointer tables are a common source
 *   of incomplete or incorrect Ghidra decompilation.  The decompiler
 *   may show `(*pfn)(arg)` without resolving which function is called.
 *   This tests whether the analysis pipeline's agents can:
 *     (a) identify the dispatch table in .rdata
 *     (b) enumerate the concrete target functions
 *     (c) explain the state machine that sequences commands
 *
 *   capa should flag "dispatch function by index" or similar behavioral
 *   rules.  The error-handling branches add realistic control-flow
 *   complexity that planners must decompose into work items.
 *
 * Expected analysis signals:
 *   - Ghidra shows a function pointer array with 5 entries
 *   - Each handler function is identified and decompiled
 *   - The dispatch loop's bounds check and error path are visible
 *   - State transitions (IDLE -> RUNNING -> DONE / ERROR) are traced
 *   - String literals from each handler are recovered
 *
 * Recommended MCP servers / tools:
 *   - ghidramcp       : decompilation, xrefs to function pointers,
 *                        call graph (indirect edges)
 *   - CapaMCP         : behavioral rules for indirect dispatch
 *   - stringmcp       : handler status messages
 *   - flareflossmcp   : confirm no hidden/encoded strings
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------
 * State definitions for the command executor.
 * The state machine is intentionally simple: IDLE -> RUNNING ->
 * DONE or ERROR.  The analysis challenge comes from the indirect
 * call dispatch, not from state-space explosion.
 * --------------------------------------------------------------- */
typedef enum {
    STATE_IDLE    = 0,
    STATE_RUNNING = 1,
    STATE_DONE    = 2,
    STATE_ERROR   = 3
} ExecState;

/*
 * ExecContext -- mutable context threaded through every handler.
 * Handlers accumulate results in `result_acc` and may set the
 * error flag to trigger an early abort in the dispatch loop.
 */
typedef struct {
    ExecState state;
    int       result_acc;
    int       error_code;
    int       steps_executed;
    char      trace[256];
    size_t    trace_len;
} ExecContext;

/* ---------------------------------------------------------------
 * Handler function type.
 * Returns 0 on success, nonzero on failure.  The dispatch loop
 * checks the return value and transitions to STATE_ERROR on any
 * nonzero result.
 * --------------------------------------------------------------- */
typedef int (*HandlerFn)(ExecContext *ctx, int arg);

/*
 * CommandDescriptor -- pairs a human-readable name with its handler.
 * The dispatch table is an array of these descriptors.
 */
typedef struct {
    const char *name;
    HandlerFn   handler;
} CommandDescriptor;

/* ---------------------------------------------------------------
 * Helper: append a token to the execution trace.
 * The trace lets a reverse engineer verify dispatch order even if
 * they only inspect the final state of ctx->trace in a debugger.
 * --------------------------------------------------------------- */
static void trace_push(ExecContext *ctx, const char *token)
{
    size_t tlen = strlen(token);
    if (ctx->trace_len + tlen + 2 >= sizeof(ctx->trace))
        return;
    if (ctx->trace_len > 0) {
        ctx->trace[ctx->trace_len++] = '|';
    }
    memcpy(ctx->trace + ctx->trace_len, token, tlen);
    ctx->trace_len += tlen;
    ctx->trace[ctx->trace_len] = '\0';
}

/* ---------------------------------------------------------------
 * Handler implementations.
 * Each handler performs a trivial computation and appends to the
 * trace.  The analysis challenge is that these are called
 * *indirectly* through the dispatch table, so Ghidra must resolve
 * the function pointer to identify which handler runs.
 * --------------------------------------------------------------- */

/* cmd_init: initialization step.  Always succeeds. */
static int cmd_init(ExecContext *ctx, int arg)
{
    (void)arg;
    puts("  [handler] cmd_init: initializing context");
    ctx->result_acc = 0;
    trace_push(ctx, "init");
    return 0;
}

/* cmd_load: simulates loading a resource.  Fails if arg is negative. */
static int cmd_load(ExecContext *ctx, int arg)
{
    printf("  [handler] cmd_load: loading resource %d\n", arg);
    if (arg < 0) {
        ctx->error_code = -1;
        trace_push(ctx, "load:FAIL");
        return -1;
    }
    ctx->result_acc += arg;
    trace_push(ctx, "load");
    return 0;
}

/* cmd_transform: applies a simple transformation to the accumulator. */
static int cmd_transform(ExecContext *ctx, int arg)
{
    printf("  [handler] cmd_transform: acc=%d, multiplier=%d\n",
           ctx->result_acc, arg);
    ctx->result_acc *= (arg != 0) ? arg : 1;
    trace_push(ctx, "transform");
    return 0;
}

/* cmd_validate: checks the accumulator against bounds. */
static int cmd_validate(ExecContext *ctx, int arg)
{
    (void)arg;
    printf("  [handler] cmd_validate: checking acc=%d\n", ctx->result_acc);
    if (ctx->result_acc < 0 || ctx->result_acc > 100000) {
        ctx->error_code = -2;
        trace_push(ctx, "validate:FAIL");
        return -2;
    }
    trace_push(ctx, "validate");
    return 0;
}

/* cmd_finalize: marks execution as complete. */
static int cmd_finalize(ExecContext *ctx, int arg)
{
    (void)arg;
    printf("  [handler] cmd_finalize: result=%d\n", ctx->result_acc);
    trace_push(ctx, "finalize");
    return 0;
}

/* ---------------------------------------------------------------
 * Dispatch table.
 * This is the core analysis target.  A reverse engineer must find
 * this array in .rdata and resolve each function pointer back to
 * its handler implementation.
 * --------------------------------------------------------------- */
static const CommandDescriptor COMMAND_TABLE[] = {
    { "INIT",      cmd_init      },
    { "LOAD",      cmd_load      },
    { "TRANSFORM", cmd_transform },
    { "VALIDATE",  cmd_validate  },
    { "FINALIZE",  cmd_finalize  },
};

#define CMD_COUNT ((int)(sizeof(COMMAND_TABLE) / sizeof(COMMAND_TABLE[0])))

/* ---------------------------------------------------------------
 * run_dispatch -- walks the command table and calls each handler.
 * This function contains the indirect call site that Ghidra must
 * analyze.  The bounds check, error check, and state transitions
 * add realistic control-flow complexity.
 * --------------------------------------------------------------- */
static int run_dispatch(ExecContext *ctx, const int *args, int nargs)
{
    ctx->state = STATE_RUNNING;

    for (int i = 0; i < CMD_COUNT; i++) {
        /* Bounds guard: if fewer args than commands, use 0 as default */
        int arg = (i < nargs) ? args[i] : 0;

        printf("dispatch[%d]: %s (arg=%d)\n", i, COMMAND_TABLE[i].name, arg);

        /* --- INDIRECT CALL --- */
        int rc = COMMAND_TABLE[i].handler(ctx, arg);
        ctx->steps_executed++;

        if (rc != 0) {
            printf("dispatch[%d]: handler returned error %d, aborting\n", i, rc);
            ctx->state = STATE_ERROR;
            return rc;
        }
    }

    ctx->state = STATE_DONE;
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;

    ExecContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.state = STATE_IDLE;

    /* Argument array drives the handlers.  Use argc to inject a small
     * amount of variability so the binary is not fully constant-folded. */
    int args[] = { 0, (argc > 1) ? 42 : 10, 3, 0, 0 };

    puts("=== Callback Dispatch Test ===");
    int rc = run_dispatch(&ctx, args, (int)(sizeof(args) / sizeof(args[0])));

    printf("final state: %d (0=idle 1=running 2=done 3=error)\n", ctx.state);
    printf("result_acc:  %d\n", ctx.result_acc);
    printf("steps:       %d\n", ctx.steps_executed);
    printf("trace:       %s\n", ctx.trace);

    if (rc != 0) {
        printf("error_code:  %d\n", ctx.error_code);
    }

    puts("marker:callback_dispatch");
    return rc;
}
