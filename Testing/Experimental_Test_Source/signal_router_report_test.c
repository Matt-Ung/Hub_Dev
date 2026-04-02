/*
 * File:       signal_router_report_test.c
 * Purpose:    Medium deception-oriented sample where cleartext strings and
 *             threatening helper names suggest destructive or exfiltration
 *             behavior, but the executable actually decodes a tiny routing
 *             script, updates four local counters, and writes a deterministic
 *             local bar-chart report.
 *
 * Difficulty: MEDIUM
 *
 * Techniques:
 *   - misleading function names and cleartext decoy labels
 *   - small opcode dispatcher with live and dead entries
 *   - XOR-protected output path and operation plan
 *   - deterministic local report generation from counter state
 *   - false-positive control: decoy strings remain referenced but inert
 *
 * Why it matters for testing:
 *   This sample is meant to sit between the obvious baseline binaries and the
 *   harder low-leakage deception cases. It checks whether an agent can avoid
 *   over-claiming from strings like wipe_restore_chain or ship_token_archive
 *   while still recovering the actual behavior from the live routing logic.
 *
 *   The true behavior is not hidden behind heavy obfuscation. A careful
 *   analyst can recover it through ordinary decompilation and control-flow
 *   reasoning, but not by reading strings alone.
 *
 * Expected analysis signals:
 *   - The fixed XOR key 0x3C is used to decode the routing plan
 *   - decode_signal_plan produces eight 4-byte operations
 *   - Live handlers update four lane counters and a small summary structure
 *   - The report path is runtime-decoded rather than stored as cleartext
 *   - Cleartext labels such as wipe_restore_chain and ship_token_archive do
 *     not correspond to destructive or credential-oriented behavior
 *
 * Recommended MCP servers / tools:
 *   - ghidramcp       : dispatcher recovery, handler behavior, report-writing
 *                       flow, and plan decode logic
 *   - stringmcp       : cleartext decoy labels and format strings
 *   - CapaMCP         : structural cues such as indirect dispatch or decode
 *                       helpers without over-claiming intent
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROUTE_CHANNELS 4
#define PLAN_KEY 0x3C

#define OP_INCREMENT_LANE 0x11
#define OP_FLOOR_LANE 0x22
#define OP_SPLIT_DELTA 0x33

#define OP_DROP_RECOVERY_CHAIN 0x91
#define OP_SHIP_TOKEN_ARCHIVE  0xA2

typedef struct {
    uint8_t opcode;
    uint8_t arg0;
    uint8_t arg1;
    uint8_t arg2;
} SignalOp;

typedef struct {
    int lanes[ROUTE_CHANNELS];
    int noise_fold;
    int executed_ops;
} SignalContext;

typedef struct {
    uint32_t checksum;
    int peak_channel;
    int peak_value;
} SignalSummary;

typedef void (*SignalHandler)(SignalContext *ctx, const SignalOp *op);

typedef struct {
    uint8_t opcode;
    const char *label;
    SignalHandler handler;
    int is_decoy;
} SignalDispatchEntry;

static const char *NOISE_LABELS[] = {
    "wipe_restore_chain",
    "ship_token_archive",
    "seed_remote_wiper",
    "flush_boot_ticket",
    NULL
};

static const uint8_t ENCODED_REPORT_PATH[] = {
    0x55, 0x4F, 0x41, 0x48, 0x47, 0x4A, 0x79, 0x54,
    0x49, 0x53, 0x52, 0x43, 0x54, 0x79, 0x54, 0x43,
    0x56, 0x49, 0x54, 0x52, 0x08, 0x52, 0x5E, 0x52,
};

static const uint8_t ENCODED_SIGNAL_PLAN[] = {
    0x2D, 0x3C, 0x3A, 0x3C,
    0x2D, 0x3D, 0x38, 0x3C,
    0x1E, 0x3E, 0x39, 0x3C,
    0x0F, 0x3E, 0x3F, 0x3C,
    0x2D, 0x3C, 0x3E, 0x3C,
    0x0F, 0x3D, 0x3D, 0x3C,
    0x1E, 0x3F, 0x38, 0x3C,
    0x2D, 0x3E, 0x3F, 0x3C,
};

static int clamp_lane(int value)
{
    if (value < 0) {
        return 0;
    }
    if (value > 24) {
        return 24;
    }
    return value;
}

/* REAL behavior, deceptive name: increment a single local lane counter. */
static void wipe_restore_chain(SignalContext *ctx, const SignalOp *op)
{
    int lane = (int)(op->arg0 % ROUTE_CHANNELS);
    ctx->lanes[lane] = clamp_lane(ctx->lanes[lane] + (int)op->arg1);
}

/* REAL behavior, deceptive name: enforce a minimum floor on one lane. */
static void seed_remote_beacon(SignalContext *ctx, const SignalOp *op)
{
    int lane = (int)(op->arg0 % ROUTE_CHANNELS);
    int floor = (int)op->arg1;
    if (ctx->lanes[lane] < floor) {
        ctx->lanes[lane] = clamp_lane(floor);
    }
}

/* REAL behavior, deceptive name: split a delta between adjacent lanes. */
static void collect_credential_rows(SignalContext *ctx, const SignalOp *op)
{
    int lane = (int)(op->arg0 % ROUTE_CHANNELS);
    int next = (lane + 1) % ROUTE_CHANNELS;
    int delta = (int)op->arg1;
    ctx->lanes[lane] = clamp_lane(ctx->lanes[lane] + delta);
    ctx->lanes[next] = clamp_lane(ctx->lanes[next] + (delta / 2));
}

/* DECOY-ONLY: threatening label with no side effects beyond a sink. */
static void drop_recovery_chain(SignalContext *ctx, const SignalOp *op)
{
    volatile uint32_t sink = (uint32_t)(ctx->noise_fold + op->opcode + op->arg0);
    (void)sink;
}

/* DECOY-ONLY: threatening label with no side effects beyond a sink. */
static void ship_token_archive(SignalContext *ctx, const SignalOp *op)
{
    volatile uint32_t sink = (uint32_t)(ctx->executed_ops + op->arg1 + op->arg2);
    (void)sink;
}

static const SignalDispatchEntry DISPATCH_TABLE[] = {
    {OP_INCREMENT_LANE, "wipe_restore_chain", wipe_restore_chain, 0},
    {OP_FLOOR_LANE, "seed_remote_beacon", seed_remote_beacon, 0},
    {OP_SPLIT_DELTA, "collect_credential_rows", collect_credential_rows, 0},
    {OP_DROP_RECOVERY_CHAIN, "drop_recovery_chain", drop_recovery_chain, 1},
    {OP_SHIP_TOKEN_ARCHIVE, "ship_token_archive", ship_token_archive, 1},
};

static const SignalDispatchEntry *resolve_dispatch(uint8_t opcode)
{
    int count = (int)(sizeof(DISPATCH_TABLE) / sizeof(DISPATCH_TABLE[0]));
    for (int i = 0; i < count; i++) {
        if (DISPATCH_TABLE[i].opcode == opcode) {
            return &DISPATCH_TABLE[i];
        }
    }
    return NULL;
}

/* REAL behavior: keep cleartext decoys referenced without using them as logic. */
static int fold_noise_labels(void)
{
    int fold = 0x2442;
    for (int i = 0; NOISE_LABELS[i] != NULL; i++) {
        const char *label = NOISE_LABELS[i];
        fold = ((fold << 3) ^ (fold >> 1)) + (int)strlen(label);
        fold ^= (unsigned char)label[0];
    }
    return fold & 0x7fffffff;
}

static void decode_report_path(char *out, size_t out_size)
{
    size_t limit = sizeof(ENCODED_REPORT_PATH);
    if (limit + 1 > out_size) {
        limit = out_size - 1;
    }
    for (size_t i = 0; i < limit; i++) {
        out[i] = (char)(ENCODED_REPORT_PATH[i] ^ 0x26);
    }
    out[limit] = '\0';
}

/* REAL behavior: decode the fixed plan into live routing operations. */
static int decode_signal_plan(SignalOp *ops, int max_ops)
{
    int count = (int)(sizeof(ENCODED_SIGNAL_PLAN) / 4);
    if (count > max_ops) {
        count = max_ops;
    }
    for (int i = 0; i < count; i++) {
        int base = i * 4;
        ops[i].opcode = (uint8_t)(ENCODED_SIGNAL_PLAN[base + 0] ^ PLAN_KEY);
        ops[i].arg0 = (uint8_t)(ENCODED_SIGNAL_PLAN[base + 1] ^ PLAN_KEY);
        ops[i].arg1 = (uint8_t)(ENCODED_SIGNAL_PLAN[base + 2] ^ PLAN_KEY);
        ops[i].arg2 = (uint8_t)(ENCODED_SIGNAL_PLAN[base + 3] ^ PLAN_KEY);
    }
    return count;
}

static int run_signal_plan(SignalContext *ctx, const SignalOp *ops, int count)
{
    int executed = 0;
    for (int i = 0; i < count; i++) {
        const SignalDispatchEntry *entry = resolve_dispatch(ops[i].opcode);
        if (entry == NULL) {
            continue;
        }
        entry->handler(ctx, &ops[i]);
        if (!entry->is_decoy) {
            executed++;
        }
    }
    ctx->executed_ops = executed;
    return executed;
}

static void summarize_lanes(const SignalContext *ctx, SignalSummary *summary)
{
    summary->checksum = 0x73514B2Fu;
    summary->peak_channel = 0;
    summary->peak_value = ctx->lanes[0];
    for (int i = 0; i < ROUTE_CHANNELS; i++) {
        uint32_t lane_value = (uint32_t)ctx->lanes[i];
        summary->checksum = ((summary->checksum << 5) | (summary->checksum >> 27))
            ^ (lane_value + (uint32_t)(i * 17 + 3));
        if (ctx->lanes[i] > summary->peak_value) {
            summary->peak_value = ctx->lanes[i];
            summary->peak_channel = i;
        }
    }
}

static int write_signal_report(const SignalContext *ctx, const SignalSummary *summary, const char *path)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "lanes=%d\n", ROUTE_CHANNELS);
    fprintf(fp, "executed=%d\n", ctx->executed_ops);
    fprintf(fp, "noise=%d\n", ctx->noise_fold);
    fprintf(fp, "peak=%d:%d\n", summary->peak_channel, summary->peak_value);
    fprintf(fp, "checksum=%u\n", (unsigned)summary->checksum);
    fprintf(fp, "totals=%d,%d,%d,%d\n",
            ctx->lanes[0], ctx->lanes[1], ctx->lanes[2], ctx->lanes[3]);
    fputs("bars:\n", fp);
    for (int i = 0; i < ROUTE_CHANNELS; i++) {
        fprintf(fp, "%d:", i);
        for (int j = 0; j < ctx->lanes[i]; j++) {
            fputc('#', fp);
        }
        fputc('\n', fp);
    }

    fclose(fp);
    return 0;
}

int main(void)
{
    SignalContext ctx;
    SignalSummary summary;
    SignalOp ops[12];
    char report_path[48];
    int op_count;

    memset(&ctx, 0, sizeof(ctx));
    decode_report_path(report_path, sizeof(report_path));

    puts("=== Signal Router Report Test ===");

    ctx.noise_fold = fold_noise_labels();
    op_count = decode_signal_plan(ops, (int)(sizeof(ops) / sizeof(ops[0])));
    run_signal_plan(&ctx, ops, op_count);
    summarize_lanes(&ctx, &summary);

    if (write_signal_report(&ctx, &summary, report_path) != 0) {
        puts("[warn] failed to write signal router report");
        return 1;
    }

    printf("decoded_ops=%d\n", op_count);
    printf("executed_ops=%d\n", ctx.executed_ops);
    printf("peak_lane=%d\n", summary.peak_channel);
    puts("marker:signal_router");
    return 0;
}
