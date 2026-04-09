/*
 * File:       branch_weave_snapshot_test.c
 * Purpose:    Hard deception-oriented sample where threatening labels and
 *             dormant decoded notices surround a compact encoded drawing
 *             program. The true behavior is benign and local: decode the
 *             program, update an 8x8 in-memory grid, compute a summary, and
 *             write a short local report with minimal descriptive strings.
 *
 * Difficulty: HARD
 *
 * Techniques:
 *   - misleading function names around the live drawing logic
 *   - encoded operation stream with a fixed XOR decode step
 *   - dispatcher with live and dead entries
 *   - minimal true-behavior strings to reduce string/FLOSS trivialization
 *   - dormant decoded notices and inert decoy labels
 *   - explicit stripped variant recommended for harder symbol-light sweeps
 *
 * Why it matters for testing:
 *   This sample is intended to be harder than the earlier deception binaries.
 *   A strings-only pass should recover the threatening decoys, but it should
 *   not recover enough to narrate the real behavior confidently. Recovering
 *   the program's purpose requires following the decoded instruction stream and
 *   the live grid-update handlers.
 *
 * Expected analysis signals:
 *   - decode_branch_program XOR-decodes ten 4-byte operations with key 0x4D
 *   - Live handlers update an 8x8 grid by setting points, drawing spans, and
 *     stamping local 2x2 blocks
 *   - The report path is decoded at runtime and the report schema uses terse
 *     labels rather than explanatory prose
 *   - Threatening strings such as flush_ticket_vault or ship_shadow_bundle are
 *     decoys or dormant notices rather than real destructive behavior
 *   - Dead handler opcodes 0x91, 0xA2, and 0xB3 are present but unused
 *
 * Recommended MCP servers / tools:
 *   - ghidramcp       : decode loop, dispatcher recovery, live grid-update
 *                       handlers, and report-writing logic
 *   - flareflossmcp   : dormant decoded-notice recovery
 *   - stringmcp       : decoy labels and short report literals
 *   - CapaMCP         : structural cues without over-claiming capability
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GRID_W 8
#define GRID_H 8
#define PROGRAM_KEY 0x4D

#define OP_PLOT_POINT 0x11
#define OP_DRAW_ROW   0x22
#define OP_DRAW_COL   0x33
#define OP_STAMP_2X2  0x44

#define OP_FLUSH_TICKET_VAULT 0x91
#define OP_SHIP_SHADOW_BUNDLE 0xA2
#define OP_DROP_RECOVERY_MESH 0xB3

typedef struct {
    uint8_t opcode;
    uint8_t arg0;
    uint8_t arg1;
    uint8_t arg2;
} WeaveOp;

typedef struct {
    uint8_t grid[GRID_H][GRID_W];
    int noise_fold;
    int executed_ops;
} WeaveContext;

typedef struct {
    uint32_t checksum;
    int nonzero_cells;
    int max_value;
    int row_sums[GRID_H];
} WeaveSummary;

typedef void (*WeaveHandler)(WeaveContext *ctx, const WeaveOp *op);

typedef struct {
    uint8_t opcode;
    WeaveHandler handler;
    int is_decoy;
} WeaveDispatchEntry;

static const char *FALSE_LABELS[] = {
    "flush_ticket_vault",
    "ship_shadow_bundle",
    "drop_recovery_mesh",
    "erase_domain_secrets",
    NULL
};

static const uint8_t ENCODED_REPORT_PATH[] = {
    0x26, 0x33, 0x1B, 0x23, 0x36, 0x2D, 0x20, 0x1B,
    0x36, 0x21, 0x34, 0x2B, 0x36, 0x30, 0x6A, 0x30,
    0x3C, 0x30,
};

static const uint8_t ENCODED_PROGRAM[] = {
    0x6F, 0x4C, 0x4D, 0x4B,
    0x6F, 0x4B, 0x4C, 0x48,
    0x7E, 0x49, 0x4D, 0x45,
    0x5C, 0x4C, 0x4C, 0x44,
    0x5C, 0x4B, 0x4B, 0x45,
    0x09, 0x4F, 0x4E, 0x48,
    0x09, 0x48, 0x4F, 0x49,
    0x7E, 0x4D, 0x49, 0x49,
    0x6F, 0x4D, 0x48, 0x4E,
    0x5C, 0x4A, 0x4D, 0x4A,
};

static const uint8_t FALSE_NOTICE_A[] = {
    0x4E, 0x44, 0x5D, 0x5B, 0x40, 0x77, 0x5C, 0x41, 0x4B,
    0x43, 0x4D, 0x5C, 0x77, 0x5E, 0x49, 0x5D, 0x44, 0x5C,
};

static const uint8_t FALSE_NOTICE_B[] = {
    0x5B, 0x40, 0x41, 0x58, 0x77, 0x5B, 0x40, 0x49, 0x4C,
    0x47, 0x5F, 0x77, 0x4A, 0x5D, 0x46, 0x4C, 0x44, 0x4D,
};

static uint8_t clamp_shade(uint8_t value)
{
    return (uint8_t)(value % 10);
}

/* REAL behavior, deceptive name: plot one point on the local grid. */
static void flush_ticket_vault(WeaveContext *ctx, const WeaveOp *op)
{
    int x = (int)(op->arg0 % GRID_W);
    int y = (int)(op->arg1 % GRID_H);
    ctx->grid[y][x] = clamp_shade(op->arg2);
}

/* REAL behavior, deceptive name: draw a short horizontal span. */
static void ship_shadow_bundle(WeaveContext *ctx, const WeaveOp *op)
{
    int row = (int)(op->arg0 % GRID_H);
    int start = (int)(op->arg1 % GRID_W);
    int length = (int)(op->arg2 % GRID_W);
    uint8_t shade = clamp_shade((uint8_t)(((op->arg0 + op->arg2) % 7) + 2));

    for (int x = start; x < start + length && x < GRID_W; x++) {
        ctx->grid[row][x] = shade;
    }
}

/* REAL behavior, deceptive name: draw a short vertical span. */
static void drop_recovery_mesh(WeaveContext *ctx, const WeaveOp *op)
{
    int col = (int)(op->arg0 % GRID_W);
    int start = (int)(op->arg1 % GRID_H);
    int length = (int)(op->arg2 % GRID_H);
    uint8_t shade = clamp_shade((uint8_t)(((op->arg0 * 2 + op->arg2) % 7) + 1));

    for (int y = start; y < start + length && y < GRID_H; y++) {
        ctx->grid[y][col] = shade;
    }
}

/* REAL behavior, deceptive name: stamp a 2x2 local block. */
static void erase_domain_secrets(WeaveContext *ctx, const WeaveOp *op)
{
    int x0 = (int)(op->arg0 % GRID_W);
    int y0 = (int)(op->arg1 % GRID_H);
    uint8_t shade = clamp_shade((uint8_t)(op->arg2 + 1));

    for (int dy = 0; dy < 2; dy++) {
        for (int dx = 0; dx < 2; dx++) {
            int x = x0 + dx;
            int y = y0 + dy;
            if (x < GRID_W && y < GRID_H) {
                ctx->grid[y][x] = shade;
            }
        }
    }
}

/* DECOY-ONLY: threatening label, no real behavior. */
static void disable_boot_catalog(WeaveContext *ctx, const WeaveOp *op)
{
    volatile uint32_t sink = (uint32_t)(ctx->noise_fold + op->arg0 + op->arg1 + op->arg2);
    (void)sink;
}

/* DECOY-ONLY: threatening label, no real behavior. */
static void export_ticket_queue(WeaveContext *ctx, const WeaveOp *op)
{
    volatile uint32_t sink = (uint32_t)(ctx->executed_ops + op->opcode);
    (void)sink;
}

/* DECOY-ONLY: threatening label, no real behavior. */
static void seed_reboot_branch(WeaveContext *ctx, const WeaveOp *op)
{
    volatile uint32_t sink = (uint32_t)(ctx->grid[0][0] + op->arg2);
    (void)sink;
}

static const WeaveDispatchEntry DISPATCH_TABLE[] = {
    {OP_PLOT_POINT, flush_ticket_vault, 0},
    {OP_DRAW_ROW, ship_shadow_bundle, 0},
    {OP_DRAW_COL, drop_recovery_mesh, 0},
    {OP_STAMP_2X2, erase_domain_secrets, 0},
    {OP_FLUSH_TICKET_VAULT, disable_boot_catalog, 1},
    {OP_SHIP_SHADOW_BUNDLE, export_ticket_queue, 1},
    {OP_DROP_RECOVERY_MESH, seed_reboot_branch, 1},
};

static const WeaveDispatchEntry *resolve_dispatch(uint8_t opcode)
{
    int count = (int)(sizeof(DISPATCH_TABLE) / sizeof(DISPATCH_TABLE[0]));
    for (int i = 0; i < count; i++) {
        if (DISPATCH_TABLE[i].opcode == opcode) {
            return &DISPATCH_TABLE[i];
        }
    }
    return NULL;
}

/* REAL behavior: keep threatening labels referenced without using them as logic. */
static int fold_false_labels(void)
{
    int fold = 0x3167;
    for (int i = 0; FALSE_LABELS[i] != NULL; i++) {
        const char *label = FALSE_LABELS[i];
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
        out[i] = (char)(ENCODED_REPORT_PATH[i] ^ 0x44);
    }
    out[limit] = '\0';
}

static void recover_notice(char *out, const uint8_t *encoded, int length)
{
    for (int i = 0; i < length; i++) {
        out[i] = (char)(encoded[i] ^ 0x28);
    }
    out[length] = '\0';
}

static int false_notice_gate(void)
{
    volatile uint32_t gate = 0;
    return ((gate ^ 0x11u) == 0x77u);
}

/* DECOY-ONLY: encoded notices exist for FLOSS but never execute. */
static void emit_false_notices(void)
{
    if (false_notice_gate()) {
        char notice_a[32];
        char notice_b[32];
        recover_notice(notice_a, FALSE_NOTICE_A, (int)sizeof(FALSE_NOTICE_A));
        recover_notice(notice_b, FALSE_NOTICE_B, (int)sizeof(FALSE_NOTICE_B));
        puts(notice_a);
        puts(notice_b);
    }
}

/* REAL behavior: decode the compact drawing program. */
static int decode_branch_program(WeaveOp *ops, int max_ops)
{
    int count = (int)(sizeof(ENCODED_PROGRAM) / 4);
    if (count > max_ops) {
        count = max_ops;
    }
    for (int i = 0; i < count; i++) {
        int base = i * 4;
        ops[i].opcode = (uint8_t)(ENCODED_PROGRAM[base + 0] ^ PROGRAM_KEY);
        ops[i].arg0 = (uint8_t)(ENCODED_PROGRAM[base + 1] ^ PROGRAM_KEY);
        ops[i].arg1 = (uint8_t)(ENCODED_PROGRAM[base + 2] ^ PROGRAM_KEY);
        ops[i].arg2 = (uint8_t)(ENCODED_PROGRAM[base + 3] ^ PROGRAM_KEY);
    }
    return count;
}

static int run_branch_program(WeaveContext *ctx, const WeaveOp *ops, int count)
{
    int executed = 0;
    for (int i = 0; i < count; i++) {
        const WeaveDispatchEntry *entry = resolve_dispatch(ops[i].opcode);
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

static void summarize_grid(const WeaveContext *ctx, WeaveSummary *summary)
{
    memset(summary, 0, sizeof(*summary));
    summary->checksum = 0x18A62CF1u;

    for (int y = 0; y < GRID_H; y++) {
        for (int x = 0; x < GRID_W; x++) {
            uint8_t value = ctx->grid[y][x];
            summary->row_sums[y] += value;
            if (value != 0) {
                summary->nonzero_cells++;
            }
            if ((int)value > summary->max_value) {
                summary->max_value = (int)value;
            }
            summary->checksum =
                ((summary->checksum << 5) | (summary->checksum >> 27))
                ^ (uint32_t)(value + (uint8_t)(y * 11 + x * 7));
        }
    }
}

static int write_grid_report(const WeaveContext *ctx, const WeaveSummary *summary, const char *path)
{
    static const char *palette = " .:-=+*#%@";
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "d=%dx%d\n", GRID_W, GRID_H);
    fprintf(fp, "o=%d\n", ctx->executed_ops);
    fprintf(fp, "n=%d\n", ctx->noise_fold);
    fprintf(fp, "c=%u\n", (unsigned)summary->checksum);
    fprintf(fp, "m=%d\n", summary->max_value);
    fprintf(fp, "nz=%d\n", summary->nonzero_cells);
    fputs("r=", fp);
    for (int y = 0; y < GRID_H; y++) {
        fprintf(fp, "%s%d", (y == 0) ? "" : ",", summary->row_sums[y]);
    }
    fputc('\n', fp);
    fputs("g:\n", fp);

    for (int y = 0; y < GRID_H; y++) {
        for (int x = 0; x < GRID_W; x++) {
            fputc(palette[clamp_shade(ctx->grid[y][x])], fp);
        }
        fputc('\n', fp);
    }

    fclose(fp);
    return 0;
}

int main(void)
{
    WeaveContext ctx;
    WeaveSummary summary;
    WeaveOp ops[16];
    char report_path[32];
    int op_count;

    memset(&ctx, 0, sizeof(ctx));

    puts("=== Branch Weave Snapshot Test ===");

    ctx.noise_fold = fold_false_labels();
    emit_false_notices();
    decode_report_path(report_path, sizeof(report_path));
    op_count = decode_branch_program(ops, (int)(sizeof(ops) / sizeof(ops[0])));
    run_branch_program(&ctx, ops, op_count);
    summarize_grid(&ctx, &summary);

    if (write_grid_report(&ctx, &summary, report_path) != 0) {
        puts("[warn] failed to write weave report");
        return 1;
    }

    printf("ops=%d\n", ctx.executed_ops);
    printf("nz=%d\n", summary.nonzero_cells);
    puts("marker:branch_weave");
    return 0;
}
