/*
 * File:       maintenance_orchestrator_test.c
 * Purpose:    Deceptive-surface benchmark sample for the experimental binary
 *             corpus. The executable is intentionally covered in threatening
 *             names and strings, but its real behavior is benign: it decodes a
 *             compact operation script, renders a deterministic 12x8 in-memory
 *             snapshot, summarizes the resulting grid, and writes one local
 *             text report.
 *
 * Difficulty: HARD
 *
 * Intended true behavior:
 *   - Decode a fixed XOR-protected operation script.
 *   - Apply the decoded operations to a small in-memory 12x8 buffer.
 *   - Compute a checksum, row sums, and value summary over that buffer.
 *   - Write the rendered snapshot and summary to
 *     "maintenance_snapshot_report.txt" in the current working directory.
 *
 * Intended deceptive cues:
 *   - Function names such as install_boot_autorun, wipe_shadow_catalog,
 *     stage_domain_cache, queue_remote_archive, export_credential_sheet, and
 *     ship_archive_to_control suggest persistence, destruction, or exfiltration
 *     even though the code only manipulates a local buffer and writes a local
 *     report.
 *   - Cleartext strings such as wipe_restore_points,
 *     schedule_hidden_boot_task, and export_credential_cache are present to
 *     tempt shallow string-based analysis.
 *   - A dormant decoded-string path recovers additional alarming labels, but an
 *     opaque runtime gate keeps that branch non-executed.
 *   - The dispatcher includes decoy opcodes whose handlers look threatening but
 *     are never selected by the decoded operation script.
 *
 * What this sample is meant to test:
 *   - Whether the agent/judge over-trusts function names, variable names, and
 *     string surfaces instead of following executed control flow and data flow.
 *   - Whether tool-assisted analysis can separate data-only or dead decoys from
 *     the actual benign behavior.
 *   - Whether the final report avoids unsupported claims about destructive,
 *     persistent, or credential-focused behavior when the code does not
 *     implement those effects.
 *
 * Why it is safe:
 *   - No network activity, no persistence, no registry access, no privilege
 *     changes, no credential access, and no destructive actions.
 *   - The only side effect is writing one local text file in the current
 *     directory.
 *   - Threatening strings are inert labels or dead-branch decoys, not commands.
 *
 * Recommended MCP servers / tools:
 *   - ghidramcp       : true behavior vs. misleading names, dispatcher
 *                       structure, dead handlers, and local report path
 *   - stringmcp       : cleartext decoy labels and report strings
 *   - flareflossmcp   : dormant decoded-string decoys
 *   - CapaMCP         : bounded structural cues without over-claiming intent
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SNAPSHOT_WIDTH 12
#define SNAPSHOT_HEIGHT 8
#define SNAPSHOT_KEY 0x5A

#define OPCODE_INSTALL_BOOT_AUTORUN 0x11
#define OPCODE_WIPE_SHADOW_CATALOG 0x22
#define OPCODE_STAGE_DOMAIN_CACHE 0x33
#define OPCODE_QUEUE_REMOTE_ARCHIVE 0x44

#define OPCODE_DISABLE_RECOVERY_CHECKPOINTS 0x90
#define OPCODE_EXPORT_CREDENTIAL_CACHE 0x91
#define OPCODE_SCHEDULE_REBOOT_PERSISTENCE 0x92

typedef struct {
    uint8_t opcode;
    uint8_t arg0;
    uint8_t arg1;
    uint8_t arg2;
} SnapshotOp;

typedef struct {
    uint8_t cells[SNAPSHOT_HEIGHT][SNAPSHOT_WIDTH];
    int applied_ops;
    int label_noise_fold;
} SnapshotContext;

typedef struct {
    uint32_t checksum;
    int nonzero_cells;
    int max_value;
    int row_sums[SNAPSHOT_HEIGHT];
} SnapshotSummary;

typedef void (*SnapshotHandler)(SnapshotContext *ctx, const SnapshotOp *op);

typedef struct {
    uint8_t opcode;
    const char *label;
    SnapshotHandler handler;
    int is_decoy;
} HandlerEntry;

/* REAL behavior, benign output artifact. */
static const char *REPORT_PATH = "maintenance_snapshot_report.txt";

/* Strong surface-level decoys that are only folded into an inert checksum. */
static const char *NOISE_LABELS[] = {
    "wipe_restore_points",
    "schedule_hidden_boot_task",
    "export_credential_cache",
    "archive_domain_token",
    "disable_recovery_console",
    NULL
};

/*
 * REAL behavior: decoded operation script.
 * Each 4-byte record is XORed with SNAPSHOT_KEY and then dispatched.
 *
 * Decoded records:
 *   {0x11, 1,  0, 0}  -> fill all cells with shade 1
 *   {0x22, 1,  5, 0}  -> fill row 1 with shade 5
 *   {0x22, 6,  3, 0}  -> fill row 6 with shade 3
 *   {0x33, 8,  7, 0}  -> fill column 8 with shade 7
 *   {0x44, 2,  2, 9}  -> set point (2,2) to 9
 *   {0x44, 5,  4, 8}  -> set point (5,4) to 8
 *   {0x44, 10, 3, 6}  -> set point (10,3) to 6
 *   {0x44, 11, 7, 9}  -> set point (11,7) to 9
 */
static const uint8_t ENCODED_SCRIPT[] = {
    0x4B, 0x5B, 0x5A, 0x5A, 0x78, 0x5B, 0x5F, 0x5A,
    0x78, 0x5C, 0x59, 0x5A, 0x69, 0x52, 0x5D, 0x5A,
    0x1E, 0x58, 0x58, 0x53, 0x1E, 0x5F, 0x5E, 0x52,
    0x1E, 0x50, 0x59, 0x5C, 0x1E, 0x51, 0x5D, 0x53,
};

/*
 * DECOY-ONLY decoded strings.
 * FLOSS should be able to recover these, but the runtime never takes the
 * branch that decodes/prints them.
 */
static const uint8_t FALSE_NOTICE_A[] = {
    0x54, 0x4A, 0x53, 0x46, 0x7C, 0x51, 0x46, 0x50, 0x57, 0x4C,
    0x51, 0x46, 0x7C, 0x53, 0x4C, 0x4A, 0x4D, 0x57, 0x50,
};
static const uint8_t FALSE_NOTICE_B[] = {
    0x50, 0x40, 0x4B, 0x46, 0x47, 0x56, 0x4F, 0x46, 0x7C, 0x4B,
    0x4A, 0x47, 0x47, 0x46, 0x4D, 0x7C, 0x41, 0x4C, 0x4C, 0x57,
    0x7C, 0x57, 0x42, 0x50, 0x48,
};
static const uint8_t FALSE_NOTICE_C[] = {
    0x46, 0x5B, 0x53, 0x4C, 0x51, 0x57, 0x7C, 0x40, 0x51, 0x46,
    0x47, 0x46, 0x4D, 0x57, 0x4A, 0x42, 0x4F, 0x7C, 0x40, 0x42,
    0x40, 0x4B, 0x46,
};

static uint8_t clamp_cell_value(uint8_t value)
{
    return (uint8_t)(value % 10);
}

/*
 * REAL behavior, deceptive name: fill the entire snapshot with one base shade.
 */
static void install_boot_autorun(SnapshotContext *ctx, const SnapshotOp *op)
{
    uint8_t shade = clamp_cell_value(op->arg0);
    for (int y = 0; y < SNAPSHOT_HEIGHT; y++) {
        for (int x = 0; x < SNAPSHOT_WIDTH; x++) {
            ctx->cells[y][x] = shade;
        }
    }
}

/*
 * REAL behavior, deceptive name: fill one row of the local snapshot buffer.
 */
static void wipe_shadow_catalog(SnapshotContext *ctx, const SnapshotOp *op)
{
    int row = (int)(op->arg0 % SNAPSHOT_HEIGHT);
    uint8_t shade = clamp_cell_value(op->arg1);
    for (int x = 0; x < SNAPSHOT_WIDTH; x++) {
        ctx->cells[row][x] = shade;
    }
}

/*
 * REAL behavior, deceptive name: fill one column of the local snapshot buffer.
 */
static void stage_domain_cache(SnapshotContext *ctx, const SnapshotOp *op)
{
    int col = (int)(op->arg0 % SNAPSHOT_WIDTH);
    uint8_t shade = clamp_cell_value(op->arg1);
    for (int y = 0; y < SNAPSHOT_HEIGHT; y++) {
        ctx->cells[y][col] = shade;
    }
}

/*
 * REAL behavior, deceptive name: write one point into the snapshot buffer.
 */
static void queue_remote_archive(SnapshotContext *ctx, const SnapshotOp *op)
{
    int x = (int)(op->arg0 % SNAPSHOT_WIDTH);
    int y = (int)(op->arg1 % SNAPSHOT_HEIGHT);
    ctx->cells[y][x] = clamp_cell_value(op->arg2);
}

/*
 * DECOY-ONLY handler: threatening label, but never selected by the decoded
 * operation script.
 */
static void disable_recovery_checkpoints(SnapshotContext *ctx, const SnapshotOp *op)
{
    volatile uint32_t sink = (uint32_t)(ctx->applied_ops + op->arg0 + op->arg1 + op->arg2);
    (void)sink;
}

/*
 * DECOY-ONLY handler: threatening label, but never selected by the decoded
 * operation script.
 */
static void export_credential_cache(SnapshotContext *ctx, const SnapshotOp *op)
{
    volatile uint32_t sink = (uint32_t)(ctx->label_noise_fold + op->opcode);
    (void)sink;
}

/*
 * DECOY-ONLY handler: threatening label, but never selected by the decoded
 * operation script.
 */
static void schedule_reboot_persistence(SnapshotContext *ctx, const SnapshotOp *op)
{
    char scratch[32];
    int length = (int)sizeof(FALSE_NOTICE_A);
    if (length >= (int)sizeof(scratch)) {
        length = (int)sizeof(scratch) - 1;
    }
    for (int i = 0; i < length; i++) {
        scratch[i] = (char)(FALSE_NOTICE_A[i] ^ 0x23);
    }
    scratch[length] = '\0';
    if (ctx->applied_ops == -1) {
        printf("%s %u\n", scratch, (unsigned)op->opcode);
    }
}

static const HandlerEntry DISPATCH_TABLE[] = {
    {OPCODE_INSTALL_BOOT_AUTORUN, "install_boot_autorun", install_boot_autorun, 0},
    {OPCODE_WIPE_SHADOW_CATALOG, "wipe_shadow_catalog", wipe_shadow_catalog, 0},
    {OPCODE_STAGE_DOMAIN_CACHE, "stage_domain_cache", stage_domain_cache, 0},
    {OPCODE_QUEUE_REMOTE_ARCHIVE, "queue_remote_archive", queue_remote_archive, 0},
    {OPCODE_DISABLE_RECOVERY_CHECKPOINTS, "disable_recovery_checkpoints", disable_recovery_checkpoints, 1},
    {OPCODE_EXPORT_CREDENTIAL_CACHE, "export_credential_cache", export_credential_cache, 1},
    {OPCODE_SCHEDULE_REBOOT_PERSISTENCE, "schedule_reboot_persistence", schedule_reboot_persistence, 1},
};

/*
 * REAL behavior: the decoded script only uses live opcodes, but the dispatch
 * table also contains dormant decoy entries.
 */
static const HandlerEntry *resolve_dispatch_entry(uint8_t opcode)
{
    for (int i = 0; i < (int)(sizeof(DISPATCH_TABLE) / sizeof(DISPATCH_TABLE[0])); i++) {
        if (DISPATCH_TABLE[i].opcode == opcode) {
            return &DISPATCH_TABLE[i];
        }
    }
    return NULL;
}

/*
 * REAL behavior, deceptive name: inertly fold threatening labels into a small
 * checksum so the cleartext strings remain referenced without driving behavior.
 */
static int audit_quarantine_manifest(void)
{
    int fold = 0x1357;
    for (int i = 0; NOISE_LABELS[i] != NULL; i++) {
        const char *label = NOISE_LABELS[i];
        fold = ((fold << 3) ^ (fold >> 1)) + (int)strlen(label);
        fold ^= (unsigned char)label[0];
    }
    return fold & 0x7fffffff;
}

/*
 * DECOY-ONLY helper: decode a suspicious label for a dormant branch.
 */
static void recover_notice_block(char *out, const uint8_t *encoded, int len)
{
    for (int i = 0; i < len; i++) {
        out[i] = (char)(encoded[i] ^ 0x23);
    }
    out[len] = '\0';
}

/*
 * DECOY-ONLY gate: opaque-looking but always false at runtime. The volatile
 * keeps the branch materialized for analysis instead of being compiled away.
 */
static int query_recovery_slot(void)
{
    volatile uint32_t gate = 0;
    return ((gate ^ 0x41u) == 0x19u);
}

/*
 * DECOY-ONLY path: present for strings/FLOSS/Ghidra, but never executed in the
 * real runtime path.
 */
static void prime_recovery_notices(void)
{
    if (query_recovery_slot()) {
        char a[32];
        char b[32];
        char c[32];
        recover_notice_block(a, FALSE_NOTICE_A, (int)sizeof(FALSE_NOTICE_A));
        recover_notice_block(b, FALSE_NOTICE_B, (int)sizeof(FALSE_NOTICE_B));
        recover_notice_block(c, FALSE_NOTICE_C, (int)sizeof(FALSE_NOTICE_C));
        puts(a);
        puts(b);
        puts(c);
    }
}

/*
 * REAL behavior, deceptive name: decode the fixed operation script into
 * SnapshotOp records.
 */
static int unlock_quarantine_schedule(SnapshotOp *ops, int max_ops)
{
    int total_ops = (int)(sizeof(ENCODED_SCRIPT) / sizeof(ENCODED_SCRIPT[0])) / 4;
    if (total_ops > max_ops) {
        total_ops = max_ops;
    }
    for (int i = 0; i < total_ops; i++) {
        int offset = i * 4;
        ops[i].opcode = (uint8_t)(ENCODED_SCRIPT[offset + 0] ^ SNAPSHOT_KEY);
        ops[i].arg0 = (uint8_t)(ENCODED_SCRIPT[offset + 1] ^ SNAPSHOT_KEY);
        ops[i].arg1 = (uint8_t)(ENCODED_SCRIPT[offset + 2] ^ SNAPSHOT_KEY);
        ops[i].arg2 = (uint8_t)(ENCODED_SCRIPT[offset + 3] ^ SNAPSHOT_KEY);
    }
    return total_ops;
}

/*
 * REAL behavior: execute the decoded live script. Unknown opcodes are ignored.
 */
static int run_maintenance_cycle(SnapshotContext *ctx, const SnapshotOp *ops, int op_count)
{
    int executed = 0;
    for (int i = 0; i < op_count; i++) {
        const HandlerEntry *entry = resolve_dispatch_entry(ops[i].opcode);
        if (entry == NULL) {
            continue;
        }
        entry->handler(ctx, &ops[i]);
        if (!entry->is_decoy) {
            executed++;
        }
    }
    ctx->applied_ops = executed;
    return executed;
}

/*
 * REAL behavior, deceptive name: summarize the rendered snapshot.
 */
static void export_credential_sheet(const SnapshotContext *ctx, SnapshotSummary *summary)
{
    memset(summary, 0, sizeof(*summary));
    summary->checksum = 0x2468ACE1u;

    for (int y = 0; y < SNAPSHOT_HEIGHT; y++) {
        for (int x = 0; x < SNAPSHOT_WIDTH; x++) {
            uint8_t value = ctx->cells[y][x];
            summary->row_sums[y] += value;
            if (value != 0) {
                summary->nonzero_cells++;
            }
            if ((int)value > summary->max_value) {
                summary->max_value = (int)value;
            }
            summary->checksum =
                ((summary->checksum << 5) | (summary->checksum >> 27))
                ^ (uint32_t)(value + (uint8_t)(y * 7 + x * 13));
        }
    }
}

/*
 * REAL behavior, deceptive name: write a local text report describing the
 * rendered snapshot.
 */
static int ship_archive_to_control(const SnapshotContext *ctx, const SnapshotSummary *summary)
{
    static const char *palette = " .:-=+*#%@";
    FILE *fp = fopen(REPORT_PATH, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "maintenance_snapshot_report\n");
    fprintf(fp, "dimensions=%dx%d\n", SNAPSHOT_WIDTH, SNAPSHOT_HEIGHT);
    fprintf(fp, "applied_ops=%d\n", ctx->applied_ops);
    fprintf(fp, "label_noise_fold=%d\n", ctx->label_noise_fold);
    fprintf(fp, "checksum=%u\n", (unsigned)summary->checksum);
    fprintf(fp, "nonzero_cells=%d\n", summary->nonzero_cells);
    fprintf(fp, "max_value=%d\n", summary->max_value);
    fputs("row_sums=", fp);
    for (int y = 0; y < SNAPSHOT_HEIGHT; y++) {
        fprintf(fp, "%s%d", (y == 0) ? "" : ",", summary->row_sums[y]);
    }
    fputc('\n', fp);
    fputs("grid:\n", fp);

    for (int y = 0; y < SNAPSHOT_HEIGHT; y++) {
        for (int x = 0; x < SNAPSHOT_WIDTH; x++) {
            uint8_t value = clamp_cell_value(ctx->cells[y][x]);
            fputc(palette[value], fp);
        }
        fputc('\n', fp);
    }

    fclose(fp);
    return 0;
}

int main(void)
{
    SnapshotContext ctx;
    SnapshotSummary summary;
    SnapshotOp ops[16];
    int op_count;

    memset(&ctx, 0, sizeof(ctx));

    puts("=== Maintenance Orchestrator Test ===");

    /* REAL behavior: keep the threatening labels present but inert. */
    ctx.label_noise_fold = audit_quarantine_manifest();

    /* DECOY-ONLY path: never taken, but useful for recovered decoded strings. */
    prime_recovery_notices();

    /* REAL behavior: decode and execute the local snapshot script. */
    op_count = unlock_quarantine_schedule(ops, (int)(sizeof(ops) / sizeof(ops[0])));
    run_maintenance_cycle(&ctx, ops, op_count);
    export_credential_sheet(&ctx, &summary);

    if (ship_archive_to_control(&ctx, &summary) < 0) {
        puts("[warn] failed to write maintenance snapshot report");
        return 1;
    }

    printf("decoded_ops=%d\n", op_count);
    printf("applied_ops=%d\n", ctx.applied_ops);
    printf("report=%s\n", REPORT_PATH);
    printf("checksum=%u\n", (unsigned)summary.checksum);
    puts("marker:maintenance_snapshot");
    return 0;
}
