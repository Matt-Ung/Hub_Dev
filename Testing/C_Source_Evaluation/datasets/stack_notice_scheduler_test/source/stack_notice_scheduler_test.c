/*
 * File:       stack_notice_scheduler_test.c
 * Purpose:    Medium deception-oriented sample where FLOSS-recoverable
 *             threatening labels and dormant decoded notices suggest unrelated
 *             credential or persistence behavior, but the executable actually
 *             decodes a fixed list of local schedule windows, sorts them, and
 *             writes a deterministic schedule digest.
 *
 * Difficulty: MEDIUM
 *
 * Techniques:
 *   - stack-built decoy strings intended for FLOSS recovery
 *   - dormant XOR-decoded warning notices on a never-taken branch
 *   - insertion-sort based schedule ordering and gap analysis
 *   - misleading function names around benign local scheduling logic
 *   - deterministic local text report generation
 *
 * Why it matters for testing:
 *   This sample is designed for the specific failure mode where an analysis
 *   over-trusts FLOSS output. Recovering the threatening labels is useful, but
 *   those labels are not the program's real behavior. A good report should
 *   identify the stack strings as decoys and describe the actual schedule
 *   decode, sort, and summary pipeline instead.
 *
 * Expected analysis signals:
 *   - FLOSS recovers stack-built strings such as wipe_wallet_cache,
 *     schedule_hidden_sync, and ship_ticket_material
 *   - The real data path decodes eight minute offsets with XOR key 0x27
 *   - collect_browser_cache is actually an insertion sort over local windows
 *   - ship_archive_manifest writes schedule_window_digest.txt locally
 *   - The dormant decoded notices are present but never executed
 *
 * Recommended MCP servers / tools:
 *   - flareflossmcp   : stack-string and dormant decoded-notice recovery
 *   - ghidramcp       : real scheduling logic, insertion sort, and report
 *                       generation path
 *   - stringmcp       : cleartext report strings and any residual literals
 *   - CapaMCP         : structural cues without over-attributing malicious
 *                       capabilities
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WINDOW_COUNT 8
#define WINDOW_BASE_MINUTE 480
#define WINDOW_KEY 0x27

typedef struct {
    int minutes[WINDOW_COUNT];
    int noise_fold;
} WindowContext;

typedef struct {
    int earliest;
    int latest;
    int largest_gap;
    uint32_t checksum;
} WindowSummary;

static const char *REPORT_PATH = "schedule_window_digest.txt";

static const uint8_t ENCODED_WINDOWS[] = {
    0x15, 0x22, 0x78, 0x33, 0x66, 0x04, 0x5F, 0x77,
};

static const uint8_t FALSE_NOTICE_A[] = {
    0x42, 0x5C, 0x40, 0x57, 0x46, 0x4C, 0x70, 0x44, 0x43, 0x4B,
    0x56, 0x57, 0x52, 0x70, 0x46, 0x59, 0x57, 0x4D, 0x4C,
};

static const uint8_t FALSE_NOTICE_B[] = {
    0x46, 0x5B, 0x4A, 0x55, 0x57, 0x46, 0x70, 0x41, 0x5C, 0x56,
    0x56, 0x4C, 0x5A, 0x5D, 0x70, 0x47, 0x58, 0x50, 0x5C, 0x4D,
};

/* REAL behavior: decode minute offsets and map them onto a local schedule. */
static int stage_recovery_queue(WindowContext *ctx)
{
    for (int i = 0; i < WINDOW_COUNT; i++) {
        ctx->minutes[i] = WINDOW_BASE_MINUTE + ((int)ENCODED_WINDOWS[i] ^ WINDOW_KEY);
    }
    return WINDOW_COUNT;
}

/* REAL behavior, deceptive name: insertion-sort the local schedule windows. */
static void collect_browser_cache(WindowContext *ctx)
{
    for (int i = 1; i < WINDOW_COUNT; i++) {
        int value = ctx->minutes[i];
        int j = i - 1;
        while (j >= 0 && ctx->minutes[j] > value) {
            ctx->minutes[j + 1] = ctx->minutes[j];
            j--;
        }
        ctx->minutes[j + 1] = value;
    }
}

/* REAL behavior: summarize the sorted windows and the largest gap. */
static void summarize_windows(const WindowContext *ctx, WindowSummary *summary)
{
    summary->earliest = ctx->minutes[0];
    summary->latest = ctx->minutes[WINDOW_COUNT - 1];
    summary->largest_gap = 0;
    summary->checksum = 0x61A4C32Fu;

    for (int i = 0; i < WINDOW_COUNT; i++) {
        uint32_t value = (uint32_t)ctx->minutes[i];
        summary->checksum = ((summary->checksum << 7) | (summary->checksum >> 25))
            ^ (value + (uint32_t)(i * 19 + 5));
        if (i > 0) {
            int gap = ctx->minutes[i] - ctx->minutes[i - 1];
            if (gap > summary->largest_gap) {
                summary->largest_gap = gap;
            }
        }
    }
}

/* REAL behavior, deceptive name: write one local schedule digest. */
static int ship_archive_manifest(const WindowContext *ctx, const WindowSummary *summary)
{
    FILE *fp = fopen(REPORT_PATH, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "count=%d\n", WINDOW_COUNT);
    fprintf(fp, "noise=%d\n", ctx->noise_fold);
    fprintf(fp, "earliest=%d\n", summary->earliest);
    fprintf(fp, "latest=%d\n", summary->latest);
    fprintf(fp, "largest_gap=%d\n", summary->largest_gap);
    fprintf(fp, "checksum=%u\n", (unsigned)summary->checksum);
    fputs("windows=", fp);
    for (int i = 0; i < WINDOW_COUNT; i++) {
        fprintf(fp, "%s%d", (i == 0) ? "" : ",", ctx->minutes[i]);
    }
    fputc('\n', fp);

    fclose(fp);
    return 0;
}

/* DECOY-ONLY: stack strings meant to be recoverable but not behavior-driving. */
static int seed_watchlist_labels(void)
{
    char a[] = {'w','i','p','e','_','w','a','l','l','e','t','_','c','a','c','h','e','\0'};
    char b[] = {'s','c','h','e','d','u','l','e','_','h','i','d','d','e','n','_','s','y','n','c','\0'};
    char c[] = {'s','h','i','p','_','t','i','c','k','e','t','_','m','a','t','e','r','i','a','l','\0'};
    char d[] = {'e','r','a','s','e','_','s','h','a','d','o','w','_','p','a','i','r','s','\0'};
    const char *items[] = {a, b, c, d, NULL};
    int fold = 0x1D7B;

    for (int i = 0; items[i] != NULL; i++) {
        fold = ((fold << 2) ^ (fold >> 3)) + (int)strlen(items[i]);
        fold ^= (unsigned char)items[i][0];
    }
    return fold & 0x7fffffff;
}

static void recover_notice(char *out, const uint8_t *encoded, int length)
{
    for (int i = 0; i < length; i++) {
        out[i] = (char)(encoded[i] ^ 0x35);
    }
    out[length] = '\0';
}

static int false_watchlist_gate(void)
{
    volatile uint32_t gate = 0;
    return ((gate ^ 0x24u) == 0x55u);
}

/* DECOY-ONLY: encoded notices remain available to FLOSS but never execute. */
static void emit_recovery_notices(void)
{
    if (false_watchlist_gate()) {
        char notice_a[32];
        char notice_b[32];
        recover_notice(notice_a, FALSE_NOTICE_A, (int)sizeof(FALSE_NOTICE_A));
        recover_notice(notice_b, FALSE_NOTICE_B, (int)sizeof(FALSE_NOTICE_B));
        puts(notice_a);
        puts(notice_b);
    }
}

int main(void)
{
    WindowContext ctx;
    WindowSummary summary;

    memset(&ctx, 0, sizeof(ctx));

    puts("=== Stack Notice Scheduler Test ===");

    ctx.noise_fold = seed_watchlist_labels();
    emit_recovery_notices();
    stage_recovery_queue(&ctx);
    collect_browser_cache(&ctx);
    summarize_windows(&ctx, &summary);

    if (ship_archive_manifest(&ctx, &summary) != 0) {
        puts("[warn] failed to write schedule digest");
        return 1;
    }

    printf("first=%d\n", summary.earliest);
    printf("last=%d\n", summary.latest);
    printf("largest_gap=%d\n", summary.largest_gap);
    puts("marker:stack_notice_scheduler");
    return 0;
}
