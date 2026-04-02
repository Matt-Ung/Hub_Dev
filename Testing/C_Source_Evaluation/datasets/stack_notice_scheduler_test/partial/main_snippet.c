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
