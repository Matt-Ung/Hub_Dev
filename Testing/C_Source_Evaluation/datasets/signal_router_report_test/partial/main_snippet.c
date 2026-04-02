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
