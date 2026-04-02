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
