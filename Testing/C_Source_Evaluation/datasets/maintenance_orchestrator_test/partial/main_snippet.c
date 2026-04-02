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
