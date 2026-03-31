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
