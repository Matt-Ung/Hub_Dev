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
