int main(int argc, char **argv) {
    int seed = (argc > 1 && argv[1][0] != '\0') ? (unsigned char)argv[1][0] : 0x41;
    FlowContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.input = seed;

    int result = run_flattened(&ctx);

    puts("marker:flatten_dispatcher");
    puts("marker:opaque_predicate");
    printf("state_steps=%d\n", ctx.steps);
    printf("flattened_result=%d\n", result);
    printf("dispatch_trace=%s\n", ctx.trace);
    return 0;
}
