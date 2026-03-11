#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int state;
    int input;
    int acc;
    int steps;
    uint32_t branch_mask;
    char trace[192];
    size_t trace_len;
} FlowContext;

static void trace_push(FlowContext *ctx, const char *token) {
    size_t n = strlen(token);
    if (ctx->trace_len + n + 2 >= sizeof(ctx->trace)) {
        return;
    }
    memcpy(ctx->trace + ctx->trace_len, token, n);
    ctx->trace_len += n;
    ctx->trace[ctx->trace_len++] = '|';
    ctx->trace[ctx->trace_len] = '\0';
}

static int opaque_predicate(const FlowContext *ctx) {
    uint32_t seed = (uint32_t)(ctx->input * 17 + ctx->steps * 31 + 7);
    uint32_t mixed = (seed ^ 0xA5A5A5A5u) + (ctx->branch_mask * 3u);
    return ((mixed >> 3) & 1u) == ((uint32_t)(ctx->input ^ ctx->steps) & 1u);
}

static int run_flattened(FlowContext *ctx) {
    while (ctx->state != 99 && ctx->steps < 40) {
        switch (ctx->state) {
            case 0:
                trace_push(ctx, "entry");
                ctx->acc = ctx->input & 0xF;
                ctx->branch_mask = (uint32_t)(ctx->input * 0x45D9F3Bu + 0x1337u);
                ctx->state = 1;
                break;
            case 1:
                trace_push(ctx, "dispatch");
                ctx->state = opaque_predicate(ctx) ? 2 : 3;
                break;
            case 2:
                trace_push(ctx, "path_a");
                ctx->acc = (ctx->acc * 3) + 5;
                ctx->state = (ctx->acc & 1) ? 4 : 5;
                break;
            case 3:
                trace_push(ctx, "path_b");
                ctx->acc = (ctx->acc ^ 0x2A) + 7;
                ctx->state = ((ctx->acc & 2) != 0) ? 4 : 5;
                break;
            case 4:
                trace_push(ctx, "loop");
                ctx->acc += (int)(ctx->branch_mask & 0x7u);
                ctx->branch_mask = (ctx->branch_mask >> 1) | (ctx->branch_mask << 31);
                ctx->state = (ctx->steps % 3 == 0) ? 5 : 1;
                break;
            case 5:
                trace_push(ctx, "final");
                ctx->state = 99;
                break;
            default:
                trace_push(ctx, "invalid");
                ctx->state = 99;
                break;
        }
        ctx->steps++;
    }
    return ctx->acc;
}

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
