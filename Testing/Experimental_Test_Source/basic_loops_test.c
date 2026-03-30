/*
 * File:       basic_loops_test.c
 * Purpose:    Baseline control-flow sample with simple loops, arithmetic,
 *             and straightforward function calls.  No obfuscation, no
 *             indirection.  A reverse engineer should be able to fully
 *             reconstruct the logic from Ghidra decompilation alone.
 *
 * Difficulty: EASY
 *
 * Techniques:
 *   - for / while / do-while loops
 *   - nested function calls with return values
 *   - simple conditional branching (if / else)
 *   - integer arithmetic (no floating-point)
 *
 * Why it matters for testing:
 *   This sample establishes the decompilation-accuracy baseline.
 *   If the analysis pipeline cannot cleanly reconstruct this sample,
 *   something is fundamentally wrong with the Ghidra integration or
 *   the planner's work-item targeting.  It also provides a floor for
 *   the Quality Score (QS) metric: every experimental condition should
 *   score >= QS of this sample.
 *
 * Expected analysis signals:
 *   - Clean, readable decompiled output with loop boundaries intact
 *   - Correct identification of function call graph (main -> compute_sum
 *     -> classify_value -> accumulate)
 *   - No false claims about obfuscation or suspicious behavior
 *
 * Recommended MCP servers / tools:
 *   - ghidramcp   : decompilation, call graph, function listing
 *   - stringmcp   : should find the printf format strings and status msgs
 *   - CapaMCP     : should report minimal / benign capabilities only
 */

#include <stdint.h>
#include <stdio.h>

/*
 * compute_sum -- straightforward summation loop.
 * A reverse engineer should see a single basic block with an induction
 * variable and a running total.  At -O2, the compiler may reduce this
 * to a closed-form expression; at -O0 the loop will be literal.
 */
static int compute_sum(int n)
{
    int total = 0;
    for (int i = 1; i <= n; i++) {
        total += i;
    }
    return total;
}

/*
 * classify_value -- simple if/else ladder.
 * Produces a small integer category from a raw value.
 * The purpose is to test that the decompiler preserves the branch
 * structure rather than collapsing it into a ternary or cmov chain.
 */
static int classify_value(int v)
{
    if (v < 0)
        return -1;
    else if (v == 0)
        return 0;
    else if (v < 100)
        return 1;
    else if (v < 1000)
        return 2;
    else
        return 3;
}

/*
 * accumulate -- do-while with early exit.
 * The do-while ensures the body executes at least once, which tests
 * whether the decompiler correctly models the loop entry condition.
 */
static int accumulate(const int *arr, int len)
{
    if (len <= 0)
        return 0;

    int acc = 0;
    int idx = 0;
    do {
        acc += arr[idx];
        /* Early exit on sentinel value */
        if (arr[idx] == -1)
            break;
        idx++;
    } while (idx < len);

    return acc;
}

/*
 * main -- orchestrates the three helper functions.
 * Uses argc to inject a small amount of input-dependent behavior so the
 * binary is not entirely constant-folded.
 */
int main(int argc, char **argv)
{
    (void)argv;

    int base = (argc > 1) ? 20 : 10;

    /* Loop-based computation */
    int s = compute_sum(base);
    printf("sum(1..%d) = %d\n", base, s);

    /* Branching classification */
    int cls = classify_value(s);
    printf("class(%d) = %d\n", s, cls);

    /* Array accumulation with sentinel */
    int data[] = {5, 10, 15, -1, 99, 200};
    int acc = accumulate(data, (int)(sizeof(data) / sizeof(data[0])));
    printf("accumulate = %d\n", acc);

    /* Simple while loop that a reverse engineer should trivially spot */
    int countdown = base;
    while (countdown > 0) {
        countdown -= 3;
    }
    printf("countdown remainder = %d\n", countdown);

    puts("marker:basic_loops_baseline");
    return 0;
}
