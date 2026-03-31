#include <stdint.h>
#include <stdio.h>

static int helper(int x) {
    // Multiple exits + loop + arithmetic
    if (x < 0) return -1;
    if (x == 0) return 0;

    int acc = 0;
    for (int i = 0; i < x; i++) {
        if ((i & 1) == 0) acc += i;
        else acc -= i;

        if (acc > 50) break;      // early break -> interesting edge
    }

    return acc;
}

static int classify(int v) {
    // Switch will typically produce a jump table at -O2
    switch (v & 7) {
        case 0: return 10;
        case 1: return 11;
        case 2: return 12;
        case 3: return 13;
        case 4: return 14;
        case 5: return 15;
        case 6: return 16;
        default: return 17;
    }
}

int main(int argc, char **argv) {
    int x = (argc > 1) ? (int)argv[1][0] : 42;  // simple input dependency

    int h = helper(x);
    if (h < 0) {
        puts("neg");
        return 2;               // early return edge
    }

    int c = classify(h);
    if (c >= 15) {
        puts("high");
    } else if (c >= 12) {
        puts("mid");
    } else {
        puts("low");
    }

    // Ternary produces a nice diamond
    int out = (c & 1) ? (c + 3) : (c - 3);
    printf("%d\n", out);
    return 0;
}
