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
