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
