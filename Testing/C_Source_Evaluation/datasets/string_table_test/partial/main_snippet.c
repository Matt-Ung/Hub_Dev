int main(int argc, char **argv)
{
    puts(BANNER);

    /* Print every table entry so the strings are referenced and not
     * dead-stripped by the linker. */
    for (int i = 0; i < MSG_COUNT; i++) {
        printf("  %s\n", lookup_message(i));
    }

    /* Out-of-bounds access to exercise the default path */
    printf("  %s\n", lookup_message(99));

    /* Status codes */
    print_status(0);
    print_status(1);
    print_status(2);

    /* Stack-based greeting */
    const char *user = (argc > 1) ? argv[1] : "analyst";
    build_greeting(user);

    puts("marker:string_table_baseline");
    return 0;
}
