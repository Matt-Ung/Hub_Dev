int main(int argc, char **argv)
{
    (void)argv;

    puts("=== Hash Dispatch Test ===");

    /* Build command names as stack character arrays.
     * Each array is initialized with individual character literals
     * to avoid a single string constant in .rdata.
     * FLOSS should recover these through stack-string analysis. */

    char c_ping[]  = {'p', 'i', 'n', 'g'};
    char c_exec[]  = {'e', 'x', 'e', 'c'};
    char c_exfil[] = {'e', 'x', 'f', 'i', 'l'};
    char c_sleep[] = {'s', 'l', 'e', 'e', 'p'};

    int seq = (argc > 1) ? 5 : 1;

    build_and_dispatch(c_ping,  4, seq);
    build_and_dispatch(c_exec,  4, seq + 1);
    build_and_dispatch(c_exfil, 5, seq + 2);
    build_and_dispatch(c_sleep, 5, seq + 3);

    /* Try a command that won't resolve -- exercises the NULL path */
    char c_bad[] = {'n', 'o', 'p', 'e'};
    build_and_dispatch(c_bad, 4, 0);

    puts("marker:hash_dispatch");
    puts("marker:djb2_resolution");
    return 0;
}
