int main(void) {
    ApiSymbol symbols[] = {
        {"kernel32.dll", "Sleep", 0, NULL},
        {"kernel32.dll", "GetTickCount", 0, NULL},
        {"kernel32.dll", "GetCurrentProcessId", 0, NULL},
    };

    ApiRequest requests[] = {
        {{{0x60, 0x5F, 0x56, 0x56, 0x43}, 5, 0x33}, 0, NULL},
        {{{0x74, 0x56, 0x47, 0x67, 0x5A, 0x50, 0x58, 0x70, 0x5C, 0x46, 0x5D, 0x47}, 12, 0x33}, 0, NULL},
        {{{0x74, 0x56, 0x47, 0x70, 0x46, 0x41, 0x41, 0x56, 0x5D, 0x47, 0x63, 0x41, 0x5C, 0x50, 0x56, 0x40, 0x40, 0x7A, 0x57}, 19, 0x33}, 0, NULL},
    };

    char decoded_name[32];
    for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); ++i) {
        decode_name(&requests[i].encoded_name, decoded_name, sizeof(decoded_name));
        requests[i].target_hash = fnv1a_ci(decoded_name);
        requests[i].resolved_proc = resolve_api_by_hash(
            symbols,
            sizeof(symbols) / sizeof(symbols[0]),
            requests[i].target_hash
        );
        printf("resolved_name=%s hash=0x%08x ok=%d\n", decoded_name, requests[i].target_hash, requests[i].resolved_proc != NULL);
    }

    SleepFn pSleep = (SleepFn)requests[0].resolved_proc;
    GetTickCountFn pGetTickCount = (GetTickCountFn)requests[1].resolved_proc;
    GetCurrentProcessIdFn pGetCurrentProcessId = (GetCurrentProcessIdFn)requests[2].resolved_proc;

    if (!pSleep || !pGetTickCount || !pGetCurrentProcessId) {
        puts("resolver_failure");
        return 2;
    }

    pSleep(10);
    DWORD tick = pGetTickCount();
    DWORD pid = pGetCurrentProcessId();

    puts("marker:api_hash_lookup");
    puts("marker:runtime_api_resolution");
    printf("tick=%lu\n", (unsigned long)tick);
    printf("pid=%lu\n", (unsigned long)pid);
    return 0;
}
