int main(void) {
    const char *url = "https://updates.example.net/checkin";
    const char *reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    char stack_cmd[64] = {0};

    build_stack_string(stack_cmd, sizeof(stack_cmd));

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) {
        puts("no kernel32");
        return 1;
    }

    VirtualAllocFn pVirtualAlloc = (VirtualAllocFn)GetProcAddress(k32, "VirtualAlloc");
    VirtualFreeFn pVirtualFree = (VirtualFreeFn)GetProcAddress(k32, "VirtualFree");
    if (!pVirtualAlloc || !pVirtualFree) {
        puts("missing proc");
        return 2;
    }

    LPVOID mem = pVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        memset(mem, 0x41, 16);
        pVirtualFree(mem, 0, MEM_RELEASE);
    }

    HANDLE h = CreateMutexA(NULL, FALSE, "Global\\UpdaterMutex");
    if (h) {
        CloseHandle(h);
    }

    puts(url);
    puts(reg);
    puts(stack_cmd);
    puts("GetProcAddress -> VirtualAlloc/VirtualFree");

    return 0;
}
