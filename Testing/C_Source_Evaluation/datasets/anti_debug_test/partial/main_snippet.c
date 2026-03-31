int main(void) {
    BOOL local_debugger = IsDebuggerPresent();
    BOOL remote_debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);

    int elapsed_us = timing_probe();

    const char *tool_markers[] = {
        "x64dbg.exe",
        "ollydbg.exe",
        "procmon.exe",
        "wireshark.exe",
    };

    printf("local_debugger=%d\n", (int)local_debugger);
    printf("remote_debugger=%d\n", (int)remote_debugger);
    printf("elapsed_us=%d\n", elapsed_us);

    for (int i = 0; i < 4; ++i) {
        puts(tool_markers[i]);
    }

    return 0;
}
