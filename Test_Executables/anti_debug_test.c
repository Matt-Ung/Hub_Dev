#include <windows.h>
#include <stdio.h>

static int timing_probe(void) {
    LARGE_INTEGER a, b, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&a);

    for (volatile int i = 0; i < 5000000; ++i) {
    }

    QueryPerformanceCounter(&b);
    if (freq.QuadPart == 0) {
        return -1;
    }

    long long micros = ((b.QuadPart - a.QuadPart) * 1000000LL) / freq.QuadPart;
    return (int)micros;
}

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
