#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
typedef unsigned long DWORD;
typedef void VOID;
typedef void (*FARPROC)(void);
#define WINAPI
#endif

typedef struct {
    const char *module_name;
    const char *api_name;
    uint32_t hash;
    FARPROC proc;
} ApiSymbol;

typedef struct {
    uint8_t data[24];
    size_t len;
    uint8_t key;
} EncodedName;

typedef struct {
    EncodedName encoded_name;
    uint32_t target_hash;
    FARPROC resolved_proc;
} ApiRequest;

typedef DWORD(WINAPI *GetTickCountFn)(void);
typedef DWORD(WINAPI *GetCurrentProcessIdFn)(void);
typedef VOID(WINAPI *SleepFn)(DWORD);

#if !defined(_WIN32)
static void stub_Sleep(DWORD ms) {
    volatile DWORD delay = ms;
    (void)delay;
}

static DWORD stub_GetTickCount(void) {
    return 13371337u;
}

static DWORD stub_GetCurrentProcessId(void) {
    return 4242u;
}

static FARPROC resolve_stub_proc(const char *api_name) {
    if (strcmp(api_name, "Sleep") == 0) {
        return (FARPROC)stub_Sleep;
    }
    if (strcmp(api_name, "GetTickCount") == 0) {
        return (FARPROC)stub_GetTickCount;
    }
    if (strcmp(api_name, "GetCurrentProcessId") == 0) {
        return (FARPROC)stub_GetCurrentProcessId;
    }
    return NULL;
}
#endif

static uint32_t fnv1a_ci(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; ++s) {
        h ^= (uint8_t)tolower((unsigned char)*s);
        h *= 16777619u;
    }
    return h;
}

static void decode_name(const EncodedName *enc, char *out, size_t out_sz) {
    if (out_sz == 0) {
        return;
    }
    size_t n = enc->len;
    if (n >= out_sz) {
        n = out_sz - 1;
    }
    for (size_t i = 0; i < n; ++i) {
        out[i] = (char)(enc->data[i] ^ enc->key);
    }
    out[n] = '\0';
}

static FARPROC resolve_api_by_hash(ApiSymbol *symbols, size_t symbol_count, uint32_t target_hash) {
    for (size_t i = 0; i < symbol_count; ++i) {
        if (symbols[i].hash == 0) {
            symbols[i].hash = fnv1a_ci(symbols[i].api_name);
        }
        if (symbols[i].hash != target_hash) {
            continue;
        }
        if (!symbols[i].proc) {
#if defined(_WIN32)
            HMODULE mod = GetModuleHandleA(symbols[i].module_name);
            if (!mod) {
                mod = LoadLibraryA(symbols[i].module_name);
            }
            if (mod) {
                symbols[i].proc = GetProcAddress(mod, symbols[i].api_name);
            }
#else
            symbols[i].proc = resolve_stub_proc(symbols[i].api_name);
#endif
        }
        return symbols[i].proc;
    }
    return NULL;
}

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
