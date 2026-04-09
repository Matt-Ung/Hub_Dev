/**
 * wannacry_config.h - WannaCry Simulation Configuration
 */
#pragma once
#include <windows.h>

// WannaCry uses specific mutex to prevent multiple executions [citation:8]
#define WANNACRY_MUTEX L"Global\\MsWinZonesCacheCounterMutexA"

// Service name used for persistence [citation:8]
#define WANNACRY_SERVICE L"mssecsvc2.0"
#define WANNACRY_DISPLAY L"Microsoft Security Center (2.0) Service"

// Bitcoin addresses (from real WannaCry) [citation:8]
[[maybe_unused]] static const char* BITCOIN_ADDRESSES[] = {
    "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94",
    "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",
    "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn"
};

// File extensions targeted for encryption [citation:8]
[[maybe_unused]] static const char* TARGET_EXTENSIONS[] = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".jpg", ".jpeg", ".png", ".bmp", ".gif",
    ".mp3", ".mp4", ".avi", ".mkv",
    ".sql", ".db", ".mdb", ".accdb",
    ".cpp", ".h", ".cs", ".java", ".py",
    NULL
};

// Excluded paths (not encrypted) [citation:8]
[[maybe_unused]] static const char* EXCLUDED_PATHS[] = {
    "Program Files",
    "Program Files (x86)",
    "Windows",
    "ProgramData",
    "Intel",
    "NVIDIA",
    "AMD",
    NULL
};

// Resource IDs for embedded components [citation:8]
#define RESOURCE_ENCRYPTOR   1001  // @WanaDecryptor@.exe
#define RESOURCE_PRIVESC     1002  // taskse.exe (EternalBlue privilege escalation)
#define RESOURCE_CLEANUP     1003  // taskdl.exe (shadow copy deletion)
#define RESOURCE_RESOURCES   1004  // Language resources (.res)
