/**
 * trick_config.h - Trickbot Simulation Configuration
 */
#pragma once
#include <windows.h>

// Trickbot module IDs (real Trickbot has 20+ modules)
enum TrickModule {
    MODULE_SYSTEMINFO = 100,
    MODULE_INJECTDLL = 200,
    MODULE_WEBINJECTS = 300,
    MODULE_NETWORKDLL = 400,
    MODULE_BCRYPT = 500
};

// C2 server list (encrypted in .bss section)
static const BYTE ENC_C2_SERVERS[] = {
    0x4A, 0x8F, 0x2E, 0x91, 0x55, 0xC3, 0x7A, 0x1E,  // server1
    0xB2, 0x6D, 0x88, 0xF4, 0x19, 0xE7, 0x3C, 0xA5   // server2
};

// Server-side injection URL patterns
[[maybe_unused]] static const char* INJECT_TARGETS[] = {
    "*.bankofamerica.com/*",
    "*.wellsfargo.com/*",
    "*.chase.com/*",
    "*.citi.com/*",
    NULL
};
