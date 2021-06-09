#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#define DEBUG_MODE 1
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define ThreadQuerySetWin32StartAddress 9

typedef NTSTATUS(WINAPI* NTQUERYINFOMATIONTHREAD)(HANDLE, LONG, PVOID, ULONG, PULONG);

struct args {
	HANDLE hThread;
};

DWORD_PTR WINAPI GetThreadStartAddress(HANDLE hThread)
{
	NTSTATUS ntStatus;
	DWORD_PTR dwThreadStartAddr;
	NTQUERYINFOMATIONTHREAD NtQueryInformationThread;
	NtQueryInformationThread = (NTQUERYINFOMATIONTHREAD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
	ntStatus = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwThreadStartAddr, sizeof(DWORD_PTR), NULL);
	if (ntStatus != STATUS_SUCCESS) {
		return 0;
	}
	return dwThreadStartAddr;
}

DWORD_PTR * GetModuleInfo(DWORD pid, const wchar_t *target) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	DWORD_PTR moduleinfo[2];
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!_wcsicmp(modEntry.szModule, target)) {
					moduleinfo[0] = (DWORD_PTR)modEntry.modBaseAddr;
					moduleinfo[1] = modEntry.modBaseSize;
					return moduleinfo;
				}
				//std::wcout << "Name: " << modEntry.szModule << "\t Addr: " << modEntry.modBaseAddr << "\n";
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	return 0;
}

BOOL isTarget(HANDLE tHandle, DWORD pid, const wchar_t *target) {
	DWORD_PTR ThreadStartAddr = GetThreadStartAddress(tHandle);
	if (!ThreadStartAddr) {
		std::cout << "Get start address of thread failed!\n";
		ExitProcess(1);
	}
	DWORD_PTR* retmoduleinfo = GetModuleInfo(pid, target);
	DWORD_PTR ModuleStart = retmoduleinfo[0];
	DWORD_PTR ModuleEnd = retmoduleinfo[0] + retmoduleinfo[1];
	// Only shows debug mode on (1)
	if (DEBUG_MODE) {
		printf("THREAD START ADDR: %012X\n", ThreadStartAddr);
		printf("MODULE START ADDR: %012X\n", retmoduleinfo[0]);
		printf("MODULE END ADDR: %012X\n", retmoduleinfo[0] + retmoduleinfo[1]);
	}
	if (ThreadStartAddr >= ModuleStart && ThreadStartAddr <= ModuleEnd) { // Is thread start address between ModuleStart and ModuleEnd?
		return TRUE;
	}
	else {
		return FALSE;
	}
}

void CrackAnyRun(LPVOID inargs) {
	args *funcargs = (args*)inargs;
	HANDLE tHandle = funcargs->hThread;
	while (1){
		SuspendThread(tHandle);
		std::cout << "Thread suspended\n";
		Sleep(24000);
		ResumeThread(tHandle);
		std::cout << "Thread resumed\n";
		Sleep(1000);
	}
}

int main()
{
	HANDLE tHandle, pHandle = 0, hToken;
	DWORD tid, pid = 0;
	LUID luid = { 0 };
	BOOL privRet = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		std::cout << "OpenProcessToken success!\n";
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			privRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		}
	}
	else {
		std::cout << "OpenProcessToken failed! Error: " << GetLastError() << "\n";
		ExitProcess(1);
	}
	if (!privRet) {
		std::cout << "Adjust privilege failed!\n";
		ExitProcess(1);
	}

	// Find PID by name
	PROCESSENTRY32 pe; 
	HANDLE hps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hps != INVALID_HANDLE_VALUE) {
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hps, &pe)) {
			do {
				if (!_wcsicmp(pe.szExeFile, L"srvpost.exe")) {
					pid = pe.th32ProcessID;
				}
			} while (Process32Next(hps, &pe));
		}
	}
	else {
		std::cout << "Process snapshot cannot taken!\n";
		ExitProcess(1);
	}
	if (pid == 0) {
		std::cout << "Process not found!\n";
		ExitProcess(1);
	}
	// Retrieve threads in process
	HANDLE hth = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hth != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(hth, &te)) {
			do {
				if (te.th32OwnerProcessID == pid) {
					tHandle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
					if (tHandle != INVALID_HANDLE_VALUE) {
						if (isTarget(tHandle, pid, L"winsanr.dll")) {
							SuspendThread(tHandle);
							// Only shows debug mode on (1)
							if (DEBUG_MODE) {
								std::cout << "THREADID: " << te.th32ThreadID << "\n";
							}
						}
						// Crack any.run :D 
						if (isTarget(tHandle, pid, L"sechost.dll")) {
							HANDLE dupHandle;
							if (DuplicateHandle(GetCurrentProcess(), tHandle, GetCurrentProcess(), &dupHandle, THREAD_SUSPEND_RESUME, FALSE, 0)) {
								args thargs;
								thargs.hThread = dupHandle;
								CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CrackAnyRun, &thargs, 0, NULL);
								CloseHandle(tHandle);
								continue;
							}
						}
						else {
							continue;
						}
						CloseHandle(tHandle);
					}
				}
			} while (Thread32Next(hth, &te));
		}
	}
	else {
		std::cout << "Thread snapshot cannot taken!\n";
		ExitProcess(1);
	}
	while (1); // for second thread
}
