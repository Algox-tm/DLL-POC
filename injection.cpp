#pragma section(".text")
#pragma comment(linker, "/SECTION:.text,ERW")
#include "injection.h"

//macros
#define RELOC_FLAG32(RelInfo)((RelInfo>>0x0C)==IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo)((RelInfo>>0x0C)==IMAGE_REL_BASED_DIR64)

__declspec(noinline) void shellcode_end();

PVOID pGetLib(const WCHAR* pLibName, const char* pFunctionName) {


	if (pLibName && pFunctionName) {
		HINSTANCE hModule = GetModuleHandle("pModule");
		
		if (hModule) {
			return GetProcAddress(hModule, pFunctionName);
		}
	}
	else {
		printf("function name cannot be null \n");
		ExitProcess(0);
	}
}

bool ManualMap(HANDLE hProc, const char* szDll) {

	BYTE* pSrcData = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptionalHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	//check if file exist
	if (GetFileAttributesA(szDll) == INVALID_FILE_ATTRIBUTES) {
		printf("Error : File Not Found\n");
		return false;
	}

	//open file in binary mode
	std::ifstream File(szDll, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		printf("ManualMap failed to read binary file %x\n", File.rdstate());
		return false;
	}

	auto FileSize = File.tellg();

	if (FileSize < 0x1000) {
		printf("file size is invalid\n");
		File.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];

	if (!pSrcData) {
		printf("Memory Allocation Failed\n");
		File.close();
		return false;
	}

	//set the file pointer to the beginning
	File.seekg(0, std::ios::beg);

	//read file into memory
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
		printf("invalid file\n");
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptionalHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		printf("Error 64bit Executable is required\n");
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
		printf("Error 32bit Executable is required\n");
		delete[] pSrcData;
		return false;
	}
#endif

	// ========================================================================
	// CRITICAL FIX: Get kernel32.dll base address in TARGET process
	// ========================================================================

	printf("Resolving kernel32.dll in target process...\n");

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32) {
		printf("Failed to get kernel32.dll handle\n");
		delete[] pSrcData;
		return false;
	}

	// Get the base address of kernel32 in target process
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProc));

	BYTE* pTargetKernel32 = nullptr;

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		if (Module32First(hSnapshot, &me32)) {
			do {
				if (!_stricmp(me32.szModule, "kernel32.dll") || !_stricmp(me32.szModule, "KERNEL32.DLL")) {
					pTargetKernel32 = me32.modBaseAddr;
					printf("Found kernel32.dll in target at: %p\n", pTargetKernel32);
					break;
				}
			} while (Module32Next(hSnapshot, &me32));
		}
		CloseHandle(hSnapshot);
	}

	if (!pTargetKernel32) {
		printf("Failed to find kernel32.dll in target process!\n");
		delete[] pSrcData;
		return false;
	}

	//system class 

	HMODULE hNtdll = GetModuleHandle("ntdll.dll");

	if (!hNtdll) {
		printf("failed to get [ntdll.dll] Error: \n\n ", GetLastError());
		return false;
	}

	pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	pRtlCreateUserThread pCreateThd = (pRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");

	PNtReadVirtualMemory NtReadProcessMemory = (PNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");

	PNtWriteVirtualMemory NtWriteProcessMemory = (PNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	// Calculate function addresses in target process
	BYTE* pLocalKernel32 = reinterpret_cast<BYTE*>(hKernel32);
	BYTE* pLocalLoadLibraryA = reinterpret_cast<BYTE*>(LoadLibraryA);
	BYTE* pLocalGetProcAddress = reinterpret_cast<BYTE*>(GetProcAddress);

	// Calculate offsets from kernel32 base
	DWORD_PTR offsetLoadLibraryA = pLocalLoadLibraryA - pLocalKernel32;
	DWORD_PTR offsetGetProcAddress = pLocalGetProcAddress - pLocalKernel32;

	// Calculate target addresses
	f_LoadLibraryA pTargetLoadLibraryA = reinterpret_cast<f_LoadLibraryA>(pTargetKernel32 + offsetLoadLibraryA);
	f_GetprocAddress pTargetGetProcAddress = reinterpret_cast<f_GetprocAddress>(pTargetKernel32 + offsetGetProcAddress);

	printf("Local kernel32: %p\n", pLocalKernel32);
	printf("Target kernel32: %p\n", pTargetKernel32);
	printf("Local LoadLibraryA: %p (offset: 0x%llX)\n", pLocalLoadLibraryA, offsetLoadLibraryA);
	printf("Target LoadLibraryA: %p\n", pTargetLoadLibraryA);
	printf("Local GetProcAddress: %p (offset: 0x%llX)\n", pLocalGetProcAddress, offsetGetProcAddress);
	printf("Target GetProcAddress: %p\n", pTargetGetProcAddress);

	// ========================================================================

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptionalHeader->ImageBase),
		pOldOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!pTargetBase) {
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptionalHeader->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if (!pTargetBase) {
			printf("Target Memory Allocation Failed with error : 0x%X\n", GetLastError());
			delete[] pSrcData;
			return false;
		}
	}

	printf("Allocated memory at: %p\n", pTargetBase);


	//write PE header
	SIZE_T bytesreturned = 0;

	if (!NT_SUCCESS(NtWriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, &bytesreturned))) {
		printf("Failed to write PE header: 0x%X\n", GetLastError());
		delete[] pSrcData;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	//get target sections
	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; i++, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!NT_SUCCESS(NtWriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
				pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, &bytesreturned))) {
				printf("Failed to write section %s to process memory 0x%X\n", pSectionHeader->Name, GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	delete[] pSrcData;



	//setup manual mapping structure - USE TARGET PROCESS ADDRESSES
	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = pTargetLoadLibraryA;
	data.pGetProcAddress = pTargetGetProcAddress;
	data.pImageBase = pTargetBase;
	data.hmod = nullptr;
	//Copy data to beginning of pSrcData
	//memcpy(pSrcData, &data, sizeof(data));

	void* pMappingData = VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA),MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!pMappingData) {
		printf("Failed to allocate mapping data: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	printf("Mapping data allocated at: %p\n", pMappingData);


	// Write the mapping data to target process
	if (!NT_SUCCESS(NtWriteProcessMemory(hProc, pMappingData, &data, sizeof(data), &bytesreturned))) {
		printf("Failed to write mapping data: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
		return false;
	}


	//Calculate shellcode size
	DWORD shellcodeSize = reinterpret_cast<DWORD_PTR>(shellcode_end) - reinterpret_cast<DWORD_PTR>(shellcode);

	if (shellcodeSize == 0 || shellcodeSize > 0x10000) {
		printf("Warning: Shellcode size calculation failed (%d bytes), using default 0x2000\n", shellcodeSize);
		shellcodeSize = 0x2000;
	}
	else {
		printf("Shellcode size: %d bytes\n", shellcodeSize);
		shellcodeSize = (shellcodeSize + 0xFFF) & ~0xFFF; // Round up to page size
	}

	//Allocate shellcode
	void* pShellCode = VirtualAllocEx(hProc, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pShellCode) {
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		printf("Error failed to create payload memory 0x%X\n", GetLastError());
		return false;
	}

	printf("Shellcode allocated at: %p\n", pShellCode);

	if (!NT_SUCCESS(NtWriteProcessMemory(hProc, pShellCode, shellcode, shellcodeSize, &bytesreturned))) {
		printf("Failed to write shellcode: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
		return false;
	}
	else { printf("shellcode written btyes: %i", bytesreturned); }

	printf("Creating remote thread...\n");
	

	HANDLE hThread = NULL;

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL)


		if (pCreateThd) {
			printf("[+] Trying RtlCreateUserThread...\n");
			CLIENT_ID cid = { 0 };
			NTSTATUS status = pCreateThd(
				hProc,
				NULL,           // SecurityDescriptor
				FALSE,          // CreateSuspended (BOOLEAN is fine here)
				0,              // StackZeroBits
				0,              // StackReserve
				0,              // StackCommit
				pShellCode,   // StartAddress
				pMappingData,      // Parameter
				&hThread,       // ThreadHandle
				&cid            // ClientId
			);

			if (!(NT_SUCCESS(status) && hThread)) {
				
					// Decode common error codes
					switch (status) {
					case 0xC0000005:
						printf("    -> STATUS_ACCESS_VIOLATION\n");
						break;
					case 0xC000000D:
						printf("    -> STATUS_INVALID_PARAMETER\n");
						break;
					case 0xC0000022:
						printf("    -> STATUS_ACCESS_DENIED\n");
						break;
					case 0xC0000008:
						printf("    -> STATUS_INVALID_HANDLE\n");
						break;
					default:
						printf("    -> Unknown NTSTATUS error\n");
						break;
					}
				


				return NULL;
			}
			else {

				printf("[+] RtlCreateUserThread succeeded (TID: %d)\n", (DWORD)(ULONG_PTR)cid.UniqueThread);
			}
		
		}
		else {

			printf("using\n NtCreateThreadEx\n\n ");

			if (NtCreateThreadEx) {
				printf("using NtCreateThreadEx\n\n");



				if (!NT_SUCCESS(NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &objAttr, hProc, pShellCode, pTargetBase, 0, 0, 0, 0, NULL))) {

					printf("NtCreateThreadEx failed with status: 0x%X\n", GetLastError());
					VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
					VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
					return false;
				}


			}
		}

	if (!hThread) {
		printf("Failed to create remote thread in the target process : Error 0x%x\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
		return false;
	}


	

	printf("Remote thread created, waiting for completion...\n");

	//Wait for thread to finish or timeout
	DWORD waitResult = WaitForSingleObject(hThread, 10000);

	if (waitResult == WAIT_TIMEOUT) {
		printf("Warning: Thread execution timeout\n");
	}
	else if (waitResult == WAIT_FAILED) {
		printf("Wait failed: 0x%X\n", GetLastError());
	}

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	printf("Thread exit code: %d\n", exitCode);

	CloseHandle(hThread);

	//Wait for completion signal
	DWORD_PTR startTime = GetTickCount64();
	DWORD_PTR timeout = 5000;
	HINSTANCE hChecked = NULL;

	while (!hChecked) {
		MANUAL_MAPPING_DATA data_checked = { 0 };

		if (!NT_SUCCESS(NtReadProcessMemory(hProc, pMappingData, &data_checked, sizeof(data_checked), &bytesreturned))) {
			printf("Failed to read mapping data: 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
			return false;
		}

		hChecked = data_checked.hmod;
		if (hChecked) {
			printf("Injection completed successfully: ModuleBase %p\n", hChecked);
			break;
		}

		// Check for timeout
		if (GetTickCount64() - startTime > timeout) {
			printf("Error: Injection Timed Out. The shellcode likely crashed or failed.\n");

			DWORD processExitCode = 0;
			if (GetExitCodeProcess(hProc, &processExitCode)) {
				if (processExitCode != STILL_ACTIVE) {
					printf("The target process crashed! Exit code: %d\n", processExitCode);
				}
				else {
					printf("Target process is still running\n");
				}
			}

			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
			return false;
		}
		Sleep(10);
	}

	// Clean up shellcode after successful injection
	VirtualFreeEx(hProc, pMappingData, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
	printf("Manual Mapping Successful! Module Base: %p\n", hChecked);
	return true;
}
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#pragma runtime_checks("", off)
#pragma optimize("", off)


void __stdcall shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		return;
	}

	BYTE* pBase = pData->pImageBase;
	
	auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
	if (pDosHeader->e_magic != 0x5A4D) {
		return;
	}

	auto* pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);

	auto* pOpt = &pNtHeader->OptionalHeader; //&reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;


	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;

	// Process relocations
	if (LocationDelta) {
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			return; // No relocations available
		}

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (pRelocData->VirtualAddress) {
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i < AmountOfEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}

			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	// Fix imports
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescriptor->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			if (!hDll) {
				++pImportDescriptor;
				continue;
			}

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);

			if (!pThunkRef) {
				pThunkRef = pFuncRef;
			}

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}

			++pImportDescriptor;
		}
	}

	// TLS Callbacks
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTls->AddressOfCallBacks);

		for (; pCallBack && *pCallBack; ++pCallBack) {
			(*pCallBack)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	// Call DllMain
	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	// Signal completion
	pData->hmod = reinterpret_cast<HINSTANCE>(pBase);
}

// Shellcode end marker - DO NOT REMOVE
//DWORD __stdcall shellcode_end() { return 0; }
__declspec(noinline) void shellcode_end() { return; }

