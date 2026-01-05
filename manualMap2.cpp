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

	//setup manual mapping structure
	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetprocAddress>(GetProcAddress);

	//Copy data to beginning of pSrcData
	memcpy(pSrcData, &data, sizeof(data));

	//write PE header
	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) {
		printf("Failed to write PE header: 0x%X\n", GetLastError());
		delete[] pSrcData;
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	//get target sections
	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; i++, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
				pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				printf("Failed to write section %s to process memory 0x%X\n", pSectionHeader->Name, GetLastError());
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	delete[] pSrcData;

	//Calculate shellcode size
	DWORD shellcodeSize = reinterpret_cast<DWORD_PTR>(shellcode_end) - reinterpret_cast<DWORD_PTR>(shellcode);

	if (shellcodeSize == 0 || shellcodeSize > 0x10000) {
		printf("Warning: Shellcode size calculation failed (%d bytes), using default 0x1000\n", shellcodeSize);
		shellcodeSize = 0x1000;
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

	if (!WriteProcessMemory(hProc, pShellCode, shellcode, shellcodeSize, nullptr)) {
		printf("Failed to write shellcode: 0x%X\n", GetLastError());
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
		return false;
	}

	printf("Creating remote thread...\n");

	//create a remote thread
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode),
		pTargetBase, 0, nullptr);

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
	DWORD startTime = GetTickCount();
	DWORD timeout = 5000;
	HINSTANCE hChecked = NULL;

	while (!hChecked) {
		MANUAL_MAPPING_DATA data_checked = { 0 };

		if (!ReadProcessMemory(hProc, pTargetBase, &data_checked, sizeof(data_checked), nullptr)) {
			printf("Failed to read mapping data: 0x%X\n", GetLastError());
			VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
			return false;
		}

		hChecked = data_checked.hmod;
		if (hChecked) {
			printf("Injection completed successfully: ModuleBase %p\n", hChecked);
			break;
		}

		// Check for timeout
		if (GetTickCount() - startTime > timeout) {
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
			VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);
			return false;
		}
		Sleep(10);
	}

	// Clean up shellcode after successful injection
	VirtualFreeEx(hProc, pShellCode, 0, MEM_RELEASE);

	printf("Manual Mapping Successful! Module Base: %p\n", hChecked);
	return true;
}