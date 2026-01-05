#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include "ntdll.h"
//function pointers
using f_LoadLibraryA = HINSTANCE (WINAPI*)(const char* lpLibFilename);

using f_GetprocAddress = UINT_PTR (WINAPI*)(HINSTANCE hmod, const char* lpProcName);


using f_DLL_ENTRY_POINT = BOOL (WINAPI*)(void* hDll, DWORD reason, void* pReserved);



struct MANUAL_MAPPING_DATA {

	f_LoadLibraryA pLoadLibraryA;
	f_GetprocAddress pGetProcAddress;
	HINSTANCE hmod;
	BYTE* pImageBase;

};

#pragma pack(push, 1)
struct SHELLCODE_DATA {
	MANUAL_MAPPING_DATA mappingData;
	BYTE shellcodeBytes[4096]; // Actual shellcode
};

typedef NTSTATUS(NTAPI* _KRtlAdjustPrivilege)(
	_In_ ULONG Privilege,
	_In_ BOOLEAN Enable,
	_In_ BOOLEAN Client,
	_Out_ PBOOLEAN WasEnabled
	);

// NT Function Prototypes
typedef NTSTATUS(NTAPI* PNtQueryVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_ PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);

typedef NTSTATUS(NTAPI* PNtReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	);
typedef NTSTATUS(NTAPI* PNtWriteVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);
typedef NTSYSAPI NTSTATUS(NTAPI* PNtOpenProcess)(
	IN PHANDLE,
	IN ACCESS_MASK,
	IN POBJECT_ATTRIBUTES,
	IN PCLIENT_ID
	);

typedef NTSTATUS(WINAPI* pNtCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPVOID lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD Unknown1,
	DWORD Unknown2,
	LPVOID Unknown3
	);


typedef NTSTATUS(NTAPI* _KRtlAdjustPrivilege)(
	_In_ ULONG Privilege,
	_In_ BOOLEAN Enable,
	_In_ BOOLEAN Client,
	_Out_ PBOOLEAN WasEnabled
	);



//NtCreateThreadEx alternative
// Method 1: RtlCreateUserThread (most compatible)
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
	HANDLE ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN CreateSuspended,
	ULONG StackZeroBits,
	SIZE_T StackReserve,
	SIZE_T StackCommit,
	PVOID StartAddress,
	PVOID Parameter,
	PHANDLE ThreadHandle,
	PCLIENT_ID ClientId
	);

bool ManualMap(HANDLE hProc, const char* szDll);

PVOID pGetLib(const WCHAR* pLibName, const char* pFunctionName);
void __stdcall shellcode(MANUAL_MAPPING_DATA* pData);