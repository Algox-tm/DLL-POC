#include <Windows.h>
#include <stdio.h>

HINSTANCE g_hInstance = NULL;

// Export function for testing
extern "C" __declspec(dllexport) void TestFunction() {
    MessageBoxA(NULL, "DLL Injected Successfully!", "Test", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstance);
        g_hInstance = hInstance;

        // Simple test - create a file to prove injection worked
        {
            HANDLE hFile = CreateFileA(
                "C:\\injection_test.txt",
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hFile != INVALID_HANDLE_VALUE) {
                const char* msg = "DLL injection successful!\n";
                DWORD written;
                WriteFile(hFile, msg, strlen(msg), &written, NULL);
                CloseHandle(hFile);
            }
        }
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}