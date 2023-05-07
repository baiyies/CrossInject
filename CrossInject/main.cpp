#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include "wow64ext.h"
#include "shellcode.h"


void TestInjectShellcodeX86() {
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    CreateProcess(
        _T("C:\\windows\\SysWOW64\\cmd.exe"),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    LPVOID lpBaseAddress = VirtualAllocEx(pi.hProcess, 0, sizeof(calcX86), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, lpBaseAddress, calcX86, sizeof(calcX86), NULL);

    CloseHandle(
        CreateRemoteThread(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0)
    );

    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

void TestInjectShellcodeX64() {
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    CreateProcess(
        _T("C:\\windows\\system32\\notepad.exe"),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    DWORD64 lpBaseAddress = VirtualAllocEx64(pi.hProcess, 0, sizeof(calcX64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory64(pi.hProcess, lpBaseAddress, calcX64, sizeof(calcX64), NULL);

    CloseHandle64(
        CreateRemoteThread64((DWORD64)pi.hProcess, (DWORD64)lpBaseAddress, (DWORD64)0)
    );

    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

}

int main() {
    if (sizeof(LPVOID) == 8) {
        printf("You compiled this EXE as x64, change it to x86 to test the inject function.\n");
        return 0;
    }

    printf("Inject shellcode into 32-bit cmd.exe.\n");
    TestInjectShellcodeX86();

    printf("Sleep for 3 seconds.\n");
    Sleep(3000);

    printf("Inject shellcode into 64-bit notepad.exe.\n");
    TestInjectShellcodeX64();
    getchar();

	return 0;
}