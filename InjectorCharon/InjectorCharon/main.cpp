#include <string>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

bool GetProcessEntryByName(string name, PROCESSENTRY32* pe) {
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        cerr << "Tool helper cannot be created" << endl;
        return false;
    }

    if (!Process32First(snapshot, pe)) {
        cerr << "Tool helper cannot retrieve the first entry of process list" << endl;
        return false;
    }

    wstring wideName(name.begin(), name.end());

    do {
        if (wcscmp(pe->szExeFile, wideName.c_str()) == 0) { 
            snapshot ? CloseHandle(snapshot) : 0;
            return true;
        }
    } while (Process32Next(snapshot, pe));

    snapshot ? CloseHandle(snapshot) : 0;
    return false;
}

int main(int argc, const char* argv[]) {
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    wstring fullPath;

    if (argc != 3) {
        cerr << "[+] Usage: inject.exe <process name> <dll path>" << endl;
        return 1;
    }

    wchar_t buf[MAX_PATH] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, buf, MAX_PATH);
    GetFullPathName(buf, MAX_PATH, buf, nullptr);
    fullPath = wstring(buf, MAX_PATH);

    cout << "Waiting for " << argv[1] << "..." << endl;

    bool error = false;
    do {
        if (!GetProcessEntryByName(argv[1], &pe)) {
            error = true;
            Sleep(100);
        }
    } while (error);

    cout << argv[1] << " found" << endl;

    auto process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pe.th32ProcessID);
    if (!process) {
        cerr << "Process cannot be opened" << endl;
        return 1;
    }

    auto fpLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    auto mem = VirtualAllocEx(process, NULL, fullPath.length() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!mem) {
        cerr << "Library name cannot be allocated" << endl;
        CloseHandle(process);
        return 1;
    }

    if (!WriteProcessMemory(process, mem, fullPath.c_str(), fullPath.length() + 1, nullptr)) {
        cerr << "Library name cannot be written" << endl;
        CloseHandle(process);
        return 1;
    }

    if (!CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)fpLoadLibrary, mem, 0, nullptr)) {
        cerr << "Threads cannot be created" << endl;
        CloseHandle(process);
        return 1;
    }

    cout << "Injected" << endl;

    CloseHandle(process);
    return 0;
}

