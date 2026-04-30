#include <iostream>
#include "PEParser.hpp"
#include "StubGenerator.hpp"

int main() {
    std::cout << "=== NativaStub Gen - OOP Edition ===\n" << std::endl;

    std::string dllPath = "C:/Windows/System32/ntdll.dll";

    std::cout << "[*] Initializing parser..." << std::endl;
    PEParser parser(dllPath);

    if (!parser.Load()) {
        std::cerr << "[-] ERROR: Failed to load the DLL into memory." << std::endl;
        return 1;
    }

    std::cout << "[*] Extracting and mapping Syscalls..." << std::endl;
    if (!parser.ExtractSyscalls()) {
        std::cerr << "[-] ERROR: Failed to process the PE Header." << std::endl;
        return 1;
    }

    auto syscalls = parser.GetSyscalls();
    std::cout << "[+] SUCCESS: " << syscalls.size() << " Syscalls mapped and ordered." << std::endl;
    std::cout << "[i] DEBUG: The first 10 syscalls: " << std::endl;

    for (size_t i = 0; i < 10; ++i) {
        std::cout << "[" << i << "]  - " << syscalls[i].name << std::endl;
    }

    std::cout << "[*] Generating output files (.asm and .hpp)..." << std::endl;
    StubGenerator generator(syscalls);

    if (generator.GenerateAll()) {
        std::cout << "[+] ABSOLUTE SUCCESS! Files are ready for the compiler." << std::endl;
    }
    else {
        std::cerr << "[-] ERROR: An error occurred while writing the files." << std::endl;
        return 1;
    }

    return 0;
}