#include "StubGenerator.hpp"
#include <fstream>
#include <iostream>

StubGenerator::StubGenerator(const std::vector<SyscallEntry>& list) : syscalls(list) {}

bool StubGenerator::GenerateAll() {
    return GenerateAsm() && GenerateHpp();
}

bool StubGenerator::GenerateAsm() {
    std::ofstream asmFile("syscalls.asm");
    if (!asmFile.is_open()) {
        std::cerr << "[-] ERRO: Erro ao criar syscalls.asm" << std::endl;
        return false;
    }

    asmFile << ".code\n\n";

    for (size_t i = 0; i < syscalls.size(); i++) {
        asmFile << syscalls[i].name << " proc\n";
        asmFile << "    mov r10, rcx\n";
        asmFile << "    mov eax, " << i << " ; SSN: 0x" << std::hex << i << std::dec << "\n";
        asmFile << "    syscall\n";
        asmFile << "    ret\n";
        asmFile << syscalls[i].name << " endp\n\n";
    }

    // Diretiva vital para o compilador MASM
    asmFile << "end\n";

    asmFile.close();
    return true;
}

bool StubGenerator::GenerateHpp() {
    std::ofstream hppFile("syscalls.hpp");
    if (!hppFile.is_open()) {
        std::cerr << "[-] ERRO: Erro ao criar syscalls.hpp" << std::endl;
        return false;
    }

    hppFile << "#pragma once\n";
    hppFile << "#include <windows.h>\n\n";
    hppFile << "extern \"C\" {\n";

    for (const auto& sc : syscalls) {
        hppFile << "    NTSTATUS " << sc.name << "(...);\n";
    }

    hppFile << "}\n";

    hppFile.close();
    return true;
}