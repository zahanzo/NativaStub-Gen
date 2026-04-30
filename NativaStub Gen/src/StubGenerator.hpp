#pragma once
#include <vector>
#include "PEParser.hpp"

class StubGenerator {
private:
    std::vector<SyscallEntry> syscalls;

    bool GenerateAsm();
    bool GenerateHpp();

public:
    StubGenerator(const std::vector<SyscallEntry>& list);
    bool GenerateAll();
};