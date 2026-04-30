#pragma once
#include <string>
#include <vector>
#include <windows.h>

struct SyscallEntry {
    std::string name;
    DWORD rva;
};

class PEParser {
private:
    std::string filePath;
    std::vector<uint8_t> fileBuffer;
    std::vector<SyscallEntry> syscallList;

    DWORD RvaToOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva);

public:
    PEParser(const std::string& path);
    bool Load();
    bool ExtractSyscalls();
    const std::vector<SyscallEntry>& GetSyscalls() const;
};