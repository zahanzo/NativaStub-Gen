#include "PEParser.hpp"
#include <fstream>
#include <algorithm>
#include <iostream>

PEParser::PEParser(const std::string& path) : filePath(path) {}

// Loads the specified DLL into memory and reads its contents into a buffer.
bool PEParser::Load() {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] ERROR: Failed to open file: " << filePath << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    fileBuffer.resize(size);
    if (!file.read(reinterpret_cast<char*>(fileBuffer.data()), size)) {
        std::cerr << "[-] ERROR: Failed to read file data." << std::endl;
        return false;
    }

    return true;
}

// Converts a Relative Virtual Address (RVA) to a file offset based on the PE headers.
DWORD PEParser::RvaToOffset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    WORD numSections = pNtHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        DWORD sectionStart = pSectionHeader[i].VirtualAddress;
        DWORD sectionSize = pSectionHeader[i].Misc.VirtualSize;

        if (rva >= sectionStart && rva < (sectionStart + sectionSize)) {
            return (rva - sectionStart) + pSectionHeader[i].PointerToRawData;
        }
    }
    return 0;
}

// Extracts syscall information from the loaded PE file by parsing the export directory and identifying functions that start with "Zw".
bool PEParser::ExtractSyscalls() {
    if (fileBuffer.empty()) return false;

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBuffer.data());
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(fileBuffer.data() + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return false;

    DWORD exportDirOffset = RvaToOffset(pNtHeaders, exportDirRVA);
    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(fileBuffer.data() + exportDirOffset);

    DWORD* pAddressOfFunctions = reinterpret_cast<DWORD*>(fileBuffer.data() + RvaToOffset(pNtHeaders, pExportDir->AddressOfFunctions));
    DWORD* pAddressOfNames = reinterpret_cast<DWORD*>(fileBuffer.data() + RvaToOffset(pNtHeaders, pExportDir->AddressOfNames));
    WORD* pAddressOfNameOrdinals = reinterpret_cast<WORD*>(fileBuffer.data() + RvaToOffset(pNtHeaders, pExportDir->AddressOfNameOrdinals));

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        DWORD nameOffset = RvaToOffset(pNtHeaders, pAddressOfNames[i]);
        const char* functionName = reinterpret_cast<const char*>(fileBuffer.data() + nameOffset);

        if (functionName[0] == 'Z' && functionName[1] == 'w') {
            WORD ordinal = pAddressOfNameOrdinals[i];
            DWORD functionRva = pAddressOfFunctions[ordinal];

            std::string cleanName = functionName;
            cleanName[0] = 'N';
            cleanName[1] = 't';

            syscallList.push_back({ cleanName, functionRva });
        }
    }

    std::sort(syscallList.begin(), syscallList.end(), [](const SyscallEntry& a, const SyscallEntry& b) {
        return a.rva < b.rva;
        });

    return !syscallList.empty();
}

const std::vector<SyscallEntry>& PEParser::GetSyscalls() const {
    return syscallList;
}