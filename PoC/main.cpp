#include <iostream>
#include <windows.h>
#include "syscalls.hpp"

int main() {
    std::cout << "=== PoC: Direct Syscall Execution ===" << std::endl;
    std::cout << "[*] Preparando parametros para NtAllocateVirtualMemory..." << std::endl;

    // 1. Configurando os argumentos
    HANDLE hProcess = (HANDLE)-1; // -1 significa o próprio processo (GetCurrentProcess)
    PVOID baseAddress = nullptr;  // Deixa o SO escolher onde alocar a memória
    SIZE_T regionSize = 4096;     // Tamanho da alocação (1 página = 4KB)

    ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_EXECUTE_READWRITE; // RWX: O paraíso do shellcode

    std::cout << "[*] Efetuando a transicao para o Ring 0 (Kernel Mode)..." << std::endl;

    // 2. A chamada direta para a sua Syscall em Assembly
    NTSTATUS status = NtAllocateVirtualMemory(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        allocationType,
        protect
    );

    // 3. Verificando o resultado (NTSTATUS >= 0 significa sucesso)
    if (status >= 0) {
        std::cout << "[+] SUCESSO ABSOLUTO! Memoria alocada ignorando o User Mode." << std::endl;
        std::cout << "[+] Endereco base da alocacao: " << baseAddress << std::endl;
        std::cout << "[+] Permissoes: PAGE_EXECUTE_READWRITE" << std::endl;

        // Limpando a sujeira (Boa prática)
        SIZE_T freeSize = 0;
        NtFreeVirtualMemory(hProcess, &baseAddress, &freeSize, MEM_RELEASE);
        std::cout << "[*] Memoria liberada com sucesso." << std::endl;
    }
    else {
        std::cout << "[-] FALHA. O Kernel rejeitou o pedido. NTSTATUS: 0x" << std::hex << status << std::endl;
    }

    std::cout << "=== Fim do Teste ===" << std::endl;
    return 0;
}