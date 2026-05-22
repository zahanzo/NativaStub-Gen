# NativaStub-Gen 🥷

> **"Bypassing user-land hooks through automated Direct Syscalls."**

**NativaStub-Gen** is an automated tool developed in **C++20** that statically parses the Windows `ntdll.dll` binary to dynamically extract System Service Numbers (SSNs) and generate ready-to-use Direct Syscall stubs. 

### 🎓 Motivation
The goal was to demonstrate a deep understanding of Windows internals, PE (Portable Executable) file parsing, and evasion techniques used in Red Teaming to bypass Endpoint Detection and Response (EDR) user-mode hooks.

---

## 🧠 How It Works (Step-by-Step)

The core objective of this tool is to avoid calling standard Windows APIs that might be monitored or hooked by security solutions. It achieves this by reading the clean, unhooked `ntdll.dll` from the disk and extracting the necessary data to perform system calls manually.

1.  **Raw File Reading:** The program locates and reads the original `C:\Windows\System32\ntdll.dll` directly from the hard drive, bypassing the version loaded into the process memory (which is typically where EDRs place their `jmp` hooks).
2.  **PE Structure Parsing:** It parses the raw byte array, mapping the **DOS Header** and navigating through the **NT Headers** to locate the **Data Directories**.
3.  **Export Directory Enumeration:** The parser navigates to the **Export Directory** to map all exported functions, specifically looking for those starting with `Nt` or `Zw` (the native APIs).
4.  **SSN Extraction:** Once a target Native API is found, the tool analyzes the opcodes in the `.text` section of that specific function to dynamically extract the **System Service Number (SSN)** (e.g., identifying the `mov eax, [SSN]` instruction pattern).
5.  **Stub Generation:** Finally, it generates a clean C++ header and Assembly stub containing the extracted SSNs. These stubs use the `syscall` instruction directly, allowing your testing application to communicate with the Windows Kernel (Ring 0) while completely evading user-land API hooks.

---

## 🚀 Features

*   **Written in Modern C++20:** Utilizing modern memory management and syntax.
*   **Zero-Dependency Parsing:** Custom PE parser implementation without relying on external libraries or suspicious Windows APIs.
*   **Dynamic Extraction:** Immune to SSN changes across different Windows builds, as it extracts the numbers directly from the host's current `ntdll.dll`.
*   **Ready-to-Use Output:** Automatically formats the extracted data into usable code structures.

---

## 📂 Project Structure

```text
.
├── NativaStub-Gen.sln       # Visual Studio Solution
├── NativaStub-Gen/          # Core Generator
│   ├── src/
│   │   ├── main.cpp
│   │   ├── PEParser.cpp     # PE structure parsing logic
│   │   ├── PEParser.h
│   │   ├── StubGenerator.cpp # Logic to format and output the stubs
│   │   └── StubGenerator.h
├── PoC/                     # Proof of Concept Example
│   └── main.cpp             # Example of using the generated Direct Syscalls
```

---

## 🛠️ How to Build and Use

### Phase 1: Building the Generator
1.  Clone the repository and open `NativaStub-Gen.sln` in **Visual Studio**.
2.  Ensure the build target is set to **Release / x64**.
3.  Build the solution and run the generated executable. 
4.  The tool will parse your system's `ntdll.dll` and generate the necessary syscall files (typically a `.hpp` header and an `.asm` assembly file).

### Phase 2: Compiling the PoC (Important MASM Setup)
Since the PoC is provided as a source example, you need to manually integrate the generated stubs to test the evasion:
1.  Create a new C++ Console Project in Visual Studio for your PoC and add the provided `PoC/main.cpp` file.
2.  Copy the `.hpp` and `.asm` files generated in Phase 1 into your PoC project directory and add them to the Visual Studio solution (**Right-Click on Project -> Add -> Existing Item**).
3.  **Enable MASM:** Right-click your PoC Project in the Solution Explorer, go to **Build Dependencies -> Build Customizations...**, and check the **masm** box.
4.  **Configure the ASM file:** Right-click the generated `.asm` file in the Solution Explorer, select **Properties**. Under **Configuration Properties -> General -> Item Type**, change it to **Microsoft Macro Assembler**.
5.  Include the `.hpp` header in your `main.cpp`, ensure your PoC is set to **x64**, and compile.
6.  Run the PoC to verify the Direct Syscalls bypassing user-land hooks successfully!

---

## ⚠️ Disclaimer

This project was created for **educational purposes and security research only**. It is designed to help security professionals and students understand Windows internals and user-land hooking mechanics. The author is not responsible for any direct or indirect damage, or illegal usage of the information and tools provided in this repository.

---

**Developed by 0xRobert de Souza Lages.**  
*Exploring the depths of x64 architecture, binary analysis, and bare-metal execution.*
