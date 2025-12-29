# Rust Reflective DLL Injection

This project implements a fully functional Reflective DLL Injection (RDI) suite written in Rust. It includes a custom `no_std` DLL designed to map itself into memory and a companion injector that facilitates the initial delivery into a target process.

The goal is to load a library into a process without using the standard Windows `LoadLibrary` API, thereby avoiding disk-based detection and standard OS monitoring hooks.

## How the technique works

The process follows a two-stage approach: a "loader" (the injector) handles the initial memory allocation, and the "payload" (the reflective DLL) performs the complex manual mapping.

### Stage 1: Remote Allocation and Execution

The injector reads the reflective DLL from disk and identifies the file offset of a specific exported function (in this case, `my_reflective_fun`). It then locates the target process (e.g., `notepad.exe`), allocates memory within it, and writes the entire DLL buffer into that remote space. Finally, it triggers the execution of the exported function via `CreateRemoteThread`.

### Stage 2: Reflective Bootstrap

Once execution begins inside the target process, `my_reflective_fun` takes over. Because the DLL was simply written to memory as a raw blob, it cannot initially use any system APIs or resolve its own imports. The loader must:

* **Locate Kernel32**: It walks the Process Environment Block (PEB) to find the base address of `kernel32.dll` using CRC32 hashing for name comparison.
* **Resolve Bootstrap APIs**: It manually parses the Export Address Table (EAT) of Kernel32 to find `VirtualAlloc`, `LoadLibraryA`, and `GetProcAddress`.
* **Manual Mapping**: It allocates a final, properly aligned memory region, copies its headers and sections, applies base relocations (rebasing), and populates its own Import Address Table (IAT).

### Stage 3: Payload Activation

After completing the mapping and setting appropriate memory permissions (e.g., marking `.text` as executable), the loader executes TLS callbacks and then jumps to the DLL's entry point (`DllMain`).

## Library architecture

The project is split into two main crates:

### Injector (`/injector`)

* **`main.rs`**: The CLI entry point. It handles process lookups, file I/O, and the low-level `WriteProcessMemory`/`CreateRemoteThread` calls.

### Reflective DLL (`/reflective_dll`)

* **`lib.rs`**: Hosts the `my_reflective_fun` export and the `no_std` environment configuration, including a custom global allocator that uses the Windows Heap API.
* **`mapper.rs`**: Contains the core manual mapping logic: `fix_reloc`, `fix_imports`, and `fix_memory_permissions`.
* **`parser.rs`**: Implements a robust `PeImage` parser that abstracts over 32-bit and 64-bit PE/COFF structures.
* **`utils.rs`**: Provides the "stealth" building blocks, such as the PEB walker for module resolution and the EAT parser for function address retrieval.
* **`executor.rs`**: Handles the execution of Thread Local Storage (TLS) callbacks before the main payload runs.
* **`arch.rs`**: Defines architecture-specific constants for relocation types and thunk data structures.

## Usage example

To use the project, first build the reflective DLL and then point the injector at a running process.

```bash
# Build the DLL (output will be in target/x86_64-pc-windows-msvc/release/)
cargo build --release -p reflective_dll

# Run the injector to target notepad.exe
cargo run -p injector -- -rfldll ./target/release/reflective_dll.dll -p notepad.exe

```

Upon success, the injected DLL will execute its `DllMain`, which by default triggers a "Reflective Loading Successful!" message box within the context of the target process.

## Characteristics of the library

* **No-Std & Custom Allocator**: The reflective DLL does not depend on the Rust standard library (`std`), ensuring it doesn't attempt to call uninitialized OS handlers during the bootstrap phase.
* **API Hashing**: Instead of storing sensitive string names (like "GetProcAddress") in the `.rdata` section, the library uses CRC32 hashes to find functions, making static analysis more difficult.
* **Position Independence**: The loader is designed to work regardless of where the injector places the initial buffer in memory.
* **TLS & Exception Support**: The mapper includes support for executing TLS callbacks and registering structured exception handlers in the target process.

## References

* **Stephen Fewer**, *Reflective DLL Injection* (2008). The original research that defined this technique.
* **Microsoft Learn**, *Peering Inside the PE: A Tour of the Win32 Portable Executable File Format*. Essential documentation for the `parser.rs` implementation.
* **NSACYBER**, *Hardware-assisted Control-flow Integrity* - discusses why manual mapping is often used to bypass modern EDR hooks that monitor `LoadLibrary`.