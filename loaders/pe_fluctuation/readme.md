# PE Fluctuation

This project implements a **Module Fluctuation** engine in Rust, designed to evade memory scanners (such as Moneta or PE-Sieve) by keeping a manually mapped PE encrypted while it is not being executed.

Instead of leaving executable (RX) memory regions visible in the process at all times, this library uses a "trap-and-decrypt" mechanism. The code remains encrypted as Read-Only (RO) data and is only decrypted to an executable state on-demand when accessed.

## How it works

The fluctuation engine relies on two core Windows mechanisms: **Vectored Exception Handling (VEH)** and **Timer Queues**.

1. **Initial Encryption**: Once the PE is mapped, the engine generates a random 16-byte RC4 key and encrypts the executable sections. Memory protection is set to `PAGE_READONLY`.
2. **The Trap (VEH)**: When the program attempts to execute code in that region, the CPU triggers an **Access Violation (0xC0000005)** because the memory is not executable.
3. **On-Demand Decryption**: The Vectored Exception Handler intercepts this specific exception. It decrypts the memory region using the session-specific RC4 key and transitions the protection to `PAGE_EXECUTE_READ` (RX).
4. **Automatic Re-encryption**: A Windows Timer Queue is scheduled. After a period of inactivity (default 5 seconds), a worker thread automatically re-encrypts the memory and sets it back to `PAGE_READONLY`, hiding it from scanners again.

## Features

* **Dynamic Key Randomization**: Uses `BCryptGenRandom` to ensure every execution session uses a unique RC4 key, preventing static signature detection of the encrypted payload.
* **Stealthy Crypto**: Utilizes the undocumented `SystemFunction032` (Advapi32) for RC4 operations, avoiding large external dependencies and keeping the binary footprint minimal.
* **Modern Rust Safety**: Fully compliant with Rust 2024 memory safety standards, using `addr_of!` and `addr_of_mut!` macros to safely manage shared global state across exception and timer threads.
## Building

This project requires a Windows environment and the MSVC Rust toolchain.

```powershell
# Build for 64-bit Windows
cargo build --release

# Build for 32-bit Windows
cargo build --release --target i686-pc-windows-msvc
```


## Usage

This project it can be used as a standalone compiled binary for quick testing or as a library dependency in larger projects.

### As a Binary (CLI)

When compiled, you can execute any PE (EXE or DLL) directly from your terminal. Arguments following the `--param` flag are patched into the mapped image's PEB so they can be retrieved via standard calls like `GetCommandLineW`.

```powershell
# Execute an EXE with arguments
./pe_fluctuation.exe --pe mimikatz.exe --param coffee exit

# Execute a specific export from a DLL
./pe_fluctuation.exe --pe SharpSploit.dll --export NameOfFunction

```

### As a Library

The `lib.rs` file exposes high-level functions that automate the mapping, fluctuation, and execution flow.

```rust
use pe_fluctuation::{run, run_with_export};

// Execute an EXE/DLL entry point
run("payloads/beacon.exe", vec!["arg1".into()])?;

// Execute a specific DLL export
run_with_export("payloads/plugin.dll", vec![], "PluginEntryPoint")?;

```


### Configuration

You can adjust the "visibility window" by modifying the `EXEC_WAIT_MS` constant in `pe_fluctuation.rs`. A shorter time increases security but may cause more frequent performance overhead due to repeated decryption/encryption cycles.

```rust
/// The duration code remains decrypted before being hidden again.
const EXEC_WAIT_MS: u32 = 1000; 

```

## Evasion Profile

By using this technique, the loaded PE spends >90% of its lifecycle in a non-executable state. This specifically targets:

* **Memory Scanners**: Scanners looking for "Unbacked RX Memory" (memory marked as executable but not associated with a file on disk).
* **Static Signatures**: Since the code is encrypted with a random key, signature-based detection of known tools (like Mimikatz or Cobalt Strike) will fail while the module is at rest.