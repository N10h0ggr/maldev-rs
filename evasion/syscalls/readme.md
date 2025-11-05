# Hell’s Gate

Hell’s Gate is a Rust implementation of direct Windows syscalls. It builds and executes raw syscall stubs dynamically, bypassing user-mode API wrappers in `ntdll.dll`. The crate provides minimal, explicit, and auditable primitives to perform native syscalls without relying on potentially hooked API layers.

## Introduction

Windows system calls (Nt*/Zw* functions) are normally invoked through wrappers in `ntdll.dll`. These wrappers set up registers and execute the `syscall` instruction to transition into kernel mode. Hell’s Gate reproduces this mechanism manually: it resolves syscall numbers from the export table, writes them into an assembly stub, and issues `syscall` directly. This avoids interception by user-mode hooks or detours that may exist in monitored environments.

## How the technique works

Hell’s Gate follows three stages:

1. **Resolve the syscall number**: The library walks ntdll.dll's export table and computes a CRC32 hash of each export name. Given a target hash, it locates the function, verifies its stub, and extracts the System Service Number (SSN). This CRC32-based lookup avoids embedding plaintext API names in code.

2. **Set the syscall selector**: Once resolved, `prepare_direct_syscall(hash)` writes the SSN into a global variable (`wSystemCall`) used by the inline assembly stub. When the export appears hooked, the resolver will also attempt to locate a nearby syscall instruction (`0x0F 0x05`) and expose its address; `prepare_indirect_syscall`(hash) writes both the SSN and that instruction address into `qSyscallInsAddress` for the indirect trampoline.

3. **Invoke the syscall**:
- `run_direct_syscall(...)` executes syscall inline in the assembly stub.
- `run_indirect_syscall(...)` jumps to a stored syscall instruction address and executes it.

The crate implements the original Hell’s Gate design. It does **not** include the extended logic of *Halo’s Gate* or *Tartarus' Gate*, which search for or reconstruct unhooked syscall stubs.

## Example usage

The following minimal example shows how the crate resolves and executes a syscall directly; here calling `NtAllocateVirtualMemory` using its CRC32 hash:

```rust
use syscalls::{prepare_direct_syscall, run_direct_syscall};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

fn main() {
    unsafe {
        let mut base: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut size: usize = 0x1000;
        let hash_nt_allocate = 0xe77460e0; // CRC32("NtAllocateVirtualMemory")

        // Resolve and set the syscall selector
        prepare_direct_syscall(hash_nt_allocate);

        // Invoke the syscall directly
        let status = run_direct_syscall(
            -1isize, &mut base, 0usize, &mut size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );

        println!("NtAllocateVirtualMemory returned: 0x{:x}", status);
    }
}
```

We can perform the same behaviour using indirect syscalls: the resolver may expose a valid syscall instruction address; use the indirect path to jump to it.

```rust
use syscalls::{prepare_syscall_indirect, run_syscall_indirect, compute_crc32_hash};
use windows::Win32::System::Memory::{PAGE_EXECUTE_READ};

fn main() {
    unsafe {
        let hash = compute_crc32_hash("NtProtectVirtualMemory".as_bytes());
        prepare_indirect_syscall(hash);

        let mut base: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut size: usize = 0x1000;
        let old_prot = 0u32;

        let status = run_indirect_syscall(
            -1isize, &mut base, &mut size, PAGE_EXECUTE_READ, &old_prot
        );
        println!("NtProtectVirtualMemory returned: 0x{:x}", status);
    }
}
```

The resolver uses a CRC32 hash of each export name (computed from ASCII bytes). For example:

```
CRC32("NtAllocateVirtualMemory") = 0xe77460e0
CRC32("NtProtectVirtualMemory")  = 0x5e84b28c
CRC32("NtCreateThreadEx")        = 0xe2083cd5
```

This enables lightweight, obfuscated lookup without embedding plaintext API names.

## Library structure

* `asm.rs` - defines the logic to set the ssn number and execute the syscall.
* `hells_gate.rs` - export parser and SSN extraction.
* `lib.rs` - public interface.
* `tests/` - functional examples that demonstrate resolving and executing real syscalls.

## References

* **Hell’s Gate: Syscalls Reborn** – Adam, O. (2020). [GitHub – am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
* **Windows Syscalls and the “syscall” instruction** – Microsoft Learn: [System Calls and Kernel Mode Transitions](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/overview-of-system-calls)
* **Halo’s Gate: Evolving Syscall Techniques** – Al-Khaser (2020). [GitHub – am0nsec/HalosGate](https://github.com/am0nsec/HalosGate)
* **Tartarus’ Gate: Advanced Evasion via Syscall Reuse** – MDSec (2021). [MDSec Blog](https://www.mdsec.co.uk/2021/04/tartarus-gate-syscall-evasion/)
* **Windows Internals, 7th Edition (Part 1)** – Russinovich et al., for in-depth syscall and ntdll behavior.
