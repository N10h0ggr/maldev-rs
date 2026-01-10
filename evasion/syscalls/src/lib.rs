#![no_std]
mod asm;
pub use asm::run_direct_syscall;
pub use asm::run_indirect_syscall;
use asm::{set_ssn_direct, set_ssn_indirect};

pub mod hells_gate;
mod crc32_hash;
pub use crc32_hash::compute_crc32_hash;

use hells_gate::fetch_nt_syscall;
use crate::hells_gate::SyscallStrategy;

/// Prepares a system call by fetching the NT syscall using the provided hash.
///
/// # Parameters
///
/// - `hash`: A 32-bit unsigned integer representing the hash value used to fetch the NT syscall.
///
/// # Panics
///
/// This function will panic if there is an error in fetching the NT syscall.
/// The error message will be printed with the hash value.
pub unsafe fn prepare_direct_syscall(hash: u32) {
    // For direct syscalls, we only really need the SSN.
    // We use the Ntdll strategy as it is faster and we don't need a specific external gadget.
    match fetch_nt_syscall(hash, SyscallStrategy::Ntdll) {
        Ok(syscall) => {
            set_ssn_direct(syscall.dw_ssn as usize);
        }
        Err(e) => {
            panic!("[prepare_direct_syscall] Error: {}", e);
        }
    }
}

/// Prepares an indirect system call by fetching the NT syscall using the provided hash.
///
/// This version is used when the target syscall is hooked and the `syscall` instruction
/// must be executed indirectly (jumping to a valid `syscall` instruction elsewhere).
///
/// # Feature Behavior
///
/// - If `feature = "win32u"` is enabled: This uses the `Win32u` strategy (executing the instruction inside win32u.dll).
/// - Default: This uses the `Ntdll` strategy (executing the instruction inside ntdll.dll).
///
/// # Parameters
///
/// - `hash`: A 32-bit unsigned integer representing the hash of the NT syscall name.
///
/// # Panics
///
/// Panics if fetching the NT syscall fails or if no valid `p_syscall_inst_address` is found.
pub unsafe fn prepare_indirect_syscall(hash: u32) {
    // Select strategy based on compilation features
    #[cfg(feature = "win32u")]
    let strategy = SyscallStrategy::Win32u;

    #[cfg(not(feature = "win32u"))]
    let strategy = SyscallStrategy::Ntdll;

    match fetch_nt_syscall(hash, strategy) {
        Ok(syscall) => {
            set_ssn_indirect(
                syscall.dw_ssn as usize,
                syscall.p_syscall_inst_address as usize,
            );
        }
        Err(e) => {
            panic!("[prepare_indirect_syscall] Error: {}", e);
        }
    }
}