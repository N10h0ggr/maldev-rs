mod asm;
pub use asm::run_direct_syscall;
pub use asm::run_indirect_syscall;
use asm::{set_ssn_direct, set_ssn_indirect};

pub mod hells_gate;
use hells_gate::fetch_nt_syscall;

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
    match fetch_nt_syscall(hash) {
        Ok(syscall) => {
            set_ssn_direct(syscall.dw_ssn as usize);
        }
        Err(e) => {
            panic!("[prepare_syscall] Error: {}", e);
        }
    }
}

/// Prepares an indirect system call by fetching the NT syscall using the provided hash.
///
/// This version is used when the target syscall is hooked and the `syscall` instruction
/// must be executed indirectly (jumping to a valid `syscall` instruction elsewhere).
///
/// # Parameters
///
/// - `hash`: A 32-bit unsigned integer representing the hash of the NT syscall name.
///
/// # Panics
///
/// Panics if fetching the NT syscall fails or if no valid `p_syscall_inst_address` is found.
pub unsafe fn prepare_indirect_syscall(hash: u32) {
    match fetch_nt_syscall(hash) {
        Ok(syscall) => {
            set_ssn_indirect(
                syscall.dw_ssn as usize,
                syscall.p_syscall_inst_address as usize,
            );
        }
        Err(e) => {
            panic!("[prepare_syscall_indirect] Error: {}", e);
        }
    }
}

