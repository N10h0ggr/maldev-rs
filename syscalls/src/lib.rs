pub mod asm;
pub use asm::run_direct_syscall;
use asm::set_ssn;
pub mod hells_gate;
use hells_gate::{fetch_nt_syscall};

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
pub unsafe fn prepare_syscall(hash: u32) {
    match fetch_nt_syscall(hash) {
        Ok(syscall) => {
            set_ssn(syscall.dw_ssn as usize);
        },
        Err(e) => {
            panic!("[prepare_syscall] Error: {}", e);
        }
    }
}