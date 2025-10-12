use std::arch::asm;
use windows_sys::Win32::System::Threading::PEB;

/// Retrieves the current Process Environment Block (PEB) pointer for the calling process.
///
/// # Safety
/// This function uses inline assembly to read the `gs:[0x60]` segment register,
/// which stores a pointer to the `PEB` structure on 64-bit Windows.
///
/// # Returns
/// - `Some(PEB)` if the pointer is valid and dereferenced successfully.
/// - `None` if the retrieved PEB pointer is null.
///
/// # Platform
/// Works only on 64-bit Windows; will not compile elsewhere.
pub fn get_peb() -> Option<PEB> {
    let peb: *mut PEB;
    unsafe { asm!("mov {peb}, gs:[0x60]", peb = out(reg) peb) };
    if !peb.is_null() {
        Some(unsafe { *peb })
    } else {
        None
    }
}
