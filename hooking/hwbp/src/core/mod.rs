pub mod breakpoint;
pub mod call_args;
pub mod error;
pub mod vector_handler;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler,
};

use crate::core::breakpoint::remove_breakpoint;
use crate::core::error::BreakpointError;
use crate::core::vector_handler::vector_handler;
use crate::types::{DrRegister, HOOK_REGISTRY};

/// Initializes the global hardware breakpoint (HWBP) runtime environment.
///
/// This function ensures that the global vectored exception handler (VEH)
/// responsible for handling `EXCEPTION_SINGLE_STEP` events is registered.
/// It does **not** remove or alter any existing hardware breakpoints.
///
/// # Behavior
/// - Registers the global VEH handler if it has not yet been registered.
/// - Leaves all currently installed hardware breakpoints untouched.
/// - Can be called multiple times safely (idempotent).
///
/// # Errors
/// Returns [`BreakpointError::VehRegistrationFailed`] if the call to
/// [`AddVectoredExceptionHandler`] fails, along with the Windows error code.
///
/// # Example
/// ```ignore
/// initialize_hwbp_runtime()?;
/// ```
///
/// # Panics
/// Panics only if the global `HOOK_REGISTRY` mutex is poisoned.
pub fn initialize_hwbp_runtime() -> Result<(), BreakpointError> {
    let mut reg = HOOK_REGISTRY.lock().expect("HOOK_REGISTRY mutex poisoned");

    if reg.veh_handle.is_none() {
        let handle = unsafe { AddVectoredExceptionHandler(1, Some(vector_handler)) };
        if handle.is_null() {
            return Err(BreakpointError::VehRegistrationFailed(unsafe {
                GetLastError()
            }));
        }
        reg.veh_handle = Some(handle as usize);
    }

    Ok(())
}

/// Uninitializes the global hardware breakpoint (HWBP) runtime environment.
///
/// This function performs a complete cleanup of all hardware breakpoint
/// infrastructure:
/// - Removes all active breakpoints (best effort).
/// - Clears the global registry of hook metadata.
/// - Unregisters the vectored exception handler if it was installed.
///
/// # Behavior
/// - Each registered hardware breakpoint is removed individually.
/// - Failures to remove individual breakpoints are ignored to ensure full cleanup.
/// - Safe to call multiple times (idempotent).
///
/// # Safety
/// This function is safe to call at any time, though calling it while
/// threads are executing hooked functions may result in undefined behavior.
///
/// # Example
/// ```ignore
/// uninitialize_hwbp_runtime();
/// ```
pub fn uninitialize_hwbp_runtime() {
    // Copy keys so we don’t hold the lock while removing breakpoints.
    let keys: Vec<(usize, DrRegister)> = {
        let reg = HOOK_REGISTRY.lock().expect("HOOK_REGISTRY mutex poisoned");
        reg.active.keys().cloned().collect()
    };

    // Best-effort removal of all active hardware breakpoints.
    for (tid, drx) in keys {
        let _ = remove_breakpoint(tid, drx);
    }

    // Clear global registry and unregister the VEH.
    let mut reg = HOOK_REGISTRY.lock().expect("HOOK_REGISTRY mutex poisoned");
    reg.active.clear();

    if let Some(h) = reg.veh_handle.take() {
        unsafe {
            let _ = RemoveVectoredExceptionHandler(h as _);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use windows_sys::Win32::{
        Foundation::HWND,
        System::Diagnostics::Debug::CONTEXT,
        System::Threading::GetCurrentThreadId,
        UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
    };

    use crate::core::breakpoint::{install_breakpoint, remove_breakpoint};
    use crate::core::{initialize_hwbp_runtime, uninitialize_hwbp_runtime};
    use crate::types::DrRegister;

    /// Simple in-test helper: sets the Resume Flag (bit 16) in EFLAGS to continue after detour.
    fn continue_execution(ctx: &mut CONTEXT) {
        ctx.EFlags |= 1 << 16;
    }

    /// Minimal detour for MessageBoxA.  
    /// Prints old parameters, modifies them, and resumes execution.
    unsafe extern "system" fn message_box_a_detour(ctx: *mut CONTEXT) {
        if ctx.is_null() {
            return;
        }

        let ctx = unsafe { &mut *ctx };

        #[cfg(target_arch = "x86_64")]
        {
            let rcx = ctx.Rcx as *const i8; // HWND (unused)
            let rdx = ctx.Rdx as *const i8; // LPCSTR lpText
            let r8 = ctx.R8 as *const i8; // LPCSTR lpCaption
            let r9 = ctx.R9; // UINT uType

            println!("[i] MessageBoxA Detour hit!");
            if !rdx.is_null() {
                let text = unsafe { CStr::from_ptr(rdx).to_string_lossy() };
                println!("\tOld text: {}", text);
            }
            if !r8.is_null() {
                let caption = unsafe { CStr::from_ptr(r8).to_string_lossy() };
                println!("\tOld caption: {}", caption);
            }

            // Modify parameters
            ctx.Rdx = b"This Is The Hook\0".as_ptr() as u64;
            ctx.R8 = b"MessageBoxADetour\0".as_ptr() as u64;
            ctx.R9 = 0x00000040; // MB_ICONEXCLAMATION
        }

        continue_execution(ctx);
    }

    /// Tests installing and triggering a hardware breakpoint hook on MessageBoxA.
    ///
    /// This test emulates the same behavior as the C example in the blog:
    /// - Hook MessageBoxA via Dr0.
    /// - Invoke MessageBoxA to trigger the detour.
    /// - Remove the breakpoint and clean up.
    #[test]
    fn test_messageboxa_detour_hook() {
        unsafe {
            initialize_hwbp_runtime().expect("Failed to initialize HWBP runtime");

            println!("[i] [NOT HOOKED] Showing normal MessageBoxA...");
            MessageBoxA(
                0 as HWND,
                b"This is a normal MsgBoxA call (0)\0".as_ptr(),
                b"Normal\0".as_ptr(),
                MB_OK,
            );

            println!("[i] Installing HWBP hook on MessageBoxA...");
            let thread_id = GetCurrentThreadId() as usize;
            install_breakpoint(
                thread_id,
                MessageBoxA as usize,
                message_box_a_detour as usize,
                DrRegister::Dr0,
            )
            .expect("Failed to install hardware breakpoint");

            println!("[+] HWBP hook installed successfully.");

            // Trigger the detour
            println!("[i] [HOOKED] Triggering MessageBoxA...");
            MessageBoxA(
                0 as HWND,
                b"This won't execute\0".as_ptr(),
                b"Will it?\0".as_ptr(),
                MB_OK,
            );

            // Remove hook
            println!("[i] Removing hook...");
            remove_breakpoint(thread_id, DrRegister::Dr0)
                .expect("Failed to remove hardware breakpoint");
            println!("[+] Hook removed successfully.");

            // Normal again
            println!("[i] [NOT HOOKED] Showing normal MessageBoxA again...");
            MessageBoxA(
                0 as HWND,
                b"This is a normal MsgBoxA call (1)\0".as_ptr(),
                b"Normal\0".as_ptr(),
                MB_OK,
            );

            uninitialize_hwbp_runtime();
        }
    }
}
