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
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    use crate::core::breakpoint::{install_breakpoint, remove_breakpoint};
    use crate::core::{initialize_hwbp_runtime, uninitialize_hwbp_runtime};
    use crate::types::DrRegister;

    static DETOUR_HIT: AtomicBool = AtomicBool::new(false);

    /// Our test target function to hook.
    extern "system" fn test_target(a: i32, b: i32) -> i32 {
        println!("[i] Inside original test_target({}, {})", a, b);
        a + b
    }

    /// Detour that modifies the parameters (registers) and flags that it ran.
    unsafe extern "system" fn test_detour(ctx: *mut CONTEXT) {
        if ctx.is_null() {
            return;
        }
        let ctx = &mut *ctx;
        #[cfg(target_arch = "x86_64")]
        {
            // x64 calling convention: first 4 args = RCX, RDX, R8, R9
            ctx.Rcx = 10;
            ctx.Rdx = 20;
        }

        DETOUR_HIT.store(true, Ordering::SeqCst);

        // Set Resume Flag
        ctx.EFlags |= 1 << 16;
    }

    #[test]
    fn test_single_thread_hw_breakpoint() {
        unsafe {
            initialize_hwbp_runtime().expect("Failed to initialize HWBP runtime");

            let tid = GetCurrentThreadId() as usize;

            println!("[i] Installing HWBP hook on test_target...");
            install_breakpoint(
                tid,
                test_target as usize,
                test_detour as usize,
                DrRegister::Dr0,
            )
            .expect("Failed to install HWBP");

            println!("[+] Hook installed.");

            // Call target on same thread (no new GUI threads)
            let result = test_target(1, 2);
            println!("[i] Returned result: {}", result);

            assert!(DETOUR_HIT.load(Ordering::SeqCst), "Detour was never hit");

            println!("[i] Removing HWBP...");
            remove_breakpoint(tid, DrRegister::Dr0).expect("Failed to remove HWBP");
            uninitialize_hwbp_runtime();
        }
    }
}
