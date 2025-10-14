use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP, System::Diagnostics::Debug::EXCEPTION_POINTERS,
};

use crate::core::breakpoint::remove_breakpoint;
use crate::types::{DrRegister, HOOK_REGISTRY};

/// This function is called by Windows when a hardware breakpoint is hit. It determines which
/// debug register (Dr0–Dr3) caused the exception, removes that breakpoint to prevent re-entry,
/// looks up the corresponding hook from `HOOK_REGISTRY`, and executes the detour function tied
/// to it. Once the hook has run, execution resumes normally.
///
/// # Parameters
/// - `p_exc`: Pointer to an `EXCEPTION_POINTERS` structure provided by the system. It contains
///   both the exception record and the current thread context. If null, the function ignores
///   the event.
///
/// # Return
/// Returns `EXCEPTION_CONTINUE_EXECUTION` (`-1`) if the exception was handled, or
/// `EXCEPTION_CONTINUE_SEARCH` (`0`) to let Windows forward it to the next handler.
///
/// # Safety
/// This function operates entirely in `unsafe` context because it dereferences raw pointers,
/// interacts directly with Windows exception handling, and executes arbitrary hook functions
/// by address. The caller must ensure that all provided pointers and detour addresses are valid
/// and that registered hooks follow the correct calling convention.
pub unsafe extern "system" fn vector_handler(p_exc: *mut EXCEPTION_POINTERS) -> i32 {
    if p_exc.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_record = unsafe { &*(*p_exc).ExceptionRecord };
    let context_record = unsafe { &*(*p_exc).ContextRecord };

    // We only handle exceptions triggered by breakpoints
    if exception_record.ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Address where the hwbp triggered
    let exception_addr = exception_record.ExceptionAddress as usize;

    let drx = if exception_addr == context_record.Dr0 as usize {
        Some(DrRegister::Dr0)
    } else if exception_addr == context_record.Dr1 as usize {
        Some(DrRegister::Dr1)
    } else if exception_addr == context_record.Dr2 as usize {
        Some(DrRegister::Dr2)
    } else if exception_addr == context_record.Dr3 as usize {
        Some(DrRegister::Dr3)
    } else {
        None
    };

    if let Some(drx) = drx {
        let current_thread_id = unsafe { GetCurrentThreadId() as usize };

        // Disable HWBP (re-entry protection)
        remove_breakpoint(current_thread_id, drx)
            .unwrap_or_else(|e| panic!("Failed to remove breakpoint for {:?}: {}", drx, e));

        // Lookup active hook
        let hook_registry = HOOK_REGISTRY.lock().expect("HOOK_REGISTRY mutex poisoned");

        let hook_info = hook_registry
            .active
            .get(&(current_thread_id, drx))
            .expect("No active hook for this DR register");

        // Make sure detour_address is a plain usize, not Option<usize>
        let detour_addr = hook_info.detour_address.expect("detour_address is None");

        // Convert stored address into callable function pointer
        let hook_function = unsafe {
            std::mem::transmute::<usize, unsafe extern "system" fn(*mut CONTEXT)>(detour_addr)
        };

        unsafe {
            hook_function(context_record as *const CONTEXT as *mut CONTEXT);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}
