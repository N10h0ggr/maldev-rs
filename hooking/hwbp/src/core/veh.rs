//! VEH (Vectored Exception Handler) dispatcher.
//!
//! This module owns the registration and the callback that services hardware-breakpoint
//! single-step exceptions. It’s structured around a small singleton that tracks whether
//! the handler is installed and provides an idempotent initializer.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use log::{debug, error, info, trace, warn};
use windows_sys::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, CONTEXT, EXCEPTION_CONTINUE_EXECUTION,
        EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    },
    System::Threading::GetCurrentThreadId,
};

use crate::core::breakpoint::{clear_hardware_breakpoint, set_hardware_breakpoint};
use crate::manager::hook_registry::HOOK_REGISTRY;
use crate::utils::types::DrRegister;

/// Singleton that manages the lifecycle of the vectored exception handler (VEH).
///
/// The handler is registered once per process and services all HWBP single-step exceptions.
/// Use [`Veh::init`] (or the free wrapper [`init`]) before installing breakpoints.
struct Veh {
    initialized: AtomicBool,
    cookie: AtomicPtr<c_void>,
}

impl Veh {
    /// Creates a new, uninitialized dispatcher.
    const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            cookie: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Returns whether the VEH has already been initialized.
    fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Initializes (registers) the vectored exception handler if not already done.
    ///
    /// This call is **idempotent**; subsequent calls after a successful initialization
    /// are no-ops that return `Ok(())`.
    ///
    /// # Errors
    /// Returns `Err(&'static str)` if the underlying `AddVectoredExceptionHandler` fails.
    fn init(&self) -> Result<(), &'static str> {
        if self.is_initialized() {
            return Ok(());
        }

        // Register as first handler to ensure we see HWBP exceptions before others.
        let cookie = unsafe { AddVectoredExceptionHandler(1, Some(vector_handler)) };
        if cookie.is_null() {
            return Err("AddVectoredExceptionHandler failed");
        }

        self.cookie.store(cookie, Ordering::Release);
        self.initialized.store(true, Ordering::Release);
        info!("VEH successfully initialized.");
        Ok(())
    }
}

// Global singleton instance.
static VEH: Veh = Veh::new();

/// Returns whether the VEH is initialized (registered).
pub fn is_initialized() -> bool {
    VEH.is_initialized()
}

/// Initializes the VEH if needed (idempotent).
///
/// # Errors
/// Returns `Err(&'static str)` if registration fails at the OS layer.
pub fn init() -> Result<(), &'static str> {
    VEH.init()
}

/// Vectored exception handler that services hardware-breakpoint single-step exceptions.
///
/// The handler identifies which debug register (Dr0–Dr3) triggered the event, disables
/// the breakpoint to prevent re-entry, looks up the corresponding hook from `HOOK_REGISTRY`,
/// calls the detour function, and optionally reinstalls the breakpoint.
///
/// # Parameters
/// - `p_exc`: Pointer to the system-provided `EXCEPTION_POINTERS`.
///
/// # Returns
/// - `EXCEPTION_CONTINUE_EXECUTION` if the exception was handled by us.
/// - `EXCEPTION_CONTINUE_SEARCH` to pass handling to the next handler.
///
/// # Safety
/// This function dereferences raw pointers provided by the OS and performs FFI calls.
/// The library assumes any registered detour function uses the correct calling convention
/// and is valid for the lifetime of the hook.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn vector_handler(p_exc: *mut EXCEPTION_POINTERS) -> i32 {
    if p_exc.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // SAFETY: `p_exc` was checked for null above; Windows provides valid structures here.
    let (exception_record, context_record) =
        unsafe { (&*(*p_exc).ExceptionRecord, &*(*p_exc).ContextRecord) };

    // Only handle hardware single-step exceptions.
    if exception_record.ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // The address of the instruction that triggered the breakpoint.
    let exception_addr = exception_record.ExceptionAddress as usize;

    // Determine which DRx fired by matching the exception address against DR0..DR3.
    let drx = if exception_addr ==  { context_record.Dr0 as usize } {
        Some(DrRegister::Dr0)
    } else if exception_addr ==  { context_record.Dr1 as usize } {
        Some(DrRegister::Dr1)
    } else if exception_addr ==  { context_record.Dr2 as usize } {
        Some(DrRegister::Dr2)
    } else if exception_addr ==  { context_record.Dr3 as usize } {
        Some(DrRegister::Dr3)
    } else {
        None
    };

    let Some(drx) = drx else {
        return EXCEPTION_CONTINUE_SEARCH;
    };

    let current_thread_id = unsafe { GetCurrentThreadId() as usize };

    // Look up the hook descriptor for (TID, DRx).
    let hook_info = {
        let Ok(registry) = HOOK_REGISTRY.lock() else {
            return EXCEPTION_CONTINUE_SEARCH;
        };
        match registry.active.get(&(current_thread_id, drx)) {
            Some(info) => info.clone(),
            None => {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
    };

    // Best-effort: disable the HWBP to avoid re-entry storms.
    let _ = clear_hardware_breakpoint(current_thread_id, drx);

    // Resolve detour address into a callable function pointer.
    let Some(detour_address) = hook_info.detour_address else {
        return EXCEPTION_CONTINUE_SEARCH;
    };

    let hook_fn: unsafe extern "system" fn(*mut CONTEXT) =
        unsafe { core::mem::transmute::<usize, _>(detour_address) };

    // Invoke detour with the current thread context.
    unsafe {
        hook_fn(context_record as *const _ as *mut _);
    }

    // Optionally reinstall the breakpoint so subsequent hits keep flowing through.
    if let (Some(tid), Some(target), Some(detour), Some(reg)) = (
        hook_info.thread_id,
        hook_info.target_address,
        hook_info.detour_address,
        hook_info.register,
    ) {
        let _ = set_hardware_breakpoint(tid, target as _, detour as _, reg);
    }

    EXCEPTION_CONTINUE_EXECUTION
}
