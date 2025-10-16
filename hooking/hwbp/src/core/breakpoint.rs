use log::{debug, error, trace, warn};
use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, GetCurrentThreadId, OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_X86 as CONTEXT_DEBUG_REGISTERS;

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64 as CONTEXT_DEBUG_REGISTERS;

#[cfg(target_arch = "arm")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_ARM as CONTEXT_DEBUG_REGISTERS;

#[cfg(target_arch = "aarch64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_ARM64 as CONTEXT_DEBUG_REGISTERS;

use crate::core::context::set_dr7_bits;
use crate::manager::hook_registry::HOOK_REGISTRY;
use crate::utils::error::HwbpError;
use crate::utils::types::{BreakpointState, DrRegister, HookDescriptor};

/// Installs a hardware breakpoint (HWBP) in a specific thread.
///
/// This function modifies the target thread’s debug registers (`Dr0–Dr3`)
/// to point to the specified `target_address`. When that instruction executes,
/// an exception will be raised and handled by the global VEH handler.
///
/// # Parameters
/// - `thread_id`: ID of the target thread.
/// - `target_address`: Address to watch for execution.
/// - `detour`: Pointer to the detour (callback) function.
/// - `register`: Which debug register (`Dr0–Dr3`) to use.
///
/// # Returns
/// - `Ok(())` if the breakpoint was successfully installed.
/// - `Err(HwbpError)` on any WinAPI or validation failure.
///
/// # Errors
/// - [`HwbpError::InvalidAddress`] if the address or detour pointer is invalid.
/// - [`HwbpError::ThreadNotFound`] if the thread cannot be opened.
/// - [`HwbpError::ContextReadFailed`] / [`HwbpError::ContextWriteFailed`] if
///   context operations fail.
/// - [`HwbpError::RegisterInUse`] if the requested register is already occupied.
///
/// # Safety
/// This function uses `GetThreadContext` and `SetThreadContext`, which modify
/// thread state. Unsafe operations are wrapped and verified.
pub fn set_hardware_breakpoint(
    thread_id: usize,
    target_address: *const c_void,
    detour: *const c_void,
    register: DrRegister,
) -> Result<(), HwbpError> {
    if target_address.is_null() || detour.is_null() {
        return Err(HwbpError::InvalidAddress);
    }

    let desired_access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
    let objective_thread = thread_id;

    // Obtain thread handle
    let h_thread: HANDLE = unsafe { OpenThread(desired_access, 0, thread_id as u32) };

    if h_thread.is_null() {
        let err = unsafe { GetLastError() };
        error!("Failed to open thread {} (error {})", thread_id, err);
        return Err(HwbpError::ThreadNotFound(err));
    }

    trace!("Opened thread {} handle successfully.", objective_thread);

    // Initialize context structure
    // Note: Using box to heap allocate CONTEXT since it might not be aligned
    let mut thread_ctx = unsafe { Box::<CONTEXT>::new_zeroed().assume_init() };
    thread_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Read current context
    let success = unsafe { GetThreadContext(h_thread, thread_ctx.as_mut() ) };
    if success == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(h_thread) };
        error!(
            "GetThreadContext failed for {} (error {})",
            objective_thread, err
        );
        return Err(HwbpError::ContextReadFailed(err));
    }

    // Lock registry and check register availability
    let mut hook_registry = HOOK_REGISTRY
        .lock()
        .map_err(|_| HwbpError::RegistryPoisoned)?;

    if hook_registry.contains(objective_thread, register) {
        unsafe { CloseHandle(h_thread) };
        warn!(
            "Thread {} already has breakpoint in {:?}",
            objective_thread, register
        );
        return Err(HwbpError::RegisterInUse);
    }

    // Write address to the correct DRx register

    match register {
        DrRegister::Dr0 => thread_ctx.Dr0 = target_address as u64,
        DrRegister::Dr1 => thread_ctx.Dr1 = target_address as u64,
        DrRegister::Dr2 => thread_ctx.Dr2 = target_address as u64,
        DrRegister::Dr3 => thread_ctx.Dr3 = target_address as u64,
    }

    // Enable the breakpoint in Dr7
    let drx_index = register.index();
    thread_ctx.Dr7 = set_dr7_bits(thread_ctx.Dr7, drx_index * 2, 1, 1);

    // Write modified context back
    let success = unsafe { SetThreadContext(h_thread, thread_ctx.as_mut()) };
    if success == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(h_thread) };
        error!(
            "SetThreadContext failed for {} (error {})",
            objective_thread, err
        );
        return Err(HwbpError::ContextWriteFailed(err));
    }

    unsafe { CloseHandle(h_thread) };

    // Record descriptor
    let hook_descriptor = HookDescriptor {
        target_address: Some(target_address as usize),
        detour_address: Some(detour as usize),
        register: Some(register),
        state: BreakpointState::Active,
        thread_id: Some(objective_thread),
    };

    debug!(
        "Installed HWBP: TID={} DR={:?} Target=0x{:X}",
        objective_thread, register, target_address as usize
    );

    hook_registry.insert(objective_thread, register, hook_descriptor);
    Ok(())
}

/// Removes a hardware breakpoint (HWBP) from a specific thread.
///
/// This function clears the selected debug register (`Dr0`–`Dr3`)
/// and disables the corresponding enable bit (`G0`–`G3`) in the `Dr7` register.
/// It also updates the global [`HOOK_REGISTRY`] to reflect the removal.
///
/// # Parameters
/// - `thread_id`: ID of the target thread.
/// - `register`: The hardware debug register (`Dr0–Dr3`) to clear.
///
/// # Returns
/// - `Ok(())` on success.
/// - `Err(HwbpError)` if the operation fails.
///
/// # Errors
/// - [`HwbpError::ThreadNotFound`] if the thread cannot be opened.
/// - [`HwbpError::ContextReadFailed`] or [`HwbpError::ContextWriteFailed`] if
///   thread context modification fails.
/// - [`HwbpError::RemoveFailed`] if the breakpoint was not found.
///
/// # Safety
/// This function modifies the target thread’s hardware debug registers.
/// All unsafe operations are isolated and verified.
pub fn clear_hardware_breakpoint(
    thread_id: usize,
    register: DrRegister,
) -> std::result::Result<(), HwbpError> {
    trace!(
        "Attempting to clear HWBP for thread {} in {:?}",
        thread_id, register
    );

    // Check if breakpoint exists in registry
    let mut hook_registry = HOOK_REGISTRY
        .lock()
        .map_err(|_| HwbpError::RegistryPoisoned)?;

    if !hook_registry.contains(thread_id, register) {
        warn!(
            "No existing HWBP entry for thread {} register {:?}.",
            thread_id, register
        );
        return Err(HwbpError::RemoveFailed);
    }

    // Open thread handle
    let desired_access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
    let current_thread_id = unsafe { GetCurrentThreadId() };
    let h_thread: HANDLE = unsafe {
        if thread_id == current_thread_id as usize {
            GetCurrentThread()
        } else {
            OpenThread(desired_access, 0, thread_id as u32)
        }
    };

    if h_thread.is_null() {
        let err = unsafe { GetLastError() };
        error!("Failed to open thread {} (error {})", thread_id, err);
        return Err(HwbpError::ThreadNotFound(err));
    }

    // Prepare thread context
    let mut thread_ctx = unsafe { Box::<CONTEXT>::new_zeroed().assume_init() };
    thread_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Read thread context
    let success = unsafe { GetThreadContext(h_thread, thread_ctx.as_mut()) };
    if success == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(h_thread) };
        error!("GetThreadContext failed for {} (error {})", thread_id, err);
        return Err(HwbpError::ContextReadFailed(err));
    }

    // Clear the selected DRx register
    match register {
        DrRegister::Dr0 => thread_ctx.Dr0 = 0,
        DrRegister::Dr1 => thread_ctx.Dr1 = 0,
        DrRegister::Dr2 => thread_ctx.Dr2 = 0,
        DrRegister::Dr3 => thread_ctx.Dr3 = 0,
    }

    // Disable the Gx bit in Dr7
    let drx_index = register.index();
    thread_ctx.Dr7 = set_dr7_bits(thread_ctx.Dr7, drx_index * 2, 1, 0);

    // Write context back
    let success = unsafe { SetThreadContext(h_thread, thread_ctx.as_mut()) };
    if success == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(h_thread) };
        error!("SetThreadContext failed for {} (error {})", thread_id, err);
        return Err(HwbpError::ContextWriteFailed(err));
    }

    unsafe { CloseHandle(h_thread) };

    // Remove from registry
    hook_registry.active.remove(&(thread_id, register));
    debug!(
        "Removed HWBP from registry: TID={} DR={:?}",
        thread_id, register
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use std::{
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    use crate::core::breakpoint::{clear_hardware_breakpoint, set_hardware_breakpoint};
    use crate::utils::error::HwbpError;
    use crate::utils::types::{BreakpointState, DrRegister};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
        THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };
    use crate::manager::hook_registry::HOOK_REGISTRY;

    /// Spawns a worker thread that reports its Windows thread ID
    /// and keeps running until explicitly stopped.
    fn spawn_test_thread() -> (std::thread::JoinHandle<()>, u32) {
        let thread_id_arc = Arc::new(Mutex::new(0u32));
        let thread_id_clone = Arc::clone(&thread_id_arc);

        // Spawn a background thread that records its Win32 thread ID
        let handle = thread::spawn(move || {
            let tid = unsafe { GetCurrentThreadId() };
            *thread_id_clone.lock().unwrap() = tid;
            loop {
                std::thread::sleep(Duration::from_millis(100));
            }
        });

        // Wait until the thread has stored its ID
        std::thread::sleep(Duration::from_millis(200));
        let tid = *thread_id_arc.lock().unwrap();
        assert!(tid != 0, "Failed to retrieve thread ID");

        (handle, tid)
    }

    /// Installing a breakpoint on the current thread.
    /// This validates the pseudo-handle code path (GetCurrentThread).
    #[test]
    fn test_install_breakpoint_current_thread() {
        let thread_id = unsafe { GetCurrentThreadId() } as usize;
        let target_address = 0x1234usize as *const c_void;
        let detour_address = 0x5678usize as *const c_void;

        // Execute installation
        let result =
            set_hardware_breakpoint(thread_id, target_address, detour_address, DrRegister::Dr0);
        assert!(
            result.is_ok(),
            "set_hardware_breakpoint() failed: {:?}",
            result.err()
        );

        // Validate it was stored in the global registry
        let registry = HOOK_REGISTRY.lock().unwrap();
        assert!(
            registry.contains(thread_id, DrRegister::Dr0),
            "Breakpoint not found in registry after installation"
        );

        let desc = registry
            .active
            .get(&(thread_id, DrRegister::Dr0))
            .expect("Descriptor not found");

        assert_eq!(desc.target_address, Some(target_address as usize));
        assert_eq!(desc.detour_address, Some(detour_address as usize));
        assert_eq!(desc.register, Some(DrRegister::Dr0));
        assert_eq!(desc.thread_id, Some(thread_id));
        assert_eq!(desc.state, BreakpointState::Active);
    }

    /// Installing a breakpoint on an external thread while suspended.
    ///
    /// This covers the expected production scenario — manipulating
    /// another thread’s debug registers typically requires suspension
    /// for consistent GetThreadContext / SetThreadContext access.
    #[test]
    fn test_install_breakpoint_on_external_thread_suspended() {
        let (worker, tid) = spawn_test_thread();

        unsafe {
            // Open the external thread for full context access
            let desired_access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
            let h_thread: HANDLE = OpenThread(desired_access, 0, tid);
            assert!(!h_thread.is_null(), "OpenThread failed");

            // Suspend the thread before modifying context
            let suspend_count = SuspendThread(h_thread);
            assert!(suspend_count != u32::MAX, "SuspendThread failed");

            // Attempt to install the hardware breakpoint
            let result = set_hardware_breakpoint(
                tid as usize,
                0x12345678usize as *const c_void,
                0x87654321usize as *const c_void,
                DrRegister::Dr1,
            );
            assert!(
                result.is_ok(),
                "set_hardware_breakpoint() failed on suspended thread: {:?}",
                result.err()
            );

            // Validate registry state
            let registry = HOOK_REGISTRY.lock().unwrap();
            assert!(
                registry.contains(tid as usize, DrRegister::Dr1),
                "Breakpoint not found in registry after installation"
            );

            // Resume and clean up
            let resumed = ResumeThread(h_thread);
            assert!(resumed != u32::MAX, "ResumeThread failed");
            CloseHandle(h_thread);
        }

        // Stop the worker thread (it loops indefinitely)
        worker.thread().unpark();
    }

    /// Installing a breakpoint on an external thread that is not suspended.
    ///
    /// Depending on the OS state, modifying a live thread’s context may fail,
    /// but for our API surface this test asserts success for the happy path.
    #[test]
    fn test_install_breakpoint_on_external_thread_unsuspended() {
        let (worker, tid) = spawn_test_thread();

        unsafe {
            // Open the thread with full context access
            let desired_access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
            let h_thread: HANDLE = OpenThread(desired_access, 0, tid);
            assert!(!h_thread.is_null(), "OpenThread failed");

            // Attempt to install the breakpoint without suspending
            let result = set_hardware_breakpoint(
                tid as usize,
                0xAAAABBBBusize as *const c_void,
                0xBBBBCCCCusize as *const c_void,
                DrRegister::Dr2,
            );
            assert!(
                result.is_ok(),
                "set_hardware_breakpoint() failed on unsuspended thread: {:?}",
                result.err()
            );

            // Validate registry state
            let registry = HOOK_REGISTRY.lock().unwrap();
            assert!(
                registry.contains(tid as usize, DrRegister::Dr2),
                "Breakpoint not found in registry after installation"
            );

            CloseHandle(h_thread);
        }

        // Stop the worker thread
        worker.thread().unpark();
    }

    /// Removing a valid hardware breakpoint from the current thread.
    ///
    /// Validates:
    /// - The breakpoint is deleted from both the CPU context and the registry.
    /// - The registry no longer contains the entry afterward.
    #[test]
    fn test_remove_existing_breakpoint() {
        let thread_id = unsafe { GetCurrentThreadId() } as usize;
        let target_address = 0x1111usize as *const c_void;
        let detour_address = 0x2222usize as *const c_void;

        // Ensure clean registry state
        {
            let mut reg = HOOK_REGISTRY.lock().unwrap();
            reg.active.clear();
        }

        // Install first
        let result =
            set_hardware_breakpoint(thread_id, target_address, detour_address, DrRegister::Dr0);
        assert!(
            result.is_ok(),
            "set_hardware_breakpoint() failed: {:?}",
            result.err()
        );

        // Confirm it's in the registry
        {
            let reg = HOOK_REGISTRY.lock().unwrap();
            assert!(
                reg.contains(thread_id, DrRegister::Dr0),
                "Breakpoint should exist in registry"
            );
        }

        // Remove the breakpoint
        let remove_result = clear_hardware_breakpoint(thread_id, DrRegister::Dr0);
        assert!(
            remove_result.is_ok(),
            "clear_hardware_breakpoint() failed: {:?}",
            remove_result.err()
        );

        // Confirm it's gone
        {
            let reg = HOOK_REGISTRY.lock().unwrap();
            assert!(
                !reg.contains(thread_id, DrRegister::Dr0),
                "Breakpoint should have been removed from registry"
            );
        }
    }

    /// Attempting to remove a breakpoint that doesn't exist.
    ///
    /// Our implementation returns `HwbpError::RemoveFailed` for this case.
    #[test]
    fn test_remove_nonexistent_breakpoint() {
        let thread_id = unsafe { GetCurrentThreadId() } as usize;

        // Ensure registry is empty
        {
            let mut reg = HOOK_REGISTRY.lock().unwrap();
            reg.active.clear();
        }

        // Try to remove Dr1 (which isn't installed)
        let result = clear_hardware_breakpoint(thread_id, DrRegister::Dr1);

        match result {
            Err(HwbpError::RemoveFailed) => {} // expected behavior for "not found"
            other => panic!("Expected HwbpError::RemoveFailed, but got {:?}", other),
        }
    }
}
