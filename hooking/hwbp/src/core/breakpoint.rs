use std::os::windows::raw::HANDLE;

use crate::core::error::BreakpointError;
use crate::types::{BreakpointState, DrRegister, HookDescriptor};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext};
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

/// Installs a hardware breakpoint for a specific thread.
///
/// This function assigns a hardware debug register (`Dr0`–`Dr3`)
/// to the given `target_address` and links it with a detour function.
/// The breakpoint is configured directly in the target thread’s
/// debug registers (`DrX` and `Dr7`).
///
/// # Arguments
///
/// * `thread_id` - Identifier of the thread where the breakpoint will be installed.
/// * `target_address` - Address of the instruction or function to break on.
/// * `detour_address` - Address of the detour function that will be invoked
///   when the breakpoint is hit.
/// * `register` - The hardware debug register (`Dr0`–`Dr3`) to use for this breakpoint.
///
/// # Returns
///
/// On success, returns a [`HookDescriptor`] describing the installed breakpoint.
/// On failure, returns a [`BreakpointError`] indicating the reason:
/// - [`BreakpointError::ThreadNotFound`] if the target thread cannot be accessed.
/// - [`BreakpointError::RegisterInUse`] if the chosen debug register is already occupied.
/// - [`BreakpointError::ContextReadFailed`] if reading the thread context fails.
/// - [`BreakpointError::ContextWriteFailed`] if writing the thread context fails.
///
/// Breakpoints installed using this function are **thread-local**; they affect
/// only the thread identified by `thread_id`. Each thread supports up to
/// four hardware breakpoints at a time.
pub fn install_breakpoint(
    thread_id: usize,
    target_address: usize,
    detour_address: usize,
    register: DrRegister,
) -> Result<HookDescriptor, BreakpointError> {
    if target_address == 0 || detour_address == 0 {
        return Err(BreakpointError::InvalidAddress);
    }

    // Try to open the target thread by ID
    let desired_access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
    let current_thread_id = unsafe { GetCurrentThreadId() };

    let h_thread: HANDLE = if thread_id == current_thread_id as usize {
        // Use pseudo-handle for current thread
        unsafe { GetCurrentThread() }
    } else {
        // Open real handle for external thread
        unsafe { OpenThread(desired_access, 0, thread_id as u32) }
    };
    if h_thread.is_null() {
        let err = unsafe { GetLastError() };
        return Err(BreakpointError::ThreadNotFound(err));
    }

    // Prepare a context with debug registers
    let mut thread_ctx: CONTEXT = unsafe { std::mem::zeroed() };
    thread_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Read current context
    let success = unsafe { GetThreadContext(h_thread, &mut thread_ctx as *mut CONTEXT) };
    if success == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(h_thread) };
        return Err(BreakpointError::ContextReadFailed(err));
    }

    // Set the requested debug register
    match register {
        DrRegister::Dr0 => thread_ctx.Dr0 = target_address as u64,
        DrRegister::Dr1 => thread_ctx.Dr1 = target_address as u64,
        DrRegister::Dr2 => thread_ctx.Dr2 = target_address as u64,
        DrRegister::Dr3 => thread_ctx.Dr3 = target_address as u64,
    }

    // Write the modified context back
    let success = unsafe { SetThreadContext(h_thread, &mut thread_ctx as *mut CONTEXT) };
    if success == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(h_thread) };
        return Err(BreakpointError::ContextWriteFailed(err));
    }

    unsafe { CloseHandle(h_thread) };

    Ok(HookDescriptor {
        target_address: Some(target_address),
        detour_address: Some(detour_address),
        register: Some(register),
        state: BreakpointState::Active,
        thread_id: Some(thread_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Threading::{
        GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
        THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

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
        let target_address = 0x1234usize;
        let detour_address = 0x5678usize;

        let result = install_breakpoint(thread_id, target_address, detour_address, DrRegister::Dr0);

        match result {
            Ok(desc) => {
                assert_eq!(desc.target_address, Some(target_address));
                assert_eq!(desc.detour_address, Some(detour_address));
                assert_eq!(desc.register, Some(DrRegister::Dr0));
                assert_eq!(desc.thread_id, Some(thread_id));
                assert_eq!(desc.state, BreakpointState::Active);
            }
            Err(err) => panic!("install_breakpoint() failed with error: {}", err),
        }
    }

    /// Installing a breakpoint on an external thread while suspended.
    ///
    /// This covers the expected production scenario — manipulating
    /// another thread’s debug registers requires suspension for
    /// consistent GetThreadContext / SetThreadContext access.
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
            let result = install_breakpoint(tid as usize, 0x12345678, 0x87654321, DrRegister::Dr0);

            assert!(
                result.is_ok(),
                "install_breakpoint() failed on suspended thread: {:?}",
                result.err()
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
    /// Warning: Windows may return ERROR_NOACCESS (998) or a similar error because a live
    /// thread’s context cannot be safely accessed with GetThreadContext.
    #[test]
    fn test_install_breakpoint_on_external_thread_unsuspended() {
        let (worker, tid) = spawn_test_thread();

        unsafe {
            // Open the thread with full context access
            let desired_access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
            let h_thread: HANDLE = OpenThread(desired_access, 0, tid);
            assert!(!h_thread.is_null(), "OpenThread failed");

            // Attempt to install the breakpoint without suspending
            let result = install_breakpoint(tid as usize, 0xAAAABBBB, 0xBBBBCCCC, DrRegister::Dr1);
            assert!(
                result.is_ok(),
                "install_breakpoint() failed on suspended thread: {:?}",
                result.err()
            );

            CloseHandle(h_thread);
        }

        // Stop the worker thread
        worker.thread().unpark();
    }
}
