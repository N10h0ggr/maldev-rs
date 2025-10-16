//! detour::callbacks — propagate hooks to newly created threads.
//!
//! Strategy (Solution 2 from the blog):
//!  1) Hardware-breakpoint `NtCreateThreadEx` so our detour runs on entry.
//!  2) In the detour, force the thread to be created **suspended** by OR-ing
//!     the `Flags` parameter with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`.
//!  3) Schedule a **timer-queue callback** that waits until the OUT `hThread`
//!     is populated, then mirrors up to four global hooks into the new thread,
//!     picking a free DRx each time, and finally **resumes** the thread.
//!
//! The detour returns and the VEH handler continues execution (no special
//! "continue" helper is required).

use core::ffi::c_void;
use log::{debug, error, info, trace, warn};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    CreateTimerQueueTimer, GetThreadId, ResumeThread, THREAD_CREATE_SUSPENDED, WT_EXECUTEDEFAULT
};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

use crate::core::breakpoint::set_hardware_breakpoint;
use crate::detour::callargs::CallArgs;
use crate::manager::hook_registry::HOOK_REGISTRY;
use crate::utils::types::DrRegister;


/// Detour for `NtCreateThreadEx` that ensures new threads are created suspended
/// and schedules a callback to mirror global hooks into the new thread.
///
/// Parameters (Windows):
///   1: OUT PHANDLE hThread            <-- we need this pointer
///   7: ULONG Flags                    <-- we OR with CREATE_SUSPENDED
///
/// We use `CallArgs` to access parameters by **1-based index**.
///
/// # Safety
/// - Called from our VEH path with a valid pointer to the current thread `CONTEXT`.
/// - Uses raw WinAPI calls and pointer manipulation; all unsafe operations are localized.
pub unsafe extern "system" fn ntcreate_thread_ex_detour(ctx: *mut CONTEXT) {
    if ctx.is_null() {
        warn!("NtCreateThreadExDetour: null CONTEXT pointer");
        return;
    }

    // Wrap the context
    let mut args = unsafe { CallArgs::new(ctx) };

    // Get OUT PHANDLE parameter (param #1)
    let p_thread_out = unsafe { args.get_ptr::<HANDLE>(1) };
    if p_thread_out.is_null() {
        warn!("NtCreateThreadExDetour: OUT hThread parameter is null");
        // Still proceed to modify flags and return, to not disrupt the syscall path.
    }

    // Force creation suspended by setting the CREATE_SUSPENDED flag (param #7)
    let old_flags = unsafe { args.get(7) } as u32;
    let new_flags = old_flags | THREAD_CREATE_SUSPENDED;
    unsafe { args.set(7, new_flags as usize) };
    trace!(
        "NtCreateThreadExDetour: Flags 0x{:08X} -> 0x{:08X}",
        old_flags,
        new_flags
    );

    // Schedule timer-queue callback; we pass PHANDLE so the callback can
    // spin until it's populated by the real NtCreateThreadEx.
    let mut h_timer: HANDLE = ptr::null_mut();
    let ok = unsafe {
        CreateTimerQueueTimer(
            &mut h_timer as *mut HANDLE,
            0 as HANDLE, // default timer queue
            Some(timed_hook_callback),
            p_thread_out as *mut c_void,
            0, // due time (ms)
            0, // period (ms) one-shot
            WT_EXECUTEDEFAULT,
        )
    };

    if ok == 0 {
        warn!("NtCreateThreadExDetour: CreateTimerQueueTimer failed; no propagation for this thread.");
    } else {
        trace!("NtCreateThreadExDetour: scheduled propagation callback.");
    }

    unsafe { args.continue_execution() }
}

/// Timer-queue callback used to mirror up to four global hooks into a newly created thread.
///
/// # Parameters
/// - `lp_parameter`: Pointer to a `HANDLE` filled by `NtCreateThreadEx` upon success.
/// - `_timer_or_wait_fired`: Unused.
pub unsafe extern "system" fn timed_hook_callback(lp_parameter: *mut c_void, _timer_or_wait_fired: bool) {
    if lp_parameter.is_null() {
        warn!("TimedHookCallback: lpParameter is null");
        return;
    }

    let p_thread = lp_parameter as *mut HANDLE;

    // Wait for NtCreateThreadEx to populate OUT hThread
    let h_thread = loop {
        let handle = unsafe { *p_thread };
        if !handle.is_null() {
            break handle;
        }
        std::thread::yield_now();
    };

    // Resolve the thread ID
    let new_tid = unsafe { GetThreadId(h_thread) };
    if new_tid == 0 {
        warn!("TimedHookCallback: GetThreadId returned 0; resuming without propagation.");
        unsafe {
            ResumeThread(h_thread);
        }
        return;
    }

    info!("TimedHookCallback: New thread detected (TID = {}) — propagating hooks.", new_tid);

    // Step 1: Collect up to four (target -> detour) hook pairs
    let (targets, detours) = match collect_active_hooks() {
        Some(pairs) => pairs,
        None => {
            unsafe {
                ResumeThread(h_thread);
            }
            return;
        }
    };

    // Step 2: Try installing each hook using a free debug register
    let mut installed = 0usize;
    for (idx, target) in targets.iter().enumerate() {
        if installed >= 4 {
            break;
        }

        let detour = detours[idx];
        let drx = match find_free_drx(new_tid as usize) {
            Some(reg) => reg,
            None => {
                warn!("TimedHookCallback: No free DRx for TID {} — stopping propagation.", new_tid);
                break;
            }
        };

        match set_hardware_breakpoint(new_tid as usize, *target as *const _, detour as *const _, drx) {
            Ok(_) => {
                debug!(
                    "TimedHookCallback: Mirrored HWBP into TID {} — target=0x{:X} via {:?}",
                    new_tid, *target, drx
                );
                installed += 1;
            }
            Err(e) => {
                error!(
                    "TimedHookCallback: Failed HWBP install in TID {} for 0x{:X}: {:?}",
                    new_tid, *target, e
                );
            }
        }
    }

    // Step 3: Resume the suspended thread
    let resume_rc = unsafe { ResumeThread(h_thread) };
    if resume_rc == u32::MAX {
        warn!("TimedHookCallback: ResumeThread failed for TID {}", new_tid);
    }

    info!("TimedHookCallback: Propagation complete for TID {} (installed {}).", new_tid, installed);
}

/// Collects up to four active (target, detour) hook pairs from the global registry.
fn collect_active_hooks() -> Option<(Vec<usize>, Vec<usize>)> {
    use std::collections::HashMap;

    let registry = HOOK_REGISTRY.lock().ok()?;
    let mut pairs = HashMap::new();

    for desc in registry.active.values() {
        if let (Some(tgt), Some(det)) = (desc.target_address, desc.detour_address) {
            pairs.entry(tgt).or_insert(det);
            if pairs.len() >= 4 {
                break;
            }
        }
    }

    let (targets, detours): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    Some((targets, detours))
}

/// Finds a free debug register (DRx) for a given thread ID.
fn find_free_drx(tid: usize) -> Option<DrRegister> {
    HOOK_REGISTRY.lock().ok()?.find_free_drx_for_thread(tid)
}
