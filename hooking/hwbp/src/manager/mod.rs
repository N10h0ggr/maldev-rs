pub(crate) mod hook_registry;
mod installer;

use core::ffi::c_void;
use std::sync::Once;
use log::{debug, error, info, trace, warn};
use windows_sys::s;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use hook_registry::HOOK_REGISTRY;
use crate::core::veh;
use crate::detour::callbacks::ntcreate_thread_ex_detour;
use crate::manager::installer::{install_hook_all_threads, uninstall_hook_all_threads};
use crate::utils::error::HwbpError;
// ensure we only hook NtCreateThreadEx once globally
static INIT_NT_CREATE_THREAD_EX: Once = Once::new();

/// Installs a hardware-breakpoint (HWBP) hook for the given `address`, dispatching to the
/// provided `detour` routine when the breakpoint is hit.  
///
/// The function ensures the vectored exception handler (VEH) is initialized, and then
/// installs the breakpoint across **all existing threads** of the current process.
/// Newly created threads will automatically receive this hook via the
/// `NtCreateThreadEx` detour installed by the library.
///
/// # Parameters
/// - `address`: Pointer to the target function or instruction to monitor.
/// - `detour`: Pointer to the detour (callback) function invoked by the VEH.
///
/// # Returns
/// - `Ok(())` if the HWBP was successfully installed on all threads.
/// - `Err(HwbpError)` if validation, VEH initialization, or thread installation fails.
///
/// # Safety
/// The function modifies thread contexts across the current process.
/// All unsafe operations are internally contained.
///
/// # Example
/// ```ignore
/// install_hwbp(target_fn as *const c_void, detour_fn as *const c_void)?;
/// ```
pub fn install_hwbp(
    address: *const c_void,
    detour: *const c_void,
) -> std::result::Result<(), HwbpError> {
    //env_logger::init();

    if address.is_null() {
        return Err(HwbpError::NullPointer { what: "address" });
    }
    if detour.is_null() {
        return Err(HwbpError::NullPointer { what: "detour" });
    }

    // Ensure VEH is ready
    if !veh::is_initialized() {
        info!("VEH not initialized — initializing now.");
        if let Err(e) = veh::init() {
            error!("VEH initialization failed: {}", e);
            return Err(HwbpError::VehInitFailed(e));
        }
    }

    trace!("Installing HWBP for address {:p}", address);

    // hook NtCreateThreadEx (only once)
    // since are they registered as any other hook they will be deleted automatically at cleanup
    INIT_NT_CREATE_THREAD_EX.call_once(|| {
        let lpmodulename = s!("ntdll.dll");
        let lpprocname = s!("NtCreateThreadEx");
        let h_ntdll = unsafe { GetModuleHandleA(lpmodulename) };
        let nt_create_thread_ex = unsafe { GetProcAddress(h_ntdll, lpprocname) };

        if let Some(addr) = nt_create_thread_ex {
            match install_hook_all_threads(addr as *const c_void, ntcreate_thread_ex_detour as *const c_void) {
                Ok(_) => info!("Hooked NtCreateThreadEx for new-thread propagation."),
                Err(e) => warn!("Failed to hook NtCreateThreadEx: {:?}", e),
            }
        } else {
            warn!("Failed to locate NtCreateThreadEx in ntdll.dll");
        }
    });

    install_hook_all_threads(address, detour)?;

    info!("HWBP installed globally for address {:p}", address);
    Ok(())
}

/// Removes a specific hardware-breakpoint (HWBP) hook from all threads that have it installed.
///
/// This function delegates to [`uninstall_hook_all_threads`] to ensure the target
/// function or instruction is fully unhooked across all existing threads, regardless
/// of which debug register (Dr0–Dr3) was used in each.
///
/// # Parameters
/// - `address`: Pointer to the hooked function or instruction.
///
/// # Returns
/// - `Ok(())` if all related breakpoints were successfully removed.
/// - `Err(HwbpError)` if none were found or any removal operation failed.
///
/// # Safety
/// This function modifies thread contexts through `SetThreadContext`, indirectly
/// via [`uninstall_hook_all_threads`]. All unsafe operations are isolated inside
/// low-level modules.
pub fn uninstall_hwbp(address: *const c_void) -> std::result::Result<(), HwbpError> {
    if address.is_null() {
        return Err(HwbpError::NullPointer { what: "address" });
    }

    info!("Uninstalling HWBP hook globally for target {:p}", address);

    match uninstall_hook_all_threads(address) {
        Ok(_) => {
            info!("Successfully uninstalled HWBP for {:p}", address);
            Ok(())
        }
        Err(e) => {
            warn!("Failed to fully uninstall HWBP for {:p}: {:?}", address, e);
            Err(e)
        }
    }
}

/// Uninstalls **all** active hardware-breakpoint (HWBP) hooks from all threads.
///
/// This function iterates through every unique target address stored in the global
/// [`HOOK_REGISTRY`], and delegates to [`uninstall_hook_all_threads`] to remove all
/// associated breakpoints for each address across all threads.
///
/// Use this function when you want to fully reset the system and remove every HWBP.
///
/// # Returns
/// - `Ok(())` if all breakpoints were successfully removed.
/// - `Err(HwbpError)` if the registry is poisoned or one or more removals fail.
///
/// # Safety
/// This function modifies thread contexts indirectly via
/// [`uninstall_hook_all_threads`], which performs safe low-level cleanup.
pub fn uninstall_all_hwbp() -> std::result::Result<(), HwbpError> {
    info!("Uninstalling all hardware breakpoints from all threads...");

    // Get snapshot of current targets from registry
    let registry = HOOK_REGISTRY
        .lock()
        .map_err(|_| HwbpError::RegistryPoisoned)?;

    if registry.active.is_empty() {
        warn!("No active hardware breakpoints found.");
        return Ok(());
    }

    // Collect unique target addresses
    let mut unique_targets = Vec::new();
    for desc in registry.active.values() {
        if let Some(addr) = desc.target_address {
            if !unique_targets.contains(&addr) {
                unique_targets.push(addr);
            }
        }
    }

    trace!(
        "Identified {} unique target addresses for removal.",
        unique_targets.len()
    );

    drop(registry); // release lock before uninstalling (important!)

    // Uninstall each hook via the existing thread-safe routine
    let mut failures = 0usize;
    for target in unique_targets {
        match uninstall_hook_all_threads(target as *const _) {
            Ok(_) => {
                debug!("Successfully removed HWBP for 0x{:X}", target);
            }
            Err(e) => {
                error!("Failed to remove HWBP for 0x{:X}: {:?}", target, e);
                failures += 1;
            }
        }
    }

    // Evaluate outcome
    if failures > 0 {
        warn!("{} HWBP(s) failed to uninstall completely.", failures);
        return Err(HwbpError::RemoveFailed);
    }

    info!("Successfully uninstalled all hardware breakpoints.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    use crate::manager::{install_hwbp, uninstall_all_hwbp};
    use crate::manager::hook_registry::HOOK_REGISTRY;
    /// Helper: spawns a simple background thread that stays alive until unparked.
    fn spawn_test_thread() -> (std::thread::JoinHandle<()>, u32) {
        let thread_id_arc = Arc::new(Mutex::new(0u32));
        let thread_id_clone = Arc::clone(&thread_id_arc);

        let handle = thread::spawn(move || {
            let tid = unsafe { GetCurrentThreadId() };
            *thread_id_clone.lock().unwrap() = tid;
            // keep thread alive until unparked
            loop {
                thread::sleep(Duration::from_millis(100));
            }
        });

        thread::sleep(Duration::from_millis(200)); // allow thread to initialize
        let tid = *thread_id_arc.lock().unwrap();
        assert!(tid != 0, "Failed to obtain thread ID");

        (handle, tid)
    }

    /// Test that newly created threads automatically receive propagated HWBP hooks
    /// when NtCreateThreadEx is hooked by the propagation detour.
    #[test]
    fn test_hook_propagation_to_new_threads() {
        env_logger::init();

        // install a normal HWBP hook for all threads
        let fake_target = 0x123456usize as *const std::ffi::c_void;
        let fake_detour = 0x654321usize as *const std::ffi::c_void;
        install_hwbp(fake_target, fake_detour).expect("Failed to install test HWBP");

        // now create a new thread AFTER the hook — it should inherit the breakpoints
        let (worker, tid) = spawn_test_thread();

        // wait a bit for propagation via TimedHookCallback
        thread::sleep(Duration::from_millis(500));

        // validate that the new thread has the propagated hook in registry
        {
            let registry = HOOK_REGISTRY.lock().unwrap();
            let found = registry
                .active
                .iter()
                .any(|((t, _), desc)| *t == tid as usize && desc.target_address == Some(fake_target as usize));

            assert!(
                found,
                "Expected propagated HWBP for new thread {}, but none found in registry",
                tid
            );
        }

        uninstall_all_hwbp().expect("Failed to uninstall hooks after test");

        worker.thread().unpark();
    }
}
