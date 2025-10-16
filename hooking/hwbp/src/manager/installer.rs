use core::ffi::c_void;
use log::{debug, error, info, trace, warn};

use crate::core::breakpoint::{clear_hardware_breakpoint, set_hardware_breakpoint};
use crate::core::thread::enum_threads_ntquery;
use crate::manager::hook_registry::HOOK_REGISTRY;
use crate::utils::error::HwbpError;
use crate::utils::types::{DrRegister, HookDescriptor};

/// Installs a hardware breakpoint (HWBP) hook for **all existing threads**
/// in the current process.
///
/// This function enumerates all active threads and attempts to install
/// a hardware breakpoint in each, automatically choosing a free debug
/// register (Dr0–Dr3). Each successfully installed breakpoint is recorded
/// in the global `HOOK_REGISTRY`.
///
/// # Parameters
/// - `address`: Pointer to the target instruction or function to monitor.
/// - `detour`: Pointer to the detour (callback) function that will be called
///   when the breakpoint triggers.
///
/// # Returns
/// - `Ok(())` if all breakpoints were installed successfully.
/// - `Err(HwbpError)` if enumeration, registry access, or installation fails.
///
/// # Errors
/// - [`HwbpError::NullPointer`] if either pointer is null.
/// - [`HwbpError::ThreadEnumerationFailed`] if thread listing fails.
/// - [`HwbpError::RegistryPoisoned`] if the global registry mutex is poisoned.
/// - [`HwbpError::InstallFailed`] if any breakpoint installation fails.
///
/// # Safety
/// This function modifies thread contexts using `SetThreadContext`.
/// All unsafe operations are contained and checked for success.
pub fn install_hook_all_threads(
    address: *const c_void,
    detour: *const c_void,
) -> std::result::Result<(), HwbpError> {
    // Validate pointers
    if address.is_null() {
        return Err(HwbpError::NullPointer { what: "address" });
    }
    if detour.is_null() {
        return Err(HwbpError::NullPointer { what: "detour" });
    }

    info!("Installing HWBP on all threads for address {:p}", address);

    // Enumerate all threads in this process
    let threads = enum_threads_ntquery().map_err(|_| HwbpError::ThreadEnumerationFailed)?;

    if threads.is_empty() {
        warn!("No threads found for current process.");
        return Err(HwbpError::ThreadEnumerationFailed);
    }

    trace!("Found {} threads to install HWBP.", threads.len());

    for tid in threads {
        let free_drx = {
            // Lock the global hook registry
            let registry = HOOK_REGISTRY
                .lock()
                .map_err(|_| HwbpError::RegistryPoisoned)?;

            // Find a free DRx register for this thread
            registry.find_free_drx_for_thread(tid)

        }; // free the registry mutex via RAII

        let Some(drx) = free_drx else {
            warn!(
                "No free DRx register available for thread {} — skipping.",
                tid
            );
            continue;
        };

        debug!("Installing HWBP on thread {} using {:?}", tid, drx);


        // Attempt to install the HWBP
        let result = set_hardware_breakpoint(tid, address, detour, drx);
        if let Err(e) = result {
            error!(
                "Failed to install HWBP on thread {} ({:?}): {:?}",
                tid, drx, e
            );
            return Err(HwbpError::InstallFailed);
        }

        // Add this hook to the registry
        let descriptor = HookDescriptor {
            thread_id: Some(tid),
            target_address: Some(address as usize),
            detour_address: Some(detour as usize),
            register: Some(drx),
            state: crate::utils::types::BreakpointState::Active,
        };

        {
            let mut registry = HOOK_REGISTRY
                .lock()
                .map_err(|_| HwbpError::RegistryPoisoned)?;

            registry.insert(tid, drx, descriptor);
        } // free the registry mutex via RAII
    }

    info!("Successfully installed HWBP on all available threads.");
    Ok(())
}

/// Uninstalls a hardware breakpoint (HWBP) hook from **all threads** that currently
/// have it installed.
///
/// This function iterates through all threads of the current process and attempts
/// to clear any hardware breakpoints whose `target_address` matches the given one.
/// The corresponding entries are also removed from the global [`HOOK_REGISTRY`].
///
/// # Parameters
/// - `address`: Pointer to the hooked target function or instruction.
///
/// # Returns
/// - `Ok(())` if all breakpoints were removed successfully.
/// - `Err(HwbpError)` if enumeration, context modification, or registry access fails.
///
/// # Errors
/// - [`HwbpError::NullPointer`] if `address` is null.
/// - [`HwbpError::ThreadEnumerationFailed`] if thread enumeration fails.
/// - [`HwbpError::RegistryPoisoned`] if the global registry mutex is poisoned.
/// - [`HwbpError::RemoveFailed`] if one or more threads failed to uninstall the hook.
pub fn uninstall_hook_all_threads(address: *const c_void) -> std::result::Result<(), HwbpError> {
    if address.is_null() {
        return Err(HwbpError::NullPointer { what: "address" });
    }

    info!("Uninstalling HWBP for all threads on target {:p}", address);

    // Enumerate all threads in the process
    let threads = enum_threads_ntquery().map_err(|_| HwbpError::ThreadEnumerationFailed)?;

    if threads.is_empty() {
        warn!("No threads found in current process.");
        return Err(HwbpError::ThreadEnumerationFailed);
    }

    trace!("Found {} threads for HWBP removal.", threads.len());

    let mut failures = 0usize;

    // For each thread, check if there’s a hook matching address
    for tid in threads {
        let regs_to_clear: Vec<DrRegister> = {
            // Acquire registry lock
            let registry = HOOK_REGISTRY
                .lock()
                .map_err(|_| HwbpError::RegistryPoisoned)?;

            // Collect the DrRegisters that correspond to the given target
            registry
            .filter_by_thread(tid)
            .filter_map(|(drx, desc)| {
                if desc.target_address == Some(address as usize) {
                    Some(drx)
                } else {
                    None
                }
            })
            .collect()
        }; // free registry via RAII

        if regs_to_clear.is_empty() {
            continue;
        }

        debug!(
            "Thread {} has {} HWBP(s) for {:p} — removing.",
            tid,
            regs_to_clear.len(),
            address
        );

        // Attempt to clear each matching HWBP
        for drx in regs_to_clear {
            match clear_hardware_breakpoint(tid, drx) {
                Ok(_) => {
                    let mut registry = HOOK_REGISTRY
                        .lock()
                        .map_err(|_| HwbpError::RegistryPoisoned)?;
                    registry.active.remove(&(tid, drx));
                    trace!("Removed HWBP from thread {} register {:?}", tid, drx);
                }
                Err(e) => {
                    error!(
                        "Failed to clear HWBP on thread {} ({:?}): {:?}",
                        tid, drx, e
                    );
                    failures += 1;
                }
            }
        }
    }

    if failures > 0 {
        warn!(
            "{} thread(s) failed to remove HWBP for target {:p}",
            failures, address
        );
        return Err(HwbpError::RemoveFailed);
    }

    info!(
        "Successfully uninstalled HWBP for all threads on {:p}",
        address
    );
    Ok(())
}
