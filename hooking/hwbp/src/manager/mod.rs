mod hook_registry;
mod installer;

use core::ffi::c_void;
use log::{debug, error, info, trace, warn};

use crate::core::breakpoint::clear_hardware_breakpoint;
use crate::core::veh;
use crate::manager::installer::uninstall_hook_all_threads;
use crate::utils::error::HwbpError;
use crate::utils::types::{DrRegister, HOOK_REGISTRY};

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
    env_logger::init();

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

    // Install on all existing threads
    installer::install_hook_all_threads(address, detour)?;

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
