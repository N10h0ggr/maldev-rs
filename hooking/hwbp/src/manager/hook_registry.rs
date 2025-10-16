use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use log::{debug, warn};
use crate::utils::types::{DrRegister, HookDescriptor};

/// Global registry tracking all hardware breakpoints (hooks) across threads.
///
/// This singleton holds a thread-safe `HookRegistry` that maps thread IDs
/// to their corresponding `ThreadHookContext`. It allows installing,
/// removing, and inspecting hardware breakpoints globally.
///
/// Access is synchronized using a `Mutex`, so operations on the registry
/// must lock it before modification can
/// ```ignore
/// let mut registry = HOOK_REGISTRY.lock().unwrap();
/// ```
pub static HOOK_REGISTRY: LazyLock<Mutex<HookRegistry>> =
    LazyLock::new(|| Mutex::new(HookRegistry::default()));

/// Global registry of all active hardware breakpoints (hooks) across threads.
///
/// This structure maintains a flat mapping of `(thread_id, DrRegister)` → [`HookDescriptor`].
/// Each entry uniquely identifies a single hardware breakpoint bound to a specific
/// thread and debug register (Dr0–Dr3).
///
/// - The key is a tuple `(usize, DrRegister)`, where:
///   - `usize` is the **thread ID** owning the breakpoint.
///   - [`DrRegister`] indicates which debug register (Dr0–Dr3) is used.
/// - The value is a [`HookDescriptor`] describing the breakpoint (target, detour, state, etc.).
///
/// This design simplifies global lookups (e.g. checking if any thread uses Dr0),
/// while still allowing efficient filtering per thread.
#[derive(Debug, Default)]
pub struct HookRegistry {
    /// Flat mapping of `(thread_id, DrRegister)` to an active [`HookDescriptor`].
    pub active: HashMap<(usize, DrRegister), HookDescriptor>,

    /// Handle returned by AddVectoredExceptionHandler encoded as usize.
    /// None = VEH not registered.
    pub veh_handle: Option<usize>,
}

impl HookRegistry {
    /// Finds the first available (unused) debug register (Dr0–Dr3)
    /// for the given thread ID.
    ///
    /// The search order is Dr0 → Dr1 → Dr2 → Dr3.
    ///
    /// # Parameters
    /// - `thread_id`: The thread ID to search available registers for.
    ///
    /// # Returns
    /// - `Some(DrRegister)` if a free register is found.
    /// - `None` if all registers are already used for this thread.
    pub fn find_free_drx_for_thread(&self, thread_id: usize) -> Option<DrRegister> {
        use log::{debug, warn};
        use crate::utils::types::DrRegister::*;

        for reg in [Dr0, Dr1, Dr2, Dr3] {
            if !self.active.contains_key(&(thread_id, reg)) {
                debug!("Found free DRx register {:?} for thread {}", reg, thread_id);
                return Some(reg);
            }
        }

        warn!(
            "No free DRx registers available for thread {} — all in use.",
            thread_id
        );
        None
    }

    /// Inserts a new hardware-breakpoint descriptor into the registry.
    ///
    /// If an entry for the same `(thread_id, DrRegister)` already exists,
    /// the existing entry is replaced, and a warning is logged.
    ///
    /// # Parameters
    /// - `thread_id`: Thread owning this hardware breakpoint.
    /// - `reg`: Debug register used (Dr0–Dr3).
    /// - `descriptor`: The [`HookDescriptor`] containing breakpoint metadata.
    pub fn insert(&mut self, thread_id: usize, reg: DrRegister, descriptor: HookDescriptor) {
        if self.active.contains_key(&(thread_id, reg)) {
            warn!(
                "Replacing existing HWBP entry for thread {} register {:?}",
                thread_id, reg
            );
        }

        debug!(
            "Registering HWBP in registry: TID={} DR={:?} Target=0x{:X} Detour=0x{:X}",
            thread_id,
            reg,
            descriptor.target_address.unwrap_or(0),
            descriptor.detour_address.unwrap_or(0)
        );

        self.active.insert((thread_id, reg), descriptor);
    }

    /// Checks if a specific (thread_id, DrRegister) combination is present in the registry.
    ///
    /// Returns true if that specific hardware breakpoint is currently active.
    #[inline]
    pub fn contains(&self, thread_id: usize, reg: DrRegister) -> bool {
        self.active.contains_key(&(thread_id, reg))
    }

    /// Returns all active hooks for a given thread as an iterator of (DrRegister, &HookDescriptor).
    ///
    /// This allows you to easily enumerate or filter all hardware breakpoints
    /// associated with a single thread.
    pub fn filter_by_thread(
        &self,
        thread_id: usize,
    ) -> impl Iterator<Item = (DrRegister, &HookDescriptor)> {
        self.active.iter().filter_map(move |(key, desc)| {
            let (tid, reg) = *key;
            if tid == thread_id {
                Some((reg, desc))
            } else {
                None
            }
        })
    }

    /// Returns the number of active hooks currently installed for a specific thread.
    #[inline]
    pub fn count_for_thread(&self, thread_id: usize) -> usize {
        self.active
            .keys()
            .filter(|(tid, _)| *tid == thread_id)
            .count()
    }
}