use log::{debug, warn};
use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{LazyLock, Mutex},
};

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

/// Represents the available hardware debug registers (Dr0–Dr3).
/// Each one can hold a hardware breakpoint address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrRegister {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

impl DrRegister {
    /// Returns the numeric index of the register (Dr0 = 0, Dr1 = 1, ...).
    #[inline]
    pub const fn index(&self) -> u8 {
        match self {
            DrRegister::Dr0 => 0,
            DrRegister::Dr1 => 1,
            DrRegister::Dr2 => 2,
            DrRegister::Dr3 => 3,
        }
    }

    /// Converts an index (0–3) into a DrRegister.
    #[inline]
    pub const fn from_index(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(DrRegister::Dr0),
            1 => Some(DrRegister::Dr1),
            2 => Some(DrRegister::Dr2),
            3 => Some(DrRegister::Dr3),
            _ => None,
        }
    }
}

/// Represents the current state of a hardware breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointState {
    /// The breakpoint is currently active and enabled in Dr7.
    Active,

    /// The breakpoint exists but is temporarily disabled.
    Disabled,

    /// The breakpoint slot is free (no address assigned).
    Free,
}

/// Describes a single hardware breakpoint (hook) installed on a thread.
///
/// Each `HookDescriptor` tracks which address is being monitored,
/// which detour function should be called, which register (Dr0–Dr3)
/// is used, and which thread owns it.
#[derive(Debug, Clone)]
pub struct HookDescriptor {
    /// The address of the target function being hooked.
    pub target_address: Option<usize>,

    /// The address of the detour (callback) function.
    pub detour_address: Option<usize>,

    /// Which debug register (Dr0–Dr3) is used for this hook.
    pub register: Option<DrRegister>,

    /// The current operational state of the breakpoint.
    pub state: BreakpointState,

    /// The thread ID that owns this hook (breakpoints are per-thread).
    pub thread_id: Option<usize>,
}

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
        use DrRegister::*;

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

use windows_sys::Win32::Foundation::{HANDLE, UNICODE_STRING};

/// LARGE_INTEGER (QuadPart) as a plain 64-bit signed integer.
pub type LargeInteger = i64;

#[repr(C)]
pub struct ClientId {
    pub unique_process: HANDLE,
    pub unique_thread: HANDLE,
}

#[repr(C)]
pub struct SystemThreadInformation {
    pub kernel_time: LargeInteger,
    pub user_time: LargeInteger,
    pub create_time: LargeInteger,
    pub wait_time: u32,
    pub start_address: *mut c_void,
    pub client_id: ClientId,
    pub priority: i32,      // KPRIORITY (LONG)
    pub base_priority: i32, // KPRIORITY (LONG)
    pub context_switches: u32,
    pub thread_state: i32, // KTHREAD_STATE
    pub wait_reason: i32,  // KWAIT_REASON
}

#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32, // size of `threads`
    pub working_set_private_size: LargeInteger,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: LargeInteger,
    pub user_time: LargeInteger,
    pub kernel_time: LargeInteger,
    pub image_name: UNICODE_STRING,
    pub base_priority: i32, // KPRIORITY (LONG)
    pub unique_process_id: HANDLE,
    pub inherited_from_unique_process_id: HANDLE,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize, // ULONG_PTR
    pub peak_virtual_size: usize,  // SIZE_T
    pub virtual_size: usize,       // SIZE_T
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,           // SIZE_T
    pub working_set_size: usize,                // SIZE_T
    pub quota_peak_paged_pool_usage: usize,     // SIZE_T
    pub quota_paged_pool_usage: usize,          // SIZE_T
    pub quota_peak_non_paged_pool_usage: usize, // SIZE_T
    pub quota_non_paged_pool_usage: usize,      // SIZE_T
    pub pagefile_usage: usize,                  // SIZE_T
    pub peak_pagefile_usage: usize,             // SIZE_T
    pub private_page_count: usize,              // SIZE_T
    pub read_operation_count: LargeInteger,
    pub write_operation_count: LargeInteger,
    pub other_operation_count: LargeInteger,
    pub read_transfer_count: LargeInteger,
    pub write_transfer_count: LargeInteger,
    pub other_transfer_count: LargeInteger,
    pub threads: [SystemThreadInformation; 1], // flexible array tail
}
