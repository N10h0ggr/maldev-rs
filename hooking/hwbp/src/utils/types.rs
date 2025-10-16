use std::ffi::c_void;

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
