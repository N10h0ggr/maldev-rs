use core::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, UNICODE_STRING};

pub const RTL_MAX_DRIVE_LETTERS: usize = 32;

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

#[repr(C)]
pub struct RtlUserProcessParameters {
    pub maximum_length: u32,
    pub length: u32,

    pub flags: u32,
    pub debug_flags: u32,

    pub console_handle: HANDLE,
    pub console_flags: u32,
    pub standard_input: HANDLE,
    pub standard_output: HANDLE,
    pub standard_error: HANDLE,

    pub current_directory: CurDir,
    pub dll_path: UNICODE_STRING,
    pub image_path_name: UNICODE_STRING,
    pub command_line: UNICODE_STRING,
    pub environment: *mut core::ffi::c_void,

    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,

    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: UNICODE_STRING,
    pub desktop_info: UNICODE_STRING,
    pub shell_info: UNICODE_STRING,
    pub runtime_data: UNICODE_STRING,
    pub current_directories: [RtlDriveLetterCurDir; RTL_MAX_DRIVE_LETTERS],

    pub environment_size: usize,
    pub environment_version: usize,

    pub package_dependency_data: *mut core::ffi::c_void,
    pub process_group_id: u32,
    pub loader_threads: u32,

    pub redirection_dll_name: UNICODE_STRING,
    pub heap_partition_name: UNICODE_STRING,
    pub default_threadpool_cpu_set_masks: usize,
    pub default_threadpool_cpu_set_mask_count: u32,
    pub default_threadpool_thread_maximum: u32,
    pub heap_memory_type_mask: u32,
}

#[repr(C)]
pub struct CurDir {
    pub dos_path: UNICODE_STRING,
    pub handle: HANDLE,
}

#[repr(C)]
pub struct RtlDriveLetterCurDir {
    pub flags: u16,
    pub length: u16,
    pub time_stamp: u32,
    pub dos_path: UNICODE_STRING,
}
