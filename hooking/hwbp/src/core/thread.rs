use crate::utils::error::HwbpError;
use crate::utils::types::SystemProcessInformation;
use log::{debug, error, trace};
use std::ffi::c_void;
use windows_sys::Wdk::System::SystemInformation::SYSTEM_INFORMATION_CLASS;
use windows_sys::Win32::{
    Foundation::{GetLastError, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS},
    System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Threading::GetCurrentProcessId,
    },
};
use windows_sys::s;

/// Enumerates all thread IDs belonging to the **current process**.
///
/// This function uses the `NtQuerySystemInformation` syscall to fetch
/// a snapshot of all system processes and their threads, then filters
/// out only those threads owned by the current process.
///
/// # Return
/// - `Ok(Vec<usize>)` containing the TIDs of all threads in this process.
/// - `Err(HwbpError)` if enumeration fails.
///
/// # Safety
/// Uses raw Windows syscalls and pointer arithmetic. All unsafe operations
/// are localized and bounds-checked.
pub fn enum_threads_ntquery() -> std::result::Result<Vec<usize>, HwbpError> {
    unsafe {
        // Load NtQuerySystemInformation dynamically
        let lpmodulename = s!("ntdll.dll");
        let lpprocname = s!("NtQuerySystemInformation");
        let h_ntdll = GetModuleHandleA(lpmodulename);
        if h_ntdll.is_null() {
            let code = GetLastError();
            error!("GetModuleHandleA failed with code {}", code);
            return Err(HwbpError::ThreadEnumerationFailed);
        }

        let proc_addr = GetProcAddress(h_ntdll, lpprocname);
        if proc_addr.is_none() {
            let code = GetLastError();
            error!(
                "GetProcAddress(NtQuerySystemInformation) failed with code {}",
                code
            );
            return Err(HwbpError::ThreadEnumerationFailed);
        }

        type NtQuerySystemInformationFn = unsafe extern "system" fn(
            system_information_class: SYSTEM_INFORMATION_CLASS,
            system_information: *mut c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;

        let fn_nt_query_system_information: NtQuerySystemInformationFn =
            std::mem::transmute(proc_addr);

        // First call to get buffer size
        let mut buffer_size = 0u32;
        let system_process_information = 5 as SYSTEM_INFORMATION_CLASS;
        let nt_status = fn_nt_query_system_information(
            system_process_information,
            std::ptr::null_mut(),
            0,
            &mut buffer_size as *mut _,
        );

        if nt_status != STATUS_SUCCESS && nt_status != STATUS_INFO_LENGTH_MISMATCH {
            error!(
                "NtQuerySystemInformation (initial) failed: NTSTATUS=0x{:08X}",
                nt_status
            );
            return Err(HwbpError::ThreadEnumerationFailed);
        }

        // Allocate buffer for SYSTEM_PROCESS_INFORMATION array
        let mut buffer = vec![0u8; buffer_size as usize];
        let mut return_len = 0u32;
        let nt_status = fn_nt_query_system_information(
            system_process_information,
            buffer.as_mut_ptr() as *mut _,
            buffer_size,
            &mut return_len as *mut _,
        );

        if nt_status != STATUS_SUCCESS {
            error!(
                "NtQuerySystemInformation (final) failed: NTSTATUS=0x{:08X}",
                nt_status
            );
            return Err(HwbpError::ThreadEnumerationFailed);
        }

        // Parse the buffer as a linked list of SYSTEM_PROCESS_INFORMATION structs
        let current_pid = GetCurrentProcessId();
        let mut process_info = buffer.as_ptr() as *const SystemProcessInformation;
        let mut thread_ids = Vec::new();

        loop {
            let entry = &*process_info;

            if entry.unique_process_id as u32 == current_pid {
                trace!(
                    "Found current process (PID={}) with {} threads",
                    current_pid, entry.number_of_threads
                );
                let threads_ptr = entry.threads.as_ptr();
                for i in 0..entry.number_of_threads as usize {
                    let tid = (*threads_ptr.add(i)).client_id.unique_thread as usize;
                    thread_ids.push(tid);
                }
                break;
            }

            if entry.next_entry_offset == 0 {
                break;
            }

            process_info = (process_info as *const u8).add(entry.next_entry_offset as usize)
                as *const SystemProcessInformation;
        }

        debug!(
            "Thread enumeration complete — found {} threads for PID {}",
            thread_ids.len(),
            current_pid
        );

        Ok(thread_ids)
    }
}
