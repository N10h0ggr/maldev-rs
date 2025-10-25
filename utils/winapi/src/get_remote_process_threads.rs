//! Enumerates process threads using `NtQuerySystemInformation(SystemProcessInformation)`.
//! This avoids the Toolhelp API layer but depends on undocumented Windows structures.
//! Use with caution: structure layouts may change, and user-mode hooks can still apply.

use windows_sys::Wdk::System::SystemInformation::SYSTEM_INFORMATION_CLASS;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::STATUS_INFO_LENGTH_MISMATCH;
use windows_sys::Win32::Foundation::STATUS_SUCCESS;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
use windows_sys::s;

use crate::structs::SystemProcessInformation;

use hashing::unicode_string_to_string;

/// Retrieves the process ID (PID) and main thread ID (TID) for the specified process name.
///
/// # Arguments
/// * `proc_name`: String - The Unicode process name to search for (e.g., `"notepad.exe"`).
///
/// # Returns
/// * `Ok((pid, tid))` if the target process is found.
/// * `Err(String)` if the process cannot be found or a query error occurs.
///
/// # Safety
/// This function relies on FFI calls to `NtQuerySystemInformation` and undocumented
/// Windows internals. Incorrect structure definitions or buffer handling can cause
/// undefined behavior. Validate all pointers, lengths, and return codes.
pub fn get_remote_process_threads(proc_name: String) -> Result<(usize, usize), String> {
    // fetch NtQuerySystemInformation address from ntdll
    let lpmodulename = s!("ntdll.dll");
    let lpprocname = s!("NtQuerySystemInformation");
    let h_ntdll = unsafe { GetModuleHandleA(lpmodulename) };
    let mut option_nt_query_system_information = unsafe { GetProcAddress(h_ntdll, lpprocname) };

    let p_nt_query_system_information =
        option_nt_query_system_information.take().ok_or_else(|| {
            format!("GetProcAddress Failed with error: {}", unsafe {
                GetLastError()
            })
        })?;

    // Declare the function type to be able to pass parameters and cast type to it
    type NtQuerySystemInformationFn = unsafe extern "system" fn(
        system_information_class: SYSTEM_INFORMATION_CLASS,
        system_information: *mut core::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32; // NTSTATUS
    let fn_nt_query_system_information: NtQuerySystemInformationFn =
        unsafe { std::mem::transmute(p_nt_query_system_information) };

    // Get the required buffer size for NtQuerySystemInformation
    let mut buffer_size = 0u32;
    let system_process_information = 5 as SYSTEM_INFORMATION_CLASS;
    let nt_status = unsafe {
        fn_nt_query_system_information(
            system_process_information,
            core::ptr::null_mut(),
            0,
            &mut buffer_size as *mut _,
        )
    };
    if nt_status != STATUS_SUCCESS && nt_status != STATUS_INFO_LENGTH_MISMATCH {
        return Err(format!(
            "(first) NtQuerySystemInformation failed: NTSTATUS=0x{:08X}",
            nt_status
        ));
    };

    // Get the SYSTEM_PROCESS_INFORMATION array
    let mut system_proc_info_buffer = vec![0u8; buffer_size as usize];
    let mut new_buffer_size = 0u32;
    let nt_status = unsafe {
        fn_nt_query_system_information(
            system_process_information,
            system_proc_info_buffer.as_mut_ptr() as *mut _,
            buffer_size,
            &mut new_buffer_size as *mut _,
        )
    };
    if nt_status != STATUS_SUCCESS {
        return Err(format!(
            "(second) NtQuerySystemInformation failed: NTSTATUS=0x{:08X}",
            nt_status
        ));
    }
    // Recast the buffer to our struct type
    let mut system_proc_info = system_proc_info_buffer.as_ptr() as *const SystemProcessInformation;

    // Search for target process name
    let mut pid: usize = 0;
    let mut tid: usize = 0;
    loop {
        let entry = unsafe { &*system_proc_info };
        if entry.image_name.Length != 0 {
            let s_image_name = unsafe { unicode_string_to_string(&entry.image_name) };
            if s_image_name == proc_name {
                pid = entry.unique_process_id as usize;
                tid = entry.threads[0].client_id.unique_thread as usize;
                break;
            }
        }
        // Move pointer to next element
        system_proc_info = unsafe {
            (system_proc_info as *const u8).add(entry.next_entry_offset as usize)
                as *const SystemProcessInformation
        };
    }

    Ok((pid, tid))
}

#[cfg(test)]
mod tests {
    use super::*;

    // cargo test test_find_system_process -- --nocapture
    #[test]
    #[cfg(target_os = "windows")]
    fn test_find_system_process() {
        let result = get_remote_process_threads("nvim.exe".to_string());
        match result {
            Ok((pid, tid)) => {
                println!("Found: PID={} TID={}", pid, tid);
                assert!(pid > 0);
                assert!(tid > 0);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                panic!("Failed with error: {}", e);
            }
        }
    }
}
