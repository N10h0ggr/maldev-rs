pub mod hash;

use std::arch::asm;
use windows::Win32::System::Threading::{PEB, PEB_LDR_DATA, TEB};
use std::ptr;
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use std::ffi::CStr;
use std::slice;
use windows::core::{PCSTR, PWSTR};

#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    (*teb).ProcessEnvironmentBlock
}

/// Retrieves the module handle for a given DLL name.
///
/// # Arguments
/// * `dll_name` - The name of the DLL for which to get the module handle.
///
/// # Returns
/// * `Option<*const u8>` - The pointer of the module if found, or `None` if not found.
unsafe fn get_module_handle(module_name: &str) -> Option<*const u8> {
    let ws_module_name = PWSTR(module_name.as_ptr() as *mut u16);
    let mut peb: *const PEB = get_peb();
    let mut p_ldr: *const PEB_LDR_DATA = (*peb).Ldr;
    let mut p_dte: *const LDR_DATA_TABLE_ENTRY = (*p_ldr).InMemoryOrderModuleList.Flink as _;

    while let Some(p_dte_ref) = p_dte.as_ref() {
        if !p_dte_ref.FullDllName.Buffer.is_null() {
            // Check if the module names match
            if p_dte_ref.FullDllName.Buffer == ws_module_name {
                // Print the name of the found DLL
                println!("[+] Found Dll \"{:?}\"", p_dte_ref.FullDllName.Buffer);
                return Some(p_dte_ref.Reserved2[0] as *const u8);
            }
        } else { break; }
        // Next element in the linked list
        p_dte = p_dte_ref.InMemoryOrderLinks.Flink as *const _ ;
    }
    None
}

/// Retrieves the NT headers for a given module handle.
///
/// # Arguments
/// * `module_handle` - The handle of the module for which to get the NT headers.
///
/// # Returns
/// * `*mut IMAGE_NT_HEADERS` - A pointer to the NT headers of the module, or `ptr::null_mut()` if invalid.
unsafe fn get_nt_headers(module_handle: HMODULE) -> *mut IMAGE_NT_HEADERS64 {
    let dos_header = module_handle.0 as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D { // Check for 'MZ' magic number
        return ptr::null_mut();
    }
    let nt_headers = (module_handle.0 as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != 0x00004550 { // Check for 'PE\0\0' signature
        return ptr::null_mut();
    }
    nt_headers
}

/// Retrieves the export directory for a given module handle.
///
/// # Arguments
/// * `module_handle` - The handle of the module for which to get the export directory.
///
/// # Returns
/// * `Option<*const IMAGE_EXPORT_DIRECTORY>` - A pointer to the export directory, or `None` if not found.
unsafe fn get_export_directory(module_handle: HMODULE) -> Option<*const IMAGE_EXPORT_DIRECTORY> {
    let nt_headers = get_nt_headers(module_handle);
    if nt_headers.is_null() {
        return None;
    }
    let export_directory_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_directory_rva == 0 {
        return None;
    }
    Some((module_handle.0 as usize + export_directory_rva as usize) as *const IMAGE_EXPORT_DIRECTORY)
}

/// Retrieves the names of all exported functions from a given DLL.
///
/// # Arguments
/// * `dll_name` - The name of the DLL from which to retrieve the exported functions.
///
/// # Returns
/// * `Vec<String>` - A vector containing the names of all exported functions.
pub unsafe fn get_exported_functions(dll_name: &str) -> Vec<String> {
    let mut exported_functions = Vec::new();

    if let Some(module_handle) = get_module_handle(dll_name) {
        if let Some(export_directory) = get_export_directory(module_handle) {
            let base_address = module_handle.0 as usize;
            let names_rva = (*export_directory).AddressOfNames;
            let names_count = (*export_directory).NumberOfNames;

            let names = slice::from_raw_parts((base_address + names_rva as usize) as *const u32, names_count as usize);
            for i in 0..names_count {
                let name_ptr = (base_address + names[i as usize] as usize) as *const i8;
                let function_name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
                exported_functions.push(function_name);
            }
        }
    }

    exported_functions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_exported_functions() {
        unsafe {
            let dll_name = "C:\\Windows\\System32\\kernel32.dll";
            let exported_functions = get_exported_functions(dll_name);
            assert!(!exported_functions.is_empty());
            println!("{:?}", exported_functions);
        }
    }
}