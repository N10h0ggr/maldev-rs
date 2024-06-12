mod asm;
pub use asm::run_syscall;

use windows;
use std::collections::HashMap;
use utils::{get_dll_exported_functions_by_hash, get_export_directory};
use utils::hash::{FastCrc32};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Threading::PEB;
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

const NT_DLL_CRC32: u32 = 0x6030EF91u32;

#[repr(C)]
#[derive(Debug)]
struct NtdllConfig {
    pdw_array_of_addresses: *mut u32, // The VA of the array of addresses of ntdll's exported functions   [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    pdw_array_of_names: *mut u32,     // The VA of the array of names of ntdll's exported functions       [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    pw_array_of_ordinals: *mut u16,   // The VA of the array of ordinals of ntdll's exported functions    [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
    dw_number_of_names: u32,          // The number of exported functions from ntdll.dll                 [IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    u_module: usize,                  // The base address of ntdll - required to calculate future RVAs   [BaseAddress]
}
type PNtdllConfig = *mut NtdllConfig;

impl NtdllConfig {
    pub fn new() -> Option<Self> {
        unsafe {
            // Getting PEB
            let p_peb: *mut PEB = utils::get_peb();
            if p_peb.is_null() { // || (*p_peb).OSMajorVersion != 0xA
                return None;
            }

            // Getting ntdll.dll module
            let p_ldr_data = (*(*p_peb).Ldr).InMemoryOrderModuleList.Flink;
            let p_ldr = ((*p_ldr_data).Flink as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY; //skip local image element
            let u_module = (*p_ldr).DllBase as usize;
            if u_module == 0 {
                return None;
            }

            // Fetching the export directory of ntdll
            let h_module = HMODULE(u_module as isize);
            let p_img_exp_dir = get_export_directory(h_module)?;

            // Initializing the NtdllConfig struct
            let config = NtdllConfig {
                u_module,
                dw_number_of_names: (*p_img_exp_dir).NumberOfNames,
                pdw_array_of_names: (u_module + (*p_img_exp_dir).AddressOfNames as usize) as *mut u32,
                pdw_array_of_addresses: (u_module + (*p_img_exp_dir).AddressOfFunctions as usize) as *mut u32,
                pw_array_of_ordinals: (u_module + (*p_img_exp_dir).AddressOfNameOrdinals as usize) as *mut u16,
            };

            // Checking
            if config.u_module == 0 || config.dw_number_of_names == 0 || config.pdw_array_of_names.is_null() || config.pdw_array_of_addresses.is_null() || config.pw_array_of_ordinals.is_null() {
                None
            } else {
                Some(config)
            }
        }
    }
}

pub unsafe fn prepare_syscall(hash: u32){
    // Initialize ntdll if not already initialized
    // FetchNtSyscall already part of direct syscall? -> Initialize
    //
}

#[test]
fn test_direct_syscall() {
    match NtdllConfig::new() {
        Some(config) => println!("NtdllConfig initialized: {:?}", config),
        None => println!("Failed to initialize NtdllConfig"),
    }
}

unsafe fn crawl_nt_dll(){
    let mut syscalls = HashMap::new();
    let crc32 = FastCrc32::new();

    // This is a placeholder for the actual enumeration and hashing logic
    // Fill syscalls with NtSyscall structs
    // 1. fetches all the exported functions from ntdll.dll
    let exported_functions = get_dll_exported_functions_by_hash(NT_DLL_CRC32 as usize);
    // . computes the hashes for the name functions
    // . creates an entry for the NtApiFunc
    for function in exported_functions {
        let hash = crc32.compute_hash(function.to_uppercase().as_bytes());
        syscalls.insert(hash, Syscall { ssn: 0, p_syscall_address: 0});
    }
}



struct Syscall {
    pub ssn: u8, // The syscall number
    pub p_syscall_address: u8, // The address of the syscall
}

pub struct NtApiFunc {
    syscalls: HashMap<u32, Syscall>, // crc32 hash, NtSyscall
}


/*pub unsafe fn new() -> Self {


    NtApiFunc { syscalls }
}

pub fn get_function_ssn(function_hash: u32) -> Option<u8>
{
    syscalls.get(&function_hash).map(|syscall| syscall.ssn)
}

pub fn get_function_syscall_address(function_hash: u32) -> Option<u8>
{
    syscalls.get(&function_hash).map(|syscall| syscall.p_syscall_address)
}*/
