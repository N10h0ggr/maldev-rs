use windows;
use std::ffi::c_void;
use std::{ptr};
use utils::{get_export_directory};
use utils::hash::{compute_crc32_hash};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Threading::PEB;
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;

const UP: isize = -32;
const DOWN: isize = 32;
const RANGE: u16 = 0xFF;

#[repr(C)]
#[derive(Debug)]
struct NtdllConfig {
    pdw_array_of_addresses: *mut u32, // The VA of the array of addresses of ntdll's exported functions   [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    pdw_array_of_names: *mut u32,     // The VA of the array of names of ntdll's exported functions       [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    pw_array_of_ordinals: *mut u16,   // The VA of the array of ordinals of ntdll's exported functions    [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
    dw_number_of_names: u32,          // The number of exported functions from ntdll.dll                 [IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    u_module: usize,                  // The base address of ntdll - required to calculate future RVAs   [BaseAddress]
}
static mut G_NTDLL_CONF: NtdllConfig = NtdllConfig {
    pdw_array_of_addresses: ptr::null_mut(),
    pdw_array_of_names: ptr::null_mut(),
    pw_array_of_ordinals: ptr::null_mut(),
    dw_number_of_names: 0,
    u_module: 0,
};

#[repr(C)]
#[derive(Clone)]
pub struct NtSyscall {
    pub dw_ssn: u32,
    pub dw_syscall_hash: u32,
    pub p_syscall_address: *mut c_void,
}
static mut SYSCALL_CACHE: Vec<NtSyscall> = Vec::new();

/// Initializes the `NtdllConfig` structure with data from the ntdll.dll module.
///
/// This function retrieves the Process Environment Block (PEB) and uses it to find the
/// `ntdll.dll` module. It then fetches the export directory of `ntdll.dll` and initializes
/// the `NtdllConfig` structure with relevant information such as the module base address,
/// the number of exported names, and pointers to arrays of names, addresses, and ordinals.
///
/// # Returns
/// * `Ok(NtdllConfig)` - If the initialization is successful with all required fields populated.
/// * `Err(&'static str)` - If there is an error during the initialization, such as a null pointer
///   being encountered or any field failing to be correctly initialized.
///
/// # Errors
/// The function returns the following errors:
/// * `"init_ntdll_config_structure: PEB is null"` - If the PEB is null.
/// * `"init_ntdll_config_structure: module is null"` - If the module base address is null.
/// * `"Failed to get export directory"` - If the export directory cannot be fetched.
/// * `"init_ntdll_config_structure: One of the parameters is null"` - If any of the parameters in
///   the `NtdllConfig` structure are null after initialization.

unsafe fn init_ntdll_config_structure() -> Result<NtdllConfig, &'static str> {
    // Getting PEB
    let p_peb: *mut PEB = utils::get_peb();
    if p_peb.is_null() { // || (*p_peb).OSMajorVersion != 0xA
        return Err("init_ntdll_config_structure: PEB is null");
    }

    // Getting ntdll.dll module
    let p_ldr_data = (*(*p_peb).Ldr).InMemoryOrderModuleList.Flink;
    let p_ldr = ((*p_ldr_data).Flink as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY; //skip local image element
    let u_module = (*p_ldr).DllBase as usize;
    if u_module == 0 {
        return Err("init_ntdll_config_structure: module is null");
    }

    // Fetching the export directory of ntdll
    let h_module = HMODULE(u_module as isize);
    let p_img_exp_dir = get_export_directory(h_module).ok_or("Failed to get export directory")?;

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
        Err("init_ntdll_config_structure: One of the parameters is null")
    } else {
        Ok(config)
    }
}

/// Fetches the NT syscall information based on the provided syscall hash.
///
/// # Safety
/// This function is marked as unsafe because it directly accesses global mutable state
/// (`G_NTDLL_CONF`) and operates on raw pointers (`module_base`, `names_slice`, `addresses_slice`,
/// `ordinals_slice`). It relies on correct initialization and configuration of `G_NTDLL_CONF`.
///
/// # Arguments
/// * `dw_sys_hash` - The hash value of the syscall name to search for.
///
/// # Returns
/// * `Ok(NtSyscall)` - If the syscall is found and validated, returns the populated `NtSyscall` structure.
/// * `Err(&'static str)` - If the syscall with the given hash is not found or validation fails.
pub unsafe fn fetch_nt_syscall(dw_sys_hash: u32) -> Result<NtSyscall, &'static str> {

    if dw_sys_hash == 0 {
        return Err("fetch_nt_syscall: dw_sys_hash argument is 0");
    }

    if let Some(syscall) = search_syscall_in_cache(dw_sys_hash) {
        return Ok(syscall)
    }

    // Initialize ntdll config if not found
    if G_NTDLL_CONF.u_module == 0 {
        G_NTDLL_CONF = init_ntdll_config_structure()?;
    }

    let mut nt_sys = NtSyscall {
        dw_ssn: 0,
        dw_syscall_hash: 0,
        p_syscall_address: ptr::null_mut(),
    };

    nt_sys.dw_syscall_hash = dw_sys_hash;

    let module_base = G_NTDLL_CONF.u_module as *const u8;
    let names_slice = std::slice::from_raw_parts(G_NTDLL_CONF.pdw_array_of_names, G_NTDLL_CONF.dw_number_of_names as usize);
    let addresses_slice = std::slice::from_raw_parts(G_NTDLL_CONF.pdw_array_of_addresses, G_NTDLL_CONF.dw_number_of_names as usize);
    let ordinals_slice = std::slice::from_raw_parts(G_NTDLL_CONF.pw_array_of_ordinals, G_NTDLL_CONF.dw_number_of_names as usize);

    for i in 0..G_NTDLL_CONF.dw_number_of_names-1 {
        let func_name_ptr = module_base.add(names_slice[i as usize] as usize) as *const i8;
        let func_address = module_base.add(addresses_slice[ordinals_slice[i as usize] as usize] as usize);

        let func_name = match std::ffi::CStr::from_ptr(func_name_ptr).to_str() {
            Ok(name) => name,
            Err(_) => continue,  // Skip invalid UTF-8 function names
        };

        if compute_crc32_hash(func_name.as_ref()) == dw_sys_hash {
            nt_sys.p_syscall_address = func_address as *mut c_void;

            if check_syscall_bytes(func_address, 0) {
                nt_sys.dw_ssn = extract_syscall_number(func_address, 0) as u32;
                SYSCALL_CACHE.push(nt_sys.clone());
                return Ok(nt_sys);
            }

            // if hooked - scenario 1
            if *func_address == 0xE9 {
                if let Some(ssn) = find_syscall_number(func_address) {
                    nt_sys.dw_ssn = ssn;
                    SYSCALL_CACHE.push(nt_sys.clone());
                    return Ok(nt_sys);
                }
            }

            // if hooked - scenario 2
            if *func_address.add(3) == 0xE9 {
                if let Some(ssn) = find_syscall_number(func_address) {
                    nt_sys.dw_ssn = ssn;
                    SYSCALL_CACHE.push(nt_sys.clone());
                    return Ok(nt_sys);
                }
            }
        }
    }

    Err("fetch_nt_syscall: Finished without finding syscall")
}

/// Finds the syscall number by checking neighboring bytes for potential hooks.
///
/// # Arguments
/// * `func_address` - A pointer to the function address.
///
/// # Returns
/// * `Some(u32)` containing the syscall number if found, `None` otherwise.
unsafe fn find_syscall_number(func_address: *const u8) -> Option<u32> {
    for idx in 1..=RANGE {
        if check_syscall_bytes(func_address, idx as isize * DOWN) {
            return Some((extract_syscall_number(func_address, idx as isize * DOWN) - idx) as u32);
        }
        if check_syscall_bytes(func_address, idx as isize * UP) {
            return Some((extract_syscall_number(func_address, idx as isize * UP) + idx) as u32);
        }
    }
    None
}

/// Checks if the bytes at the given offset match the syscall pattern.
///
/// # Arguments
/// * `address` - A pointer to the address to check.
/// * `offset` - The offset to apply to the address.
///
/// # Returns
/// * `true` if the bytes match the syscall pattern, `false` otherwise.
unsafe fn check_syscall_bytes(address: *const u8, offset: isize) -> bool {
    // First opcodes should be :
    //    MOV R10, RCX
    //    MOV EAX, <syscall>
    *address.offset(offset) == 0x4C
        && *address.offset(1 + offset) == 0x8B
        && *address.offset(2 + offset) == 0xD1
        && *address.offset(3 + offset) == 0xB8
        && *address.offset(6 + offset) == 0x00
        && *address.offset(7 + offset) == 0x00
}

/// Extracts the syscall number from the bytes at the given offset.
///
/// # Arguments
/// * `address` - A pointer to the address to extract from.
/// * `offset` - The offset to apply to the address.
///
/// # Returns
/// * The extracted syscall number as `u16`.
unsafe fn extract_syscall_number(address: *const u8, offset: isize) -> u16 {
    let high = *address.offset(5 + offset);
    let low = *address.offset(4 + offset);
    ((high as u16) << 8) | low as u16
}

unsafe fn search_syscall_in_cache(hash: u32) -> Option<NtSyscall> {
    SYSCALL_CACHE.iter().find(|&syscall| syscall.dw_syscall_hash == hash).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hooking;
    use hooking::{Hook, install_hook, remove_hook};

    #[test]
    fn test_fetch_nt_syscall() {

        let nt_create_thread_ex_crc32: u32 = 0xe2083cd5;

        let result = unsafe {
            fetch_nt_syscall(nt_create_thread_ex_crc32)
        };

        let nt_create_thread_syscall = match result {
            Ok(v) => v,
            Err(e) => {
                panic!("[!] nt_create_thread_syscall Failed With Error: {}", e)
            }
        };

        // Check the result and values against Windows 11 version 23H2
        assert_eq!(nt_create_thread_syscall.dw_syscall_hash, 0xe2083cd5);
        assert_eq!(nt_create_thread_syscall.dw_ssn, 0x00c7);
        assert!(!nt_create_thread_syscall.p_syscall_address.is_null());
    }

    #[test]
    // Command to build to debug in x64dbg
    // cargo test --color=always --package syscalls --lib hells_gate::tests::test_hook_nt_query_system_time --no-run -- --exact
    fn test_hook_nt_query_system_time() {

        let nt_query_system_time_crc32: u32 = 0x296c29b1;

        let result_before = unsafe { fetch_nt_syscall(nt_query_system_time_crc32) };

        let nt_query_system_time_syscall = match result_before {
            Ok(v) => v,
            Err(e) => {
                panic!("[!] nt_query_system_time_syscall Failed With Error: {}", e)
            }
        };

        assert_eq!(nt_query_system_time_syscall.dw_syscall_hash, 0x296c29b1);
        assert_eq!(nt_query_system_time_syscall.dw_ssn, 0x005a);
        assert!(!nt_query_system_time_syscall.p_syscall_address.is_null());

        let function_to_hook = nt_query_system_time_syscall.p_syscall_address as *const u8;
        let function_to_run = 12345678 as *const u8;

        // Create the hook
        let hook = unsafe { Hook::new(function_to_hook, function_to_run).expect("Hook failed")};

        install_hook(&hook);
        let result_after = unsafe {
            fetch_nt_syscall(nt_query_system_time_crc32)
        };

        let nt_query_system_time_syscall_after_hook = match result_after {
            Ok(v) => {
                remove_hook(hook);
                v
            },
            Err(e) => {
                remove_hook(hook);
                panic!("[!] nt_query_system_time_syscall Failed: {}", e)
            }
        };

        assert_eq!(nt_query_system_time_syscall_after_hook.dw_syscall_hash, nt_query_system_time_syscall.dw_syscall_hash);
        assert_eq!(nt_query_system_time_syscall_after_hook.dw_ssn, nt_query_system_time_syscall.dw_ssn);
        assert!(!nt_query_system_time_syscall_after_hook.p_syscall_address.is_null());
    }
}
