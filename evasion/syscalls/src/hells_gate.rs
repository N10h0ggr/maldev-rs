use core::arch::asm;
use core::ffi::{c_void, CStr};
use core::ptr;
use core::slice;

use crate::compute_crc32_hash;

// --- Constants ---
const UP: isize = -32;
const DOWN: isize = 32;
const RANGE: u16 = 0xFF;
const MAX_SYSCALL_CACHE: usize = 64;

// --- Strategy Enum ---

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SyscallStrategy {
    Ntdll,
    #[cfg(feature = "win32u")]
    Win32u,
}

impl Default for SyscallStrategy {
    fn default() -> Self {
        SyscallStrategy::Ntdll
    }
}

// --- Custom Structures for PEB Parsing ---
// We define these manually because windows-sys definitions are often opaque/incomplete.

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: windows_sys::Win32::System::Kernel::LIST_ENTRY,
    pub InMemoryOrderLinks: windows_sys::Win32::System::Kernel::LIST_ENTRY,
    pub InInitializationOrderLinks: windows_sys::Win32::System::Kernel::LIST_ENTRY,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
}

#[repr(C)]
#[derive(Debug)]
struct NtdllConfig {
    pdw_array_of_addresses: *mut u32,
    pdw_array_of_names: *mut u32,
    pw_array_of_ordinals: *mut u16,
    dw_number_of_names: u32,
    u_module: usize,
}

impl NtdllConfig {
    const fn new() -> Self {
        Self {
            pdw_array_of_addresses: ptr::null_mut(),
            pdw_array_of_names: ptr::null_mut(),
            pw_array_of_ordinals: ptr::null_mut(),
            dw_number_of_names: 0,
            u_module: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NtSyscall {
    pub dw_ssn: u32,
    pub dw_syscall_hash: u32,
    pub p_syscall_address: *mut c_void,
    pub p_syscall_inst_address: *mut c_void,
}

impl NtSyscall {
    const fn new() -> Self {
        Self {
            dw_ssn: 0,
            dw_syscall_hash: 0,
            p_syscall_address: ptr::null_mut(),
            p_syscall_inst_address: ptr::null_mut(),
        }
    }
}

// --- Global State ---
static mut G_NTDLL_CONF: NtdllConfig = NtdllConfig::new();
static mut SYSCALL_CACHE: [NtSyscall; MAX_SYSCALL_CACHE] = [NtSyscall::new(); MAX_SYSCALL_CACHE];
static mut SYSCALL_CACHE_COUNT: usize = 0;

#[cfg(feature = "win32u")]
static mut G_WIN32U_GADGET: *mut c_void = ptr::null_mut();

// --- Helper Functions ---

#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut windows_sys::Win32::System::Threading::TEB {
    let teb: *mut windows_sys::Win32::System::Threading::TEB;
    unsafe { asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb) };
    teb
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut windows_sys::Win32::System::Threading::TEB {
    let teb: *mut windows_sys::Win32::System::Threading::TEB;
    unsafe { asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb) };
    teb
}

unsafe fn get_export_directory(h_module: usize) -> Option<*const windows_sys::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY> {
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

    let base_addr = h_module;
    let p_dos_header = base_addr as *const IMAGE_DOS_HEADER;

    unsafe {
        if (*p_dos_header).e_magic != 0x5A4D { // "MZ"
            return None;
        }

        let p_nt_headers = (base_addr + (*p_dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*p_nt_headers).Signature != 0x00004550 { // "PE\0\0"
            return None;
        }

        let export_entry = (*p_nt_headers).OptionalHeader.DataDirectory[0];
        if export_entry.VirtualAddress == 0 {
            return None;
        }

        Some((base_addr + export_entry.VirtualAddress as usize) as *const _)
    }
}

unsafe fn get_module_base_by_hash(module_hash: u32) -> Option<usize> {
    use windows_sys::Win32::System::Threading::PEB;

    let teb = unsafe { get_teb() };
    // SAFETY: Dereferencing TEB/PEB pointers
    let p_peb: *mut PEB = unsafe { (*teb).ProcessEnvironmentBlock };

    if p_peb.is_null() { return None; }
    let p_ldr = unsafe { (*p_peb).Ldr };
    if p_ldr.is_null() { return None; }

    unsafe {
        let mut p_list_entry = (*p_ldr).InMemoryOrderModuleList.Flink;
        let p_list_head = &((*p_ldr).InMemoryOrderModuleList) as *const _ as *mut windows_sys::Win32::System::Kernel::LIST_ENTRY;

        while p_list_entry != p_list_head {
            // We cast to our custom struct because windows-sys definition is incomplete
            let p_entry = (p_list_entry as *mut u8).sub(0x10) as *mut LDR_DATA_TABLE_ENTRY;

            if !(*p_entry).DllBase.is_null() {
                let buffer = (*p_entry).BaseDllName.Buffer;
                let length = (*p_entry).BaseDllName.Length as usize / 2;

                if !buffer.is_null() && length > 0 {
                    let slice = slice::from_raw_parts(buffer, length);
                    let mut name_buf = [0u8; 128];
                    let len_to_copy = if length > 127 { 127 } else { length };

                    for i in 0..len_to_copy {
                        let c = slice[i] as u8;
                        name_buf[i] = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
                    }

                    let s = core::str::from_utf8_unchecked(&name_buf[..len_to_copy]);
                    if compute_crc32_hash(s) == module_hash {
                        return Some((*p_entry).DllBase as usize);
                    }
                }
            }
            p_list_entry = (*p_list_entry).Flink;
        }
    }
    None
}

unsafe fn init_ntdll_config_structure() -> Result<NtdllConfig, &'static str> {
    let ntdll_hash = compute_crc32_hash("ntdll.dll");

    let ntdll_base = match unsafe { get_module_base_by_hash(ntdll_hash) } {
        Some(addr) => addr,
        None => return Err("Failed to find NTDLL base"),
    };

    let p_img_exp_dir = unsafe { get_export_directory(ntdll_base).unwrap() };

    unsafe {
        Ok(NtdllConfig {
            u_module: ntdll_base,
            dw_number_of_names: (*p_img_exp_dir).NumberOfNames,
            pdw_array_of_names: (ntdll_base + (*p_img_exp_dir).AddressOfNames as usize) as *mut u32,
            pdw_array_of_addresses: (ntdll_base + (*p_img_exp_dir).AddressOfFunctions as usize) as *mut u32,
            pw_array_of_ordinals: (ntdll_base + (*p_img_exp_dir).AddressOfNameOrdinals as usize) as *mut u16,
        })
    }
}

// --- WIN32U Feature Logic ---

#[cfg(feature = "win32u")]
unsafe fn ensure_win32u_loaded() -> Option<usize> {
    let win32u_hash = compute_crc32_hash("win32u.dll");

    // 1. Try to find it if already loaded
    if let Some(base) = unsafe { get_module_base_by_hash(win32u_hash) } {
        return Some(base);
    }

    // 2. If not loaded, we must load it via LdrLoadDll
    let ldr_load_dll_hash = compute_crc32_hash("LdrLoadDll");

    let ntdll_base = unsafe { G_NTDLL_CONF.u_module };
    if ntdll_base == 0 { return None; }

    let p_img_exp_dir = unsafe { get_export_directory(ntdll_base)? };

    // Scan exports manually to find LdrLoadDll
    let (names, ordinals, funcs, num_names) = unsafe {
        (
            slice::from_raw_parts((ntdll_base + (*p_img_exp_dir).AddressOfNames as usize) as *mut u32, (*p_img_exp_dir).NumberOfNames as usize),
            slice::from_raw_parts((ntdll_base + (*p_img_exp_dir).AddressOfNameOrdinals as usize) as *mut u16, (*p_img_exp_dir).NumberOfNames as usize),
            slice::from_raw_parts((ntdll_base + (*p_img_exp_dir).AddressOfFunctions as usize) as *mut u32, (*p_img_exp_dir).NumberOfNames as usize),
            (*p_img_exp_dir).NumberOfNames
        )
    };

    let mut ldr_load_dll_addr: Option<usize> = None;

    for i in 0..num_names as usize {
        let name_ptr = unsafe { (ntdll_base + names[i] as usize) as *const i8 };
        if let Ok(name) = unsafe { CStr::from_ptr(name_ptr).to_str() } {
            if compute_crc32_hash(name) == ldr_load_dll_hash {
                let ord = ordinals[i] as usize;
                ldr_load_dll_addr = Some(ntdll_base + funcs[ord] as usize);
                break;
            }
        }
    }

    let ldr_load_dll = ldr_load_dll_addr?;

    // Prepare arguments for LdrLoadDll
    let mut dll_name_buf: [u16; 11] = [0; 11];
    let name_str = "win32u.dll";
    for (i, b) in name_str.bytes().enumerate() { dll_name_buf[i] = b as u16; }

    let mut unicode_str = UNICODE_STRING {
        Length: (name_str.len() * 2) as u16,
        MaximumLength: (dll_name_buf.len() * 2) as u16,
        Buffer: dll_name_buf.as_mut_ptr(),
    };

    let mut module_handle: usize = 0;

    let func: extern "system" fn(
        path_to_file: *mut u16,
        flags: *mut u32,
        module_file_name: *mut UNICODE_STRING,
        module_handle: *mut usize
    ) -> i32 = unsafe { core::mem::transmute(ldr_load_dll) };

    let status = func(ptr::null_mut(), ptr::null_mut(), &mut unicode_str, &mut module_handle);

    if status == 0 && module_handle != 0 {
        Some(module_handle)
    } else {
        None
    }
}

#[cfg(feature = "win32u")]
unsafe fn find_gadget_in_win32u() -> Option<*mut c_void> {
    unsafe {
        if !G_WIN32U_GADGET.is_null() {
            return Some(G_WIN32U_GADGET);
        }
    }

    let win32u_base = unsafe { ensure_win32u_loaded()? };
    let p_img_exp_dir = unsafe { get_export_directory(win32u_base)? };

    let (addresses, ordinals, num_names) = unsafe {
        (
            (win32u_base + (*p_img_exp_dir).AddressOfFunctions as usize) as *mut u32,
            (win32u_base + (*p_img_exp_dir).AddressOfNameOrdinals as usize) as *mut u16,
            (*p_img_exp_dir).NumberOfNames
        )
    };

    let addresses_slice = unsafe { slice::from_raw_parts(addresses, num_names as usize) };
    let ordinals_slice = unsafe { slice::from_raw_parts(ordinals, num_names as usize) };

    for i in 0..num_names as usize {
        let ordinal = ordinals_slice[i] as usize;
        let func_rva = addresses_slice[ordinal] as usize;
        let func_address = (win32u_base + func_rva) as *const u8;

        for offset in 0..32 {
            unsafe {
                let curr = func_address.add(offset);
                if *curr == 0x0F && *curr.add(1) == 0x05 {
                    G_WIN32U_GADGET = curr as *mut c_void;
                    return Some(G_WIN32U_GADGET);
                }
            }
        }
    }
    None
}

// --- Main Logic ---

pub unsafe fn fetch_nt_syscall(dw_sys_hash: u32, strategy: SyscallStrategy) -> Result<NtSyscall, &'static str> {
    if dw_sys_hash == 0 {
        return Err("fetch_nt_syscall: dw_sys_hash argument is 0");
    }

    if let Some(syscall) = unsafe { search_syscall_in_cache(dw_sys_hash) } {
        return Ok(syscall);
    }

    unsafe {
        if G_NTDLL_CONF.u_module == 0 {
            G_NTDLL_CONF = init_ntdll_config_structure()?;
        }
    }

    let mut nt_sys = NtSyscall {
        dw_ssn: 0,
        dw_syscall_hash: dw_sys_hash,
        p_syscall_address: ptr::null_mut(),
        p_syscall_inst_address: ptr::null_mut(),
    };

    let (module_base, names_slice, addresses_slice, ordinals_slice, num_names) = unsafe {
        let base = G_NTDLL_CONF.u_module as *const u8;
        let num = G_NTDLL_CONF.dw_number_of_names;
        (
            base,
            slice::from_raw_parts(G_NTDLL_CONF.pdw_array_of_names, num as usize),
            slice::from_raw_parts(G_NTDLL_CONF.pdw_array_of_addresses, num as usize),
            slice::from_raw_parts(G_NTDLL_CONF.pw_array_of_ordinals, num as usize),
            num
        )
    };

    let mut found_ssn = false;

    for i in 0..(num_names - 1) as usize {
        let name_offset = names_slice[i] as usize;
        let func_name_ptr = unsafe { module_base.add(name_offset) as *const i8 };
        let func_name = unsafe {
            match CStr::from_ptr(func_name_ptr).to_str() {
                Ok(name) => name,
                Err(_) => continue,
            }
        };

        if compute_crc32_hash(func_name) == dw_sys_hash {
            let ordinal = ordinals_slice[i] as usize;
            let address_offset = addresses_slice[ordinal] as usize;
            let func_address = unsafe { module_base.add(address_offset) };

            nt_sys.p_syscall_address = func_address as *mut c_void;

            unsafe {
                if check_syscall_bytes(func_address, 0) {
                    nt_sys.dw_ssn = extract_syscall_number(func_address, 0) as u32;
                } else if *func_address == 0xE9 {
                    if let Some(ssn) = find_syscall_number(func_address) { nt_sys.dw_ssn = ssn; }
                } else if *func_address.add(3) == 0xE9 {
                    if let Some(ssn) = find_syscall_number(func_address) { nt_sys.dw_ssn = ssn; }
                }
            }

            found_ssn = true;
            break;
        }
    }

    if !found_ssn || nt_sys.dw_ssn == 0 {
        return Err("fetch_nt_syscall: Failed to find SSN in NTDLL");
    }

    match strategy {
        SyscallStrategy::Ntdll => {
            unsafe {
                let u_func_address = (nt_sys.p_syscall_address as *const u8).add(0xFF);
                for offset in 0..RANGE as usize {
                    let curr = u_func_address.add(offset);
                    if *curr == 0x0F && *curr.add(1) == 0x05 {
                        nt_sys.p_syscall_inst_address = curr as *mut c_void;
                        break;
                    }
                }
            }
        },
        #[cfg(feature = "win32u")]
        SyscallStrategy::Win32u => {
            if let Some(addr) = unsafe { find_gadget_in_win32u() } {
                nt_sys.p_syscall_inst_address = addr;
            } else {
                return Err("fetch_nt_syscall: Failed to find syscall in win32u");
            }
        }
    }

    if !nt_sys.p_syscall_inst_address.is_null() {
        unsafe { cache_syscall(nt_sys) };
        Ok(nt_sys)
    } else {
        Err("fetch_nt_syscall: SSN found but syscall instruction address not located")
    }
}

// --- Utils ---

unsafe fn cache_syscall(syscall: NtSyscall) {
    unsafe {
        if SYSCALL_CACHE_COUNT < MAX_SYSCALL_CACHE {
            SYSCALL_CACHE[SYSCALL_CACHE_COUNT] = syscall;
            SYSCALL_CACHE_COUNT += 1;
        }
    }
}

unsafe fn search_syscall_in_cache(hash: u32) -> Option<NtSyscall> {
    unsafe {
        for i in 0..SYSCALL_CACHE_COUNT {
            if SYSCALL_CACHE[i].dw_syscall_hash == hash {
                return Some(SYSCALL_CACHE[i]);
            }
        }
    }
    None
}

unsafe fn find_syscall_number(func_address: *const u8) -> Option<u32> {
    for idx in 1..=RANGE {
        let idx = idx as isize;
        unsafe {
            if check_syscall_bytes(func_address, idx * DOWN) {
                return Some((extract_syscall_number(func_address, idx * DOWN) as isize - idx) as u32);
            }
            if check_syscall_bytes(func_address, idx * UP) {
                return Some((extract_syscall_number(func_address, idx * UP) as isize + idx) as u32);
            }
        }
    }
    None
}

unsafe fn check_syscall_bytes(address: *const u8, offset: isize) -> bool {
    unsafe {
        let p = address.offset(offset);
        *p == 0x4C
            && *p.add(1) == 0x8B
            && *p.add(2) == 0xD1
            && *p.add(3) == 0xB8
            && *p.add(6) == 0x00
            && *p.add(7) == 0x00
    }
}

unsafe fn extract_syscall_number(address: *const u8, offset: isize) -> u16 {
    unsafe {
        let p = address.offset(offset);
        let high = *p.add(5);
        let low = *p.add(4);
        ((high as u16) << 8) | low as u16
    }
}