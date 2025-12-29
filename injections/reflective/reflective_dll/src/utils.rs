use core::ffi::{c_void, CStr};
use core::{mem, ptr};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER32,
    IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};

// --- Manual PEB Structures ---

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

#[repr(C)]
struct PEB_LDR_DATA {
    length: u32,
    initialized: u8,
    ss_handle: *mut c_void,
    in_load_order_module_list: LIST_ENTRY,
    in_memory_order_module_list: LIST_ENTRY,
    in_initialization_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

// --- Public API ---

/// Retrieves the base address of a loaded module by hashing its name.
///
/// This function walks the Process Environment Block (PEB) `InMemoryOrderModuleList`.
///
/// # Arguments
/// * `module_hash` - The CRC32 hash of the module name (e.g., "kernel32.dll"), lowercased.
///
/// # Safety
/// This function is unsafe because it performs raw pointer dereferencing of the PEB
/// and loader data structures. It assumes a valid x86_64 Windows environment.
pub unsafe fn get_module_handle_h(module_hash: u32) -> Result<*mut c_void, &'static str> {
    #[cfg(not(target_arch = "x86_64"))]
    return Err("Only x86_64 is supported");

    let peb: *const c_void;
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);

    // PEB + 0x18 points to the Ldr
    let ldr = *(peb.add(0x18) as *const *mut PEB_LDR_DATA);
    let head = &(*ldr).in_memory_order_module_list as *const LIST_ENTRY;
    let mut current = (*head).flink;

    while current != head as *mut LIST_ENTRY {
        // Calculate the base address of the LDR_DATA_TABLE_ENTRY from the LIST_ENTRY pointer
        // InMemoryOrderLinks is the second field (offset 0x10)
        let entry_ptr = (current as *const u8).sub(mem::offset_of!(LDR_DATA_TABLE_ENTRY, in_memory_order_links));
        let entry = &*(entry_ptr as *const LDR_DATA_TABLE_ENTRY);

        let name = &entry.base_dll_name;
        if !name.buffer.is_null() && name.length != 0 {
            let len = (name.length / 2) as usize;
            if crc32_utf16_ascii_lower(name.buffer, len) == module_hash {
                return Ok(entry.dll_base);
            }
        }
        current = (*current).flink;
    }

    Err("Module not found")
}

/// Resolves a function's address from a module's Export Address Table (EAT) using a hash.
///
/// # Arguments
/// * `module_base` - The base address of the module to search.
/// * `function_hash` - The CRC32 hash of the function name.
///
/// # Safety
/// Dereferences memory within the provided module base. If the base address is invalid
/// or the module is malformed, this will cause a segmentation fault.
pub unsafe fn get_proc_address_h(
    module_base: *mut c_void,
    function_hash: u32,
) -> Result<*mut c_void, &'static str> {
    let base = module_base as usize;
    let dos = &*(base as *const IMAGE_DOS_HEADER);

    if dos.e_magic != 0x5A4D {
        return Err("Invalid DOS header (Magic 0x5A4D not found)");
    }

    let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != 0x4550 {
        return Err("Invalid NT header (Signature 0x4550 not found)");
    }

    let export_dir_entry = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
    if export_dir_entry.VirtualAddress == 0 {
        return Err("Module has no export directory");
    }

    let export = &*((base + export_dir_entry.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY);
    let names = (base + export.AddressOfNames as usize) as *const u32;
    let funcs = (base + export.AddressOfFunctions as usize) as *const u32;
    let ords = (base + export.AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..export.NumberOfNames {
        let name_rva = *names.add(i as usize);
        let name_ptr = (base + name_rva as usize) as *const i8;

        let cstr = CStr::from_ptr(name_ptr);
        if let Ok(name_str) = cstr.to_str() {
            if crc32_runtime(name_str) == function_hash {
                let ordinal = *ords.add(i as usize);
                let func_rva = *funcs.add(ordinal as usize);
                return Ok((base + func_rva as usize) as *mut c_void);
            }
        }
    }

    Err("Function hash match not found in exports")
}

/// Retrieves the `SizeOfImage` from the NT Headers of a PE image.
///
/// Supports both PE32 and PE32+ (x64) headers.
///
/// # Safety
/// Assumes `base` points to a valid PE image in memory.
#[inline(always)]
pub unsafe fn get_image_size_raw(base: *const c_void) -> usize {
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    let nt_ptr = base as usize + dos.e_lfanew as usize;

    // Magic is at the start of the Optional Header (NT_Headers + 4 byte sig + 20 byte FileHeader)
    let magic = *( (nt_ptr + 24) as *const u16);

    match magic {
        0x20B => (*( (nt_ptr + 24) as *const IMAGE_OPTIONAL_HEADER64)).SizeOfImage as usize,
        0x10B => (*( (nt_ptr + 24) as *const IMAGE_OPTIONAL_HEADER32)).SizeOfImage as usize,
        _ => 0,
    }
}

/// Copies PE headers and sections from a source buffer to a destination buffer.
///
/// This is typically used when "mapping" a file from disk into its virtual memory layout.
///
/// # Safety
/// Both `src_base` and `dst_base` must be valid and `dst_base` must be large enough
/// to hold the entire image size.
#[inline(always)]
pub unsafe fn copy_pe_image(src_base: *const c_void, dst_base: *mut c_void) {
    let dos = &*(src_base as *const IMAGE_DOS_HEADER);
    let nt = &*((src_base as usize + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

    // Copy Headers
    ptr::copy_nonoverlapping(
        src_base as *const u8,
        dst_base as *mut u8,
        nt.OptionalHeader.SizeOfHeaders as usize,
    );

    // Copy Sections
    let section_header_ptr = (nt as *const _ as usize + mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    let sections = core::slice::from_raw_parts(section_header_ptr, nt.FileHeader.NumberOfSections as usize);

    for sec in sections {
        if sec.SizeOfRawData != 0 {
            let src = (src_base as usize).wrapping_add(sec.PointerToRawData as usize) as *const u8;
            let dst = (dst_base as usize).wrapping_add(sec.VirtualAddress as usize) as *mut u8;
            ptr::copy_nonoverlapping(src, dst, sec.SizeOfRawData as usize);
        }
    }
}

// --- Internal Hashing Logic ---

/// Standard CRC32 implementation using the 0xEDB88320 polynomial.
#[inline(always)]
fn update_crc32(mut crc: u32, byte: u8) -> u32 {
    crc ^= byte as u32;
    for _ in 0..8 {
        crc = if (crc & 1) != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
    }
    crc
}

/// Computes CRC32 hash of a string, case-insensitive.
pub fn crc32_runtime(s: &str) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in s.as_bytes() {
        let lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        crc = update_crc32(crc, lower);
    }
    !crc
}

/// Computes CRC32 hash over a UTF-16 buffer without allocation, case-insensitive.
unsafe fn crc32_utf16_ascii_lower(buf: *const u16, len: usize) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for i in 0..len {
        let ch = *buf.add(i) as u8;
        let lower = if ch >= b'A' && ch <= b'Z' { ch + 32 } else { ch };
        crc = update_crc32(crc, lower);
    }
    !crc
}