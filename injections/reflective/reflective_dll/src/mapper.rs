use core::ffi::{c_void, CStr};
use core::mem::{size_of, transmute};
use core::ptr;

use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64, IMAGE_RUNTIME_FUNCTION_ENTRY,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME,
    IMAGE_IMPORT_DESCRIPTOR,
};

use crate::arch::native;
use crate::parser::PeImage;
use crate::utils::{crc32_runtime, get_module_handle_h, get_proc_address_h};

type LoadLibraryAFn = unsafe extern "system" fn(lplibfilename: PCSTR) -> HMODULE;
type VirtualProtectFn = unsafe extern "system" fn(
    lpaddress: *const c_void,
    dwsize: usize,
    flnewprotect: PAGE_PROTECTION_FLAGS,
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS,
) -> i32;

/// Adjusts the image's internal absolute addresses if it was loaded at a different
/// base address than its preferred `ImageBase`.
///
/// This process, known as rebasing, parses the Base Relocation Table and applies
/// the difference between the actual and preferred load addresses to all absolute pointers.
///
/// # Errors
///
/// Returns `Err(())` if the relocation table is malformed.
pub fn fix_reloc(image: &PeImage, base: *mut u8) -> Result<(), ()> {
    unsafe {
        let preferred = image.image_base() as usize;
        let actual = base as usize;

        // Skip if the image is loaded at its preferred address
        if preferred == actual {
            return Ok(());
        }

        let delta = actual.wrapping_sub(preferred);
        let dir = image.reloc_directory();

        if dir.VirtualAddress == 0 || dir.Size == 0 {
            return Ok(());
        }

        let reloc_base = base.add(dir.VirtualAddress as usize);
        let mut offset = 0usize;

        while offset < dir.Size as usize {
            let block = &*(reloc_base.add(offset) as *const IMAGE_BASE_RELOCATION);
            if block.VirtualAddress == 0 || block.SizeOfBlock == 0 {
                break;
            }

            let entry_count = (block.SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<u16>();
            let entries = reloc_base.add(offset + size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;

            for i in 0..entry_count {
                let raw = ptr::read_unaligned(entries.add(i));
                let reloc_type = (raw >> 12) as u32;
                let reloc_offset = raw & 0x0FFF;

                // Only apply relocation if the type matches the native architecture (e.g., DIR64 or HIGHLOW)
                if reloc_type == native::RELOC_TYPE as u32 {
                    let patch_addr = base.add(block.VirtualAddress as usize).add(reloc_offset as usize);
                    arch_apply_reloc(patch_addr, delta);
                }
            }
            offset += block.SizeOfBlock as usize;
        }
        Ok(())
    }
}

/// Resolves the Import Address Table (IAT) by loading required DLLs and locating function pointers.
///
/// This iterates through the Import Descriptors, loads each dependency using `LoadLibraryA`,
/// and populates the First Thunk (IAT) with the actual memory addresses of the exported functions.
///
/// # Errors
///
/// Returns `Err(())` if a dependency cannot be loaded or a symbol cannot be resolved.
pub fn fix_imports(image: &PeImage, base: *mut u8) -> Result<(), ()> {
    let dir = image.import_directory();
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return Ok(());
    }

    unsafe {
        let mut desc = base.add(dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        let h_kernel32 = get_module_handle_h(crc32_runtime("kernel32.dll")).map_err(|_| ())?;
        let p_load_library_a = get_proc_address_h(h_kernel32, crc32_runtime("LoadLibraryA")).map_err(|_| ())?;
        let load_library_a: LoadLibraryAFn = transmute(p_load_library_a);

        while (*desc).Name != 0 {
            let dll_name_ptr = base.add((*desc).Name as usize) as *const i8;
            let module = load_library_a(dll_name_ptr as _);
            if module.is_null() {
                return Err(());
            }

            let oft_rva = (*desc).Anonymous.OriginalFirstThunk;
            let ft_rva = (*desc).FirstThunk;

            // Use the ILT (OriginalFirstThunk) if present; otherwise fall back to the IAT (FirstThunk)
            let lookup = if oft_rva != 0 {
                base.add(oft_rva as usize) as *const native::ThunkData
            } else {
                base.add(ft_rva as usize) as *const native::ThunkData
            };

            let iat = base.add(ft_rva as usize) as *mut native::ThunkData;
            resolve_thunks_for_dll(module, lookup, iat, base)?;

            desc = desc.add(1);
        }
    }
    Ok(())
}

/// Updates memory protection flags (Read/Write/Execute) for each PE section based on its characteristics.
///
/// This function transitions the image memory from a generic RWE state to the specific
/// permissions requested by the compiler for each section (e.g., RX for `.text`, R for `.rdata`).
///
/// # Errors
///
/// Returns `Err(())` if `VirtualProtect` fails for any section.
pub fn fix_memory_permissions(image: &PeImage, base: *mut u8) -> Result<(), ()> {
    unsafe {
        let h_kernel32 = get_module_handle_h(crc32_runtime("kernel32.dll")).map_err(|_| ())?;
        let p_virtual_protect = get_proc_address_h(h_kernel32, crc32_runtime("VirtualProtect")).map_err(|_| ())?;
        let virtual_protect: VirtualProtectFn = transmute(p_virtual_protect);

        let section_count = image.nt_headers().file_header().NumberOfSections as usize;

        for idx in 0..section_count {
            let section = image.section_header(idx).ok_or(())?;
            let virt_size = section.Misc.VirtualSize;

            if section.VirtualAddress == 0 || (virt_size == 0 && section.SizeOfRawData == 0) {
                continue;
            }

            let protect = map_flags(
                (section.Characteristics & IMAGE_SCN_MEM_READ) != 0,
                (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0,
                (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0,
            );

            if protect == 0 { continue; }

            let addr = base.add(section.VirtualAddress as usize);
            let size = core::cmp::max(virt_size, section.SizeOfRawData) as usize;

            let mut old = 0u32;
            if virtual_protect(addr as _, size, protect, &mut old) == 0 {
                return Err(());
            }
        }
    }
    Ok(())
}

/// Registers the Exception Directory with the Windows kernel (x64 only).
///
/// This allows the OS to correctly handle exceptions occurring within the manually mapped
/// code by providing the `RUNTIME_FUNCTION` table.
///
/// # Errors
///
/// Returns `Err(())` if `RtlAddFunctionTable` fails.
#[cfg(target_pointer_width = "64")]
pub fn register_exception_handlers(image: &PeImage, base: *mut u8) -> Result<(), ()> {
    let dir = image.exception_directory();

    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return Ok(());
    }

    unsafe {
        type RtlAddFunctionTableFn = unsafe extern "system" fn(
            function_table: *const IMAGE_RUNTIME_FUNCTION_ENTRY,
            entry_count: u32,
            base_address: u64,
        ) -> i32;

        let h_kernel32 = get_module_handle_h(crc32_runtime("kernel32.dll")).map_err(|_| ())?;
        let p_rtl_add_func_table = get_proc_address_h(
            h_kernel32,
            crc32_runtime("RtlAddFunctionTable")
        ).map_err(|_| ())?;

        let rtl_add_function_table: RtlAddFunctionTableFn = core::mem::transmute(p_rtl_add_func_table);

        let table = base.add(dir.VirtualAddress as usize) as *const IMAGE_RUNTIME_FUNCTION_ENTRY;
        let count = (dir.Size as usize / size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>()) as u32;

        let success = rtl_add_function_table(table, count, base as u64);

        if success == 0 {
            return Err(());
        }
    }

    Ok(())
}

#[cfg(not(target_pointer_width = "64"))]
pub fn register_exception_handlers(_: &PeImage, _: *mut u8) -> Result<(), ()> { Ok(()) }

// --- Helpers ---

/// Maps PE section characteristic flags to Win32 PAGE protection constants.
fn map_flags(read: bool, write: bool, execute: bool) -> u32 {
    match (read, write, execute) {
        (true, true, true)    => PAGE_EXECUTE_READWRITE,
        (true, false, true)   => PAGE_EXECUTE_READ,
        (false, true, true)   => PAGE_EXECUTE_WRITECOPY,
        (false, false, true)  => PAGE_EXECUTE,
        (true, true, false)   => PAGE_READWRITE,
        (true, false, false)  => PAGE_READONLY,
        (false, true, false)  => PAGE_WRITECOPY,
        _ => 0,
    }
}

/// Applies a pointer relocation by adding the address delta.
unsafe fn arch_apply_reloc(addr: *mut u8, delta: usize) {
    let val = ptr::read_unaligned(addr as *mut usize);
    ptr::write_unaligned(addr as *mut usize, val.wrapping_add(delta));
}

/// Iterates through the thunks of a specific DLL and resolves their addresses.
unsafe fn resolve_thunks_for_dll(
    module: HMODULE,
    mut lookup: *const native::ThunkData,
    mut iat: *mut native::ThunkData,
    base: *mut u8,
) -> Result<(), ()> {
    while arch_thunk_aod(lookup) != 0 {
        let aod = arch_thunk_aod(lookup);
        let addr = if arch_is_ordinal(aod) {
            get_proc_address_ordinal(module, (aod & 0xFFFF) as u16).ok_or(())?
        } else {
            let ibn = base.add(aod as usize) as *const IMAGE_IMPORT_BY_NAME;
            get_proc_address_name(module, (*ibn).Name.as_ptr() as PCSTR).ok_or(())?
        };
        arch_thunk_write_fn(iat, addr);
        lookup = lookup.add(1);
        iat = iat.add(1);
    }
    Ok(())
}

/// Extracts the AddressOfData/Function from a thunk entry.
#[inline]
unsafe fn arch_thunk_aod(thunk: *const native::ThunkData) -> usize { (*thunk).u1.AddressOfData as usize }

/// Determines if an import thunk refers to an ordinal rather than a name.
#[inline]
fn arch_is_ordinal(aod: usize) -> bool { (aod & native::ORDINAL_FLAG as usize) != 0 }

/// Writes a resolved function pointer back into the IAT thunk.
#[inline]
unsafe fn arch_thunk_write_fn(thunk: *mut native::ThunkData, addr: usize) {
    #[cfg(target_pointer_width = "64")] { (*thunk).u1.Function = addr as u64; }
    #[cfg(target_pointer_width = "32")] { (*thunk).u1.Function = addr as u32; }
}

/// Resolves a function address from a module using a string name and CRC32 hashing.
#[inline]
unsafe fn get_proc_address_name(module: HMODULE, name: PCSTR) -> Option<usize> {
    let name_str = CStr::from_ptr(name as *const i8).to_str().ok()?;
    get_proc_address_h(module as *mut _, crc32_runtime(name_str))
        .ok()
        .map(|fp| fp as usize)
}

/// Manually parses the Export Directory of a module to resolve a function by its ordinal.
#[inline]
unsafe fn get_proc_address_ordinal(module: HMODULE, ordinal: u16) -> Option<usize> {
    let base = module as usize;
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

    let export_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
    if export_rva == 0 { return None; }

    let export = &*((base + export_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);
    let index = ordinal.wrapping_sub(export.Base as u16) as u32;

    if index >= export.NumberOfFunctions { return None; }

    let funcs = (base + export.AddressOfFunctions as usize) as *const u32;
    let func_rva = *funcs.add(index as usize);

    if func_rva == 0 { None } else { Some(base + func_rva as usize) }
}