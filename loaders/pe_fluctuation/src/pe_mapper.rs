use std::ffi::CStr;
use std::mem::size_of;
use std::ptr;

use log::{debug, error, info, trace, warn};
use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_RUNTIME_FUNCTION_ENTRY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
#[cfg(target_pointer_width = "64")]
use windows_sys::Win32::System::Diagnostics::Debug::RtlAddFunctionTable;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_BASE_RELOCATION, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_REL_BASED_ABSOLUTE,
};

use crate::arch::native;
use crate::errors::PeError;
use crate::pe_parser::PeImage;

/// Maps a PE image into memory in a way similar to the Windows loader.
///
/// Steps:
/// 1. Allocate `SizeOfImage` bytes using `VirtualAlloc` (RW)
/// 2. Copy PE headers (`SizeOfHeaders`)
/// 3. Copy each section to `base + VirtualAddress`
///
/// Returns the base address of the mapped image.
pub fn map_pe_image(image: &PeImage) -> Result<*mut u8, PeError> {
    let (size_of_image, size_of_headers) = match image.nt_headers() {
        crate::pe_parser::NtHeaders::Nt32 { optional, .. } => {
            (optional.SizeOfImage as usize, optional.SizeOfHeaders as usize)
        }
        crate::pe_parser::NtHeaders::Nt64 { optional, .. } => {
            (optional.SizeOfImage as usize, optional.SizeOfHeaders as usize)
        }
    };

    debug!(
        "map: SizeOfImage=0x{:X}, SizeOfHeaders=0x{:X}",
        size_of_image, size_of_headers
    );

    unsafe {
        let base = VirtualAlloc(
            ptr::null_mut(),
            size_of_image,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        ) as *mut u8;

        if base.is_null() {
            return Err(PeError::MemoryAllocationFailed);
        }

        info!("map: allocated image at {:p}", base);

        // Copy headers
        ptr::copy_nonoverlapping(image.as_bytes().as_ptr(), base, size_of_headers);

        // Copy sections
        let section_count = image.nt_headers().file_header().NumberOfSections as usize;
        debug!("map: copying {} section(s)", section_count);

        for i in 0..section_count {
            let section = image.section_header(i).ok_or(PeError::OutOfBounds)?;

            if section.SizeOfRawData == 0 {
                trace!("map: section {} has no raw data, skipping", i);
                continue;
            }

            let dst = base.add(section.VirtualAddress as usize);
            let src = image
                .as_bytes()
                .as_ptr()
                .add(section.PointerToRawData as usize);

            ptr::copy_nonoverlapping(src, dst, section.SizeOfRawData as usize);
        }

        Ok(base)
    }
}

/// Applies base relocations to a manually mapped PE image.
///
/// If the image is not loaded at its preferred `ImageBase`, all absolute
/// addresses described by the relocation table are adjusted by the delta.
///
/// # Errors
///
/// Returns `RelocationsRequired` if relocations are needed but the relocation
/// directory is missing.
pub fn fix_reloc(image: &PeImage, base: *mut u8) -> Result<(), PeError> {
    unsafe {
        let preferred = image.image_base() as usize;
        let actual = base as usize;

        if preferred == actual {
            debug!("reloc: image loaded at preferred base");
            return Ok(());
        }

        let delta = actual.wrapping_sub(preferred);
        debug!(
            "reloc: preferred=0x{:X}, actual=0x{:X}, delta=0x{:X}",
            preferred, actual, delta
        );

        let dir = image.reloc_directory();
        if dir.VirtualAddress == 0 || dir.Size == 0 {
            return Err(PeError::RelocationsRequired);
        }

        let reloc_base = base.add(dir.VirtualAddress as usize);
        let reloc_size = dir.Size as usize;

        let mut offset = 0usize;
        while offset < reloc_size {
            let block =
                ptr::read_unaligned(reloc_base.add(offset) as *const IMAGE_BASE_RELOCATION);

            if block.VirtualAddress == 0 || block.SizeOfBlock == 0 {
                break;
            }

            let entries_offset = offset + size_of::<IMAGE_BASE_RELOCATION>();
            let entries_size =
                block.SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>();
            let entry_count = entries_size / size_of::<u16>();

            let entries = reloc_base.add(entries_offset) as *const u16;

            for i in 0..entry_count {
                let raw = ptr::read_unaligned(entries.add(i));
                let reloc_type = (raw >> 12) as u16;
                let reloc_offset = (raw & 0x0FFF) as u16;

                let patch_addr = base
                    .add(block.VirtualAddress as usize)
                    .add(reloc_offset as usize);

                match reloc_type as u32 {
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    t if t as u16 == native::RELOC_TYPE => {
                        arch_apply_reloc(patch_addr, delta);
                    }
                    _ => {
                        debug!(
                            "reloc: unsupported type {} at RVA 0x{:X}",
                            reloc_type,
                            block.VirtualAddress + reloc_offset as u32
                        );
                    }
                }
            }

            offset += block.SizeOfBlock as usize;
        }

        info!("reloc: base relocations applied");
        Ok(())
    }
}

/// Resolves and patches the Import Address Table (IAT).
///
/// This function emulates the Windows loader import resolution logic:
/// - Walks the import descriptor list
/// - Loads each referenced DLL
/// - Resolves imports by name or ordinal
/// - Writes resolved addresses into the IAT
pub fn fix_imports(image: &PeImage, base: *mut u8) -> Result<(), PeError> {
    let dir = image.import_directory();
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        debug!("imports: no import directory present");
        return Ok(());
    }

    unsafe {
        let mut desc = base.add(dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*desc).Name != 0 {
            let d = &*desc;

            let dll_ptr = base.add(d.Name as usize) as *const i8;
            let dll_name = CStr::from_ptr(dll_ptr).to_string_lossy().into_owned();

            trace!("imports: loading '{}'", dll_name);

            let module = LoadLibraryA(dll_ptr as _);
            if module.is_null() {
                error!("imports: LoadLibraryA failed for '{}'", dll_name);
                return Err(PeError::DllLoadFailed(dll_name));
            }

            let oft_rva = d.Anonymous.OriginalFirstThunk;
            let ft_rva = d.FirstThunk;

            if ft_rva == 0 {
                return Err(PeError::ImportResolveFailed {
                    dll: dll_name,
                    symbol: "<FirstThunk==0>".to_string(),
                });
            }

            let lookup = if oft_rva != 0 {
                base.add(oft_rva as usize) as *const native::ThunkData
            } else {
                warn!(
                    "imports: '{}' has no INT, using IAT as lookup table",
                    dll_name
                );
                base.add(ft_rva as usize) as *const native::ThunkData
            };

            let iat = base.add(ft_rva as usize) as *mut native::ThunkData;

            resolve_thunks_for_dll(module, &dll_name, lookup, iat, base)?;

            desc = desc.add(1);
        }
    }

    info!("imports: IAT resolved");
    Ok(())
}


/// Adjusts memory protections and returns the (Address, Size) of the main RX section (if found).
pub fn fix_memory_permissions(image: &PeImage, base: *mut u8) -> Result<Option<(usize, usize)>, PeError> {
    let section_count = image.nt_headers().file_header().NumberOfSections as usize;
    let mut rx_region: Option<(usize, usize)> = None;

    for idx in 0..section_count {
        let section = image.section_header(idx).ok_or(PeError::OutOfBounds)?;

        let virt_size = unsafe { section.Misc.VirtualSize };
        if section.VirtualAddress == 0 || (virt_size == 0 && section.SizeOfRawData == 0) {
            continue;
        }

        let read = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        let write = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        let exec = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        let protect = map_flags(read, write, exec);
        if protect == 0 {
            continue;
        }

        let addr = unsafe { base.add(section.VirtualAddress as usize) };
        let size = std::cmp::max(virt_size, section.SizeOfRawData) as usize;

        // --- Logic Update: Match C++ Reference ---
        // The reference only checks for EXECUTE and READ.
        // We log candidates to help debugging.
        if exec && read {
            // If we haven't found a region yet, or we found a "better" one (e.g., .text)
            // For now, we take the first Executable+Readable section we find.
            if rx_region.is_none() {
                info!("protect: found RX candidate at section {} (VA: 0x{:X}, Size: 0x{:X})", idx, section.VirtualAddress, size);
                rx_region = Some((addr as usize, size));
            }
        }

        let mut old = 0u32;
        let ok = unsafe { VirtualProtect(addr as _, size, protect, &mut old) };
        if ok == 0 {
            return Err(PeError::SectionProtectionFailed {
                name: format!("section_{}", idx),
            });
        }
    }

    Ok(rx_region)
}

/// Registers x64 unwind metadata for exception handling.
///
/// On x64, Windows requires a runtime function table to correctly unwind
/// the stack during exceptions.
#[cfg(target_pointer_width = "64")]
pub fn register_exception_handlers(image: &PeImage, base: *mut u8) -> Result<(), PeError> {
    let dir = image.exception_directory();
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        debug!("seh: no exception directory present");
        return Ok(());
    }

    unsafe {
        let table = base.add(dir.VirtualAddress as usize) as *const IMAGE_RUNTIME_FUNCTION_ENTRY;
        let count = (dir.Size as usize / size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>()) as u32;

        if !RtlAddFunctionTable(table, count, base as u64) {
            return Err(PeError::ExceptionHandlerRegistrationFailed);
        }
    }

    info!("seh: exception handlers registered");
    Ok(())
}

#[cfg(target_pointer_width = "32")]
pub fn register_exception_handlers(_: &PeImage, _: *mut u8) -> Result<(), PeError> {
    debug!("seh: not applicable on x86");
    Ok(())
}

/// Map flags R/W/X to Win32 protections. 0 => no applicable.
fn map_flags(read: bool, write: bool, execute: bool) -> u32 {
    match (read, write, execute) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, true, true) => PAGE_EXECUTE_WRITECOPY,
        (false, false, true) => PAGE_EXECUTE,

        (true, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        (false, true, false) => PAGE_WRITECOPY,

        _ => 0,
    }
}

/* -------------------------------------------------------------------------- */
/* Architecture-specific helpers                                              */
/* -------------------------------------------------------------------------- */

#[cfg(target_pointer_width = "64")]
#[inline]
fn arch_apply_reloc(addr: *mut u8, delta: usize) {
    unsafe {
        let v = ptr::read_unaligned(addr as *mut u64);
        ptr::write_unaligned(addr as *mut u64, v.wrapping_add(delta as u64));
    }
}

#[cfg(target_pointer_width = "32")]
#[inline]
fn arch_apply_reloc(addr: *mut u8, delta: usize) {
    unsafe {
        let v = ptr::read_unaligned(addr as *mut u32);
        ptr::write_unaligned(addr as *mut u32, v.wrapping_add(delta as u32));
    }
}

unsafe fn resolve_thunks_for_dll(
    module: HMODULE,
    dll: &str,
    mut lookup: *const native::ThunkData,
    mut iat: *mut native::ThunkData,
    base: *mut u8,
) -> Result<(), PeError> {
    while arch_thunk_aod(lookup) != 0 {
        let aod = arch_thunk_aod(lookup);

        let addr = if arch_is_ordinal(aod) {
            let ord = arch_extract_ordinal(aod);
            get_proc_address_ordinal(module, ord).ok_or_else(|| PeError::ImportResolveFailed {
                dll: dll.to_string(),
                symbol: format!("#{}", ord),
            })?
        } else {
            let ibn = base.add(aod as usize) as *const IMAGE_IMPORT_BY_NAME;
            let name_ptr = (*ibn).Name.as_ptr() as *const i8;
            let name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();

            get_proc_address_name(module, name_ptr as PCSTR).ok_or_else(|| PeError::ImportResolveFailed {
                dll: dll.to_string(),
                symbol: name,
            })?
        };

        arch_thunk_write_fn(iat, addr);

        lookup = lookup.add(1);
        iat = iat.add(1);
    }

    Ok(())
}

#[cfg(target_pointer_width = "64")]
#[inline]
unsafe fn arch_thunk_aod(thunk: *const native::ThunkData) -> u64 {
    (*thunk).u1.AddressOfData
}

#[cfg(target_pointer_width = "32")]
#[inline]
unsafe fn arch_thunk_aod(thunk: *const native::ThunkData) -> u32 {
    (*thunk).u1.AddressOfData
}

#[cfg(target_pointer_width = "64")]
#[inline]
fn arch_is_ordinal(aod: u64) -> bool {
    (aod & native::ORDINAL_FLAG) != 0
}

#[cfg(target_pointer_width = "32")]
#[inline]
fn arch_is_ordinal(aod: u32) -> bool {
    (aod & native::ORDINAL_FLAG) != 0
}

#[cfg(target_pointer_width = "64")]
#[inline]
fn arch_extract_ordinal(aod: u64) -> u16 {
    (aod & 0xFFFF) as u16
}

#[cfg(target_pointer_width = "32")]
#[inline]
fn arch_extract_ordinal(aod: u32) -> u16 {
    (aod & 0xFFFF) as u16
}

#[cfg(target_pointer_width = "64")]
#[inline]
unsafe fn arch_thunk_write_fn(thunk: *mut native::ThunkData, addr: usize) {
    (*thunk).u1.Function = addr as u64;
}

#[cfg(target_pointer_width = "32")]
#[inline]
unsafe fn arch_thunk_write_fn(thunk: *mut native::ThunkData, addr: usize) {
    (*thunk).u1.Function = addr as u32;
}

#[inline]
unsafe fn get_proc_address_name(module: HMODULE, name: PCSTR) -> Option<usize> {
    GetProcAddress(module, name).map(|fp| fp as usize)
}

#[inline]
unsafe fn get_proc_address_ordinal(module: HMODULE, ordinal: u16) -> Option<usize> {
    let p = ordinal as usize as *const u8;
    GetProcAddress(module, p as PCSTR).map(|fp| fp as usize)
}
