//! Portable Executable (PE) parsing utilities for Windows binaries.
//!
//! These helpers wrap low-level pointer math and PE structure parsing
//! using the `windows-sys` crate. Designed for use in analysis, tooling,
//! and introspection of Windows binaries.
//!
//! Compatible with Rust 1.77+ (uses `offset_of!`).

use std::mem;
use std::slice;
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE};

/// Reads and validates the DOS header from a PE image buffer.
///
/// Returns a reference to the `IMAGE_DOS_HEADER` if valid.
///
/// # Errors
/// Returns an error string if:
/// - The buffer is too small
/// - The header signature is invalid
pub fn parse_dos_header<'a>(buffer: &'a [u8]) -> Result<&'a IMAGE_DOS_HEADER, &'static str> {
    if buffer.len() < mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err("file too small for DOS header");
    }

    let dos_hdr = unsafe { &*(buffer.as_ptr() as *const IMAGE_DOS_HEADER) };
    if dos_hdr.e_magic != 0x5A4D {
        // 'MZ'
        return Err("invalid DOS header signature");
    }

    Ok(dos_hdr)
}

/// Reads and validates the NT headers (`IMAGE_NT_HEADERS64`) from a PE image buffer.
///
/// Uses the `e_lfanew` offset from the DOS header to locate the NT headers.
/// Returns a reference to the NT headers if the PE signature is valid.
///
/// # Errors
/// Returns an error string if:
/// - The offset is invalid
/// - The PE signature is incorrect
pub fn parse_nt_headers<'a>(
    buffer: &'a [u8],
    dos_hdr: &IMAGE_DOS_HEADER,
) -> Result<&'a IMAGE_NT_HEADERS64, &'static str> {
    let nt_offset = dos_hdr.e_lfanew as usize;

    if buffer.len() < nt_offset + mem::size_of::<IMAGE_NT_HEADERS64>() {
        return Err("invalid NT header offset");
    }

    let nt_hdrs = unsafe { &*((buffer.as_ptr().add(nt_offset)) as *const IMAGE_NT_HEADERS64) };
    if nt_hdrs.Signature != IMAGE_NT_SIGNATURE {
        return Err("invalid PE signature");
    }

    Ok(nt_hdrs)
}

/// Returns a pointer to the first `IMAGE_SECTION_HEADER` given a valid NT headers pointer.
///
/// This is equivalent to the C macro:
/// ```c
/// #define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) ((ULONG_PTR) ntheader + \
///     FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + \
///     ((ntheader)->FileHeader.SizeOfOptionalHeader)))
/// ```
///
/// # Safety
/// Caller must ensure `nt` points to a valid `IMAGE_NT_HEADERS64` structure.
#[inline(always)]
pub unsafe fn image_first_section(nt: *const IMAGE_NT_HEADERS64) -> *const IMAGE_SECTION_HEADER {
    (nt as usize
        + std::mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)
        + (*nt).FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER
}

/// Returns a slice of all section headers in the PE image.
///
/// Calculates the base address of the section table and returns all section
/// headers as a slice.
///
/// # Errors
/// Returns an error string if:
/// - The image reports zero sections
/// - The table lies beyond the end of the buffer
///
/// # Safety
/// Performs unchecked pointer arithmetic on raw binary data.
pub fn list_sections<'a>(
    buffer: &'a [u8],
    nt_hdrs: &IMAGE_NT_HEADERS64,
) -> Result<&'a [IMAGE_SECTION_HEADER], &'static str> {
    let num_sections = nt_hdrs.FileHeader.NumberOfSections as usize;
    if num_sections == 0 {
        return Err("no section headers found");
    }

    let sec_start =
        unsafe { image_first_section(nt_hdrs as *const _) as usize - buffer.as_ptr() as usize };
    let needed_size = sec_start + num_sections * mem::size_of::<IMAGE_SECTION_HEADER>();

    if buffer.len() < needed_size {
        return Err("section table out of bounds");
    }

    let sections = unsafe {
        slice::from_raw_parts(
            buffer.as_ptr().add(sec_start) as *const IMAGE_SECTION_HEADER,
            num_sections,
        )
    };
    Ok(sections)
}

/// Retrieves a pointer to the Export Directory of a given module.
///
/// This function parses the PE headers starting from the DOS Header to find the 
/// Export Directory in the Optional Header's Data Directory.
///
/// # Arguments
/// * `h_module` - The base address (handle) of the module.
///
/// # Returns
/// * `Option<*const IMAGE_EXPORT_DIRECTORY>` - Pointer to the export directory if found.
unsafe fn get_export_directory(h_module: HMODULE) -> Option<*const IMAGE_EXPORT_DIRECTORY> {
    let base_addr = h_module as usize;

    // Get DOS Header
    let p_dos_header = base_addr as *const IMAGE_DOS_HEADER;
    if (*p_dos_header).e_magic != 0x5A4D { // "MZ"
        return None;
    }

    // Get NT Headers (DOS Header + e_lfanew)
    let p_nt_headers = (base_addr + (*p_dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*p_nt_headers).Signature != 0x00004550 { // "PE\0\0"
        return None;
    }

    // Get Export Directory Entry from Data Directory
    // Index 0 is always the Export Directory
    let export_entry = (*p_nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

    if export_entry.VirtualAddress == 0 {
        return None;
    }

    // Calculate absolute address (Base + RVA)
    let p_export_dir = (base_addr + export_entry.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

    Some(p_export_dir)
}
