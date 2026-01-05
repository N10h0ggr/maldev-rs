#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_void, CStr, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use log::{debug, info, warn};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HEAP_ZERO_MEMORY};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_EXPORT_DIRECTORY, PIMAGE_TLS_CALLBACK,
};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};

use crate::arch::native;
use crate::errors::PeError;
use crate::pe_parser::PeImage;

/// DLL entry point type (`DllMain`).
type DllMain = unsafe extern "system" fn(hinst_dll: *mut c_void, reason: u32, reserved: *mut c_void) -> i32;

/// EXE entry point type (CRT startup).
type ExeEntry = unsafe extern "system" fn();

/// Minimal `UNICODE_STRING` layout used by user-mode PEB structures.
///
/// Note: the x64 layout includes padding after the two `u16` fields.
#[repr(C)]
#[derive(Copy, Clone)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    #[cfg(target_pointer_width = "64")]
    _pad: u32,
    buffer: *mut u16,
}

/* -------------------------------------------------------------------------- */
/* PEB access                                                                 */
/* -------------------------------------------------------------------------- */

/// Returns the address of the Process Environment Block (PEB).
///
/// # Safety
///
/// Uses architecture-specific segment registers (FS/GS).
#[inline(always)]
unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;

    #[cfg(target_arch = "x86_64")]
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);

    #[cfg(target_arch = "x86")]
    core::arch::asm!(
    "mov {}, fs:[0x30]",
    out(reg) peb,
    options(nomem, nostack, preserves_flags),
    );

    peb
}

#[inline]
const fn peb_process_parameters_offset() -> usize {
    if cfg!(target_pointer_width = "64") { 0x20 } else { 0x10 }
}

#[inline]
const fn rtl_user_process_parameters_image_path_offset() -> usize {
    if cfg!(target_pointer_width = "64") { 0x60 } else { 0x38 }
}

#[inline]
const fn rtl_user_process_parameters_command_line_offset() -> usize {
    if cfg!(target_pointer_width = "64") { 0x70 } else { 0x40 }
}

/* -------------------------------------------------------------------------- */
/* Command line patching                                                      */
/* -------------------------------------------------------------------------- */

/// Replaces the process command line in the PEB using the *current* process image path as argv[0].
///
/// This is mostly kept for compatibility. Prefer [`fix_arguments_for_image`]
/// when executing a manually mapped image so argv[0] matches the mapped PE path.
pub fn fix_arguments(args: &[String]) -> Result<(), PeError> {
    debug!("patching PEB command line (argv[0] = current image path)");

    unsafe {
        let peb = get_peb();
        if peb.is_null() {
            return Err(PeError::InvalidPeb);
        }

        let params = *(peb.add(peb_process_parameters_offset()) as *mut *mut u8);
        if params.is_null() {
            return Err(PeError::InvalidProcessParameters);
        }

        let image_path = &*(params.add(rtl_user_process_parameters_image_path_offset()) as *const UnicodeString);
        let cmd_line = params.add(rtl_user_process_parameters_command_line_offset()) as *mut UnicodeString;

        let image_wide = std::slice::from_raw_parts(image_path.buffer, (image_path.length / 2) as usize);
        patch_command_line_with_argv0(image_wide, cmd_line, args)
    }
}

/// Replaces the process command line in the PEB using `image_path` as argv[0].
///
/// This is the variant you want for manual mapping: many programs rely on argv[0]
/// and/or the full command line format to decide behavior.
///
/// Example (what gets written into the PEB):
/// `"C:\path\mimikatz.exe" coffee exit`
///
/// # Parameters
/// - `image_path`: path of the PE you are executing (becomes argv[0])
/// - `args`: remaining command-line tokens
pub fn fix_arguments_for_image<P: AsRef<Path>>(image_path: P, args: &[String]) -> Result<(), PeError> {
    debug!("patching PEB command line (argv[0] = mapped image path)");

    let mut argv0: Vec<u16> = Vec::new();
    argv0.extend(OsStr::new(image_path.as_ref().as_os_str()).encode_wide());

    unsafe {
        let peb = get_peb();
        if peb.is_null() {
            return Err(PeError::InvalidPeb);
        }

        let params = *(peb.add(peb_process_parameters_offset()) as *mut *mut u8);
        if params.is_null() {
            return Err(PeError::InvalidProcessParameters);
        }

        let cmd_line = params.add(rtl_user_process_parameters_command_line_offset()) as *mut UnicodeString;
        patch_command_line_with_argv0(&argv0, cmd_line, args)
    }
}

unsafe fn patch_command_line_with_argv0(
    argv0_wide: &[u16],
    cmd_line: *mut UnicodeString,
    args: &[String],
) -> Result<(), PeError> {
    // Build: "argv0" arg1 arg2 ...
    let mut new_cmd: Vec<u16> = Vec::new();

    // Quote argv[0] to preserve spaces.
    new_cmd.push(b'"' as u16);
    new_cmd.extend_from_slice(argv0_wide);
    new_cmd.push(b'"' as u16);

    for arg in args {
        new_cmd.push(b' ' as u16);
        new_cmd.extend(OsStr::new(arg).encode_wide());
    }

    // Trailing NUL terminator.
    new_cmd.push(0);

    let needed_bytes = new_cmd.len() * 2;

    if needed_bytes <= (*cmd_line).maximum_length as usize && !(*cmd_line).buffer.is_null() {
        debug!("command line fits existing buffer; overwriting in-place");
        ptr::copy_nonoverlapping(new_cmd.as_ptr(), (*cmd_line).buffer, new_cmd.len());
        (*cmd_line).length = (needed_bytes - 2) as u16;
        return Ok(());
    }

    warn!("command line buffer too small (or null); allocating new heap block");

    let heap = GetProcessHeap();
    let buf = HeapAlloc(heap, HEAP_ZERO_MEMORY, needed_bytes);
    if buf.is_null() {
        return Err(PeError::HeapAllocationFailed);
    }

    ptr::copy_nonoverlapping(new_cmd.as_ptr(), buf as *mut u16, new_cmd.len());

    (*cmd_line).buffer = buf as *mut u16;
    (*cmd_line).length = (needed_bytes - 2) as u16;
    (*cmd_line).maximum_length = needed_bytes as u16;

    Ok(())
}

/* -------------------------------------------------------------------------- */
/* TLS callbacks                                                              */
/* -------------------------------------------------------------------------- */

/// Executes TLS callbacks for a manually mapped PE image.
///
/// TLS callbacks (if present) must run before the entry point.
pub fn execute_tls_callbacks(image: &PeImage, base: *mut u8) -> Result<(), PeError> {
    let dir = image.tls_directory();
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return Ok(());
    }

    unsafe {
        let tls = base.add(dir.VirtualAddress as usize) as *const native::TlsDirectory;
        let mut cb = (*tls).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;

        while let Some(func) = *cb {
            debug!("executing TLS callback");
            func(base as _, DLL_PROCESS_ATTACH, ptr::null_mut());
            cb = cb.add(1);
        }
    }

    Ok(())
}

/* -------------------------------------------------------------------------- */
/* Entry points                                                               */
/* -------------------------------------------------------------------------- */

/// Transfers execution to an EXE entry point.
pub fn execute_exe_entry_point(image: &PeImage, base: *mut u8) -> Result<(), PeError> {
    let rva = image.nt_headers().entry_point_rva();
    if rva == 0 {
        return Err(PeError::MissingEntryPoint);
    }

    let entry = unsafe { mem::transmute::<*mut u8, ExeEntry>(base.add(rva as usize)) };

    debug!("executing EXE entry point");
    unsafe { entry() };

    Ok(())
}

/// Invokes `DllMain(DLL_PROCESS_ATTACH)`.
pub fn execute_dll_main(image: &PeImage, base: *mut u8) -> Result<(), PeError> {
    let rva = image.nt_headers().entry_point_rva();
    if rva == 0 {
        return Ok(());
    }

    let dll_main = unsafe { mem::transmute::<*mut u8, DllMain>(base.add(rva as usize)) };

    debug!("calling DllMain(DLL_PROCESS_ATTACH)");
    unsafe {
        dll_main(base as *mut c_void, DLL_PROCESS_ATTACH, ptr::null_mut());
    }

    Ok(())
}

/* -------------------------------------------------------------------------- */
/* Exports                                                                    */
/* -------------------------------------------------------------------------- */

/// Resolves the virtual address of an exported function by name.
fn find_export(image: &PeImage, base: *mut u8, name: &str) -> Result<*mut c_void, PeError> {
    let dir = image.export_directory();
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return Err(PeError::ExportDirectoryMissing);
    }

    unsafe {
        let exp = base.add(dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names = base.add((*exp).AddressOfNames as usize) as *const u32;
        let ordinals = base.add((*exp).AddressOfNameOrdinals as usize) as *const u16;
        let funcs = base.add((*exp).AddressOfFunctions as usize) as *const u32;

        for i in 0..(*exp).NumberOfNames {
            let rva = *names.add(i as usize);
            let ptr = base.add(rva as usize) as *const i8;

            if CStr::from_ptr(ptr).to_string_lossy() == name {
                let ord = *ordinals.add(i as usize) as usize;
                return Ok(base.add(*funcs.add(ord) as usize) as *mut c_void);
            }
        }
    }

    Err(PeError::ExportNotFound(name.to_string()))
}

/// Resolves and executes a named exported function in a DLL.
pub fn execute_requested_export(image: &PeImage, base: *mut u8, export_name: Option<&str>) -> Result<(), PeError> {
    let Some(name) = export_name else { return Ok(()); };

    if !image.is_dll() {
        return Err(PeError::ExportOnNonDll);
    }

    let addr = find_export(image, base, name)?;
    let thread_proc: unsafe extern "system" fn(*mut c_void) -> u32 = unsafe { mem::transmute(addr) };

    info!("executing exported function '{}'", name);

    let thread = unsafe {
        CreateThread(
            ptr::null_mut(),
            0,
            Some(thread_proc),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };

    if thread.is_null() {
        return Err(PeError::CreateThreadFailed(unsafe { GetLastError() }));
    }

    let wait = unsafe { WaitForSingleObject(thread, u32::MAX) };
    unsafe { CloseHandle(thread) };

    if wait != WAIT_OBJECT_0 {
        return Err(PeError::ExportThreadJoinFailed);
    }

    Ok(())
}
