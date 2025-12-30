#![allow(non_snake_case)]
#![allow(dead_code)]

/*
    ARCHITECTURAL NOTE:
    This file is maintained as a reference implementation for an ergonomic "API Table" interface.

    The core library intentionally avoids providing this structured table to remain decoupled
    from specific type-binding crates (like `windows-sys` or `winapi`). By exposing only the
    `resolve_api!` macro, the library remains flexible, allowing the end-user to define
    their own function signatures and parameter types.

    Users can copy this pattern into their own projects to achieve lazy, on-demand
    API resolution with a singleton pattern while staying `no_std` compatible. Take in mind
    statics are not suitable for PIC payloads, so this pattern should be used with caution.
*/

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use windows_sys::core::PCSTR;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::Foundation::{CloseHandle, FreeLibrary, GetLastError, FARPROC, HANDLE, HMODULE, BOOL};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Diagnostics::Debug::{RtlAddFunctionTable, IMAGE_RUNTIME_FUNCTION_ENTRY, FlushInstructionCache};
use crate::resolve_api;

/// A structure providing lazy, on-demand access to Windows API functions.
///
/// Methods in this struct resolve function pointers via hashing only
/// upon their first invocation.
pub struct ApiTable;

/// Internal storage for the singleton instance.
static mut INSTANCE: Option<ApiTable> = None;

macro_rules! lazy_api {
    ($name:ident, $func_str:literal, $module:expr, $type:ty) => {
        pub fn $name(&self) -> $type {
            // Static storage for the resolved function pointer
            static CACHE: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

            let mut ptr = CACHE.load(Ordering::Relaxed);

            if ptr.is_null() {
                // Use the core library macro to resolve the symbol
                // Note: We unwrap here assuming the DLL and Symbol exist.
                // In production, consider more robust error handling.
                if let Ok(resolved) = resolve_api!($module, $func_str, $type) {
                    ptr = resolved as *mut c_void;
                    CACHE.store(ptr, Ordering::Relaxed);
                }
            }

            unsafe { core::mem::transmute(ptr) }
        }
    };
}

impl ApiTable {
    // --- Memory Management ---
    lazy_api!(VirtualAlloc, "VirtualAlloc", "kernel32.dll", unsafe extern "system" fn(*const c_void, usize, VIRTUAL_ALLOCATION_TYPE, PAGE_PROTECTION_FLAGS) -> *mut c_void);
    lazy_api!(VirtualProtect, "VirtualProtect", "kernel32.dll", unsafe extern "system" fn(*const c_void, usize, PAGE_PROTECTION_FLAGS, *mut PAGE_PROTECTION_FLAGS) -> BOOL);
    lazy_api!(VirtualFree, "VirtualFree", "kernel32.dll", unsafe extern "system" fn(*mut c_void, usize, VIRTUAL_FREE_TYPE) -> BOOL);
    lazy_api!(VirtualQuery, "VirtualQuery", "kernel32.dll", unsafe extern "system" fn(*const c_void, *mut MEMORY_BASIC_INFORMATION, usize) -> usize);

    // --- Process & Threading ---
    lazy_api!(CreateThread, "CreateThread", "kernel32.dll", unsafe extern "system" fn(*const SECURITY_ATTRIBUTES, usize, LPTHREAD_START_ROUTINE, *const c_void, THREAD_CREATION_FLAGS, *mut u32) -> HANDLE);
    lazy_api!(OpenProcess, "OpenProcess", "kernel32.dll", unsafe extern "system" fn(PROCESS_ACCESS_RIGHTS, BOOL, u32) -> HANDLE);
    lazy_api!(WriteProcessMemory, "WriteProcessMemory", "kernel32.dll", unsafe extern "system" fn(HANDLE, *const c_void, *const c_void, usize, *mut usize) -> BOOL);
    lazy_api!(ReadProcessMemory, "ReadProcessMemory", "kernel32.dll", unsafe extern "system" fn(HANDLE, *const c_void, *mut c_void, usize, *mut usize) -> BOOL);
    lazy_api!(CreateRemoteThread, "CreateRemoteThread", "kernel32.dll", unsafe extern "system" fn(HANDLE, *const SECURITY_ATTRIBUTES, usize, LPTHREAD_START_ROUTINE, *const c_void, u32, *mut u32) -> HANDLE);
    lazy_api!(WaitForSingleObject, "WaitForSingleObject", "kernel32.dll", unsafe extern "system" fn(HANDLE, u32) -> u32);

    // --- Module & Symbols ---
    lazy_api!(LoadLibraryA, "LoadLibraryA", "kernel32.dll", unsafe extern "system" fn(PCSTR) -> HMODULE);
    lazy_api!(GetModuleHandleA, "GetModuleHandleA", "kernel32.dll", unsafe extern "system" fn(PCSTR) -> HMODULE);
    lazy_api!(GetProcAddress, "GetProcAddress", "kernel32.dll", unsafe extern "system" fn(HMODULE, PCSTR) -> FARPROC);
    lazy_api!(FreeLibrary, "FreeLibrary", "kernel32.dll", unsafe extern "system" fn(HMODULE) -> BOOL);
    lazy_api!(RtlAddFunctionTable, "RtlAddFunctionTable", "ntdll.dll", unsafe extern "system" fn(*mut IMAGE_RUNTIME_FUNCTION_ENTRY, u32, u64) -> u8);

    // --- Native API / Low Level ---
    lazy_api!(FlushInstructionCache, "FlushInstructionCache", "kernel32.dll", unsafe extern "system" fn(HANDLE, *const c_void, usize) -> BOOL);

    // --- Diagnostics / Misc ---
    lazy_api!(GetLastError, "GetLastError", "kernel32.dll", unsafe extern "system" fn() -> u32);
    lazy_api!(CloseHandle, "CloseHandle", "kernel32.dll", unsafe extern "system" fn(HANDLE) -> BOOL);
}

/// Retrieves the global singleton instance of the `ApiTable`.
///
/// This function ensures that the `ApiTable` is initialized only once.
pub fn get_api_table() -> &'static ApiTable {
    unsafe {
        if INSTANCE.is_none() {
            INSTANCE = Some(ApiTable);
        }
        INSTANCE.as_ref().unwrap_unchecked()
    }
}