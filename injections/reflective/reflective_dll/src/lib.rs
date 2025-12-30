#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![allow(unsafe_op_in_unsafe_fn)]

mod arch;
mod mapper;
mod parser;
mod executor;
mod utils;

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::ptr;
use core::panic::PanicInfo;

use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY,
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE
};
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_ICONINFORMATION, MB_OK};

use api_hasher::resolve_api;
use crate::executor::execute_tls_callbacks;
use crate::mapper::{fix_imports, fix_memory_permissions, fix_reloc, register_exception_handlers};
use crate::parser::PeImage;

// --- Types & Constants ---

#[derive(Debug)]
pub enum LoaderError {
    InvalidImageSize,
    ApiResolutionFailed,
    MemoryAllocationFailed,
    PeParsingFailed,
    ImportFixFailed,
    RelocationFixFailed,
    PermissionFixFailed,
}

type VirtualAllocFn = unsafe extern "system" fn(
    lpaddress: *const c_void,
    dwsize: usize,
    flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    flprotect: PAGE_PROTECTION_FLAGS
) -> *mut c_void;

type FlushInstructionCacheFn = unsafe extern "system" fn(
    process_handle: *mut c_void,
    base_address: *const c_void,
    size: usize,
) -> i32;

type DllMainFn = unsafe extern "system" fn(
    module_base: *mut c_void,
    reason: u32,
    reserved: *mut c_void,
) -> i32;

// --- Core Logic ---

#[unsafe(no_mangle)]
pub extern "system" fn my_reflective_fun(lp_base_address: *mut c_void) -> u32 {
    match unsafe { reflective_loader_impl(lp_base_address) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// The internal implementation using idiomatic Result-based error handling.
unsafe fn reflective_loader_impl(lp_base_address: *mut c_void) -> Result<(), LoaderError> {
    let size_of_image = utils::get_image_size_raw(lp_base_address);
    if size_of_image == 0 {
        return Err(LoaderError::InvalidImageSize);
    }

    // Resolve bootstrapping APIs
    let virtual_alloc = resolve_api!("kernel32.dll", "VirtualAlloc", VirtualAllocFn)
        .map_err(|_| LoaderError::ApiResolutionFailed)?;

    let p_local_image = virtual_alloc(
        ptr::null_mut(),
        size_of_image,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    );

    if p_local_image.is_null() {
        return Err(LoaderError::MemoryAllocationFailed);
    }

    // Map PE sections
    utils::copy_pe_image(lp_base_address, p_local_image);

    let pe = PeImage::parse_from_ptr(p_local_image)
        .map_err(|_| LoaderError::PeParsingFailed)?;

    // Process PE structures
    fix_imports(&pe, p_local_image as *mut u8).map_err(|_| LoaderError::ImportFixFailed)?;
    fix_reloc(&pe, p_local_image as *mut u8).map_err(|_| LoaderError::RelocationFixFailed)?;
    fix_memory_permissions(&pe, p_local_image as *mut u8).map_err(|_| LoaderError::PermissionFixFailed)?;

    // Optional modern features
    let _ = register_exception_handlers(&pe, p_local_image as *mut u8);
    let _ = execute_tls_callbacks(&pe, p_local_image as *mut u8);

    // Cache coherency
    let flush_cache = resolve_api!("kernel32.dll", "FlushInstructionCache", FlushInstructionCacheFn)
        .map_err(|_| LoaderError::ApiResolutionFailed)?;

    // -1 is the pseudo-handle for current process
    flush_cache(-1isize as *mut c_void, ptr::null_mut(), 0);

    // Call Entry Point
    let entry_point_rva = pe.nt_headers().entry_point_rva();
    let entry_point: DllMainFn = core::mem::transmute(p_local_image.add(entry_point_rva as usize));

    entry_point(p_local_image, DLL_PROCESS_ATTACH, ptr::null_mut());

    Ok(())
}

// --- DLL PAYLOAD ---

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _h_module: *mut c_void,
    dw_reason: u32,
    _lp_reserved: *mut c_void,
) -> i32 {
    if dw_reason == DLL_PROCESS_ATTACH {
        payload_function();
    }
    1
}

fn payload_function() {
    let msg = b"Reflective Loading Successful!\0";
    let title = b"Rust Mapper\0";
    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

// --- RUNTIME SUPPORT ---

#[global_allocator]
static ALLOCATOR: Win32Heap = Win32Heap;

struct Win32Heap;

unsafe impl GlobalAlloc for Win32Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Alignment is ignored here for simplicity;
        // in production, use HeapAlloc with alignment adjustments if needed.
        let ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, layout.size());
        ptr as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        HeapFree(GetProcessHeap(), 0, ptr as *mut c_void);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}