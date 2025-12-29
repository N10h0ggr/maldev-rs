#![no_std]
#![feature(alloc_error_handler)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod arch;
mod mapper;
mod parser;
mod executor;
mod utils;

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::ptr;
use core::panic::PanicInfo;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY,
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_ICONINFORMATION, MB_OK};
use api_hashing::resolve_api;
use crate::executor::execute_tls_callbacks;
use crate::mapper::{fix_imports, fix_memory_permissions, fix_reloc, register_exception_handlers};
use crate::parser::PeImage;
use crate::utils::{crc32_runtime, get_image_size_raw, get_module_handle_h, get_proc_address_h};

// Function pointer signatures for bootstrapping APIs
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

/// Entry point for the reflective loader.
///
/// This function is responsible for manual mapping the PE into the current process memory.
/// It operates without a functional IAT until the mapping process is complete.
#[unsafe(no_mangle)]
pub extern "system" fn my_reflective_fun(lp_base_address: *mut c_void) -> u32 {
    // We wrap the logic in a closure to use the '?' operator for clean error propagation
    // while satisfying the u32 return requirement of the exported function.
    let bootstrap = || unsafe {
        let size_of_image = get_image_size_raw(lp_base_address);
        if size_of_image == 0 { return Err(()); }

        // Resolve Kernel32 early to bootstrap memory allocation and cache synchronization
        let h_kernel32 = get_module_handle_h(crc32_runtime("kernel32.dll")).map_err(|_| ())?;

        let p_virtual_alloc = get_proc_address_h(h_kernel32, crc32_runtime("VirtualAlloc")).map_err(|_| ())?;
        let virtual_alloc: VirtualAllocFn = core::mem::transmute(p_virtual_alloc);

        // Allocate the final buffer for the virtual image.
        let p_local_image = virtual_alloc(
            ptr::null_mut(),
            size_of_image,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if p_local_image.is_null() { return Err(()); }

        // Copying headers and sections transforms the data from 'File alignment' to 'Virtual alignment'
        utils::copy_pe_image(lp_base_address, p_local_image);

        let pe = PeImage::parse_from_ptr(p_local_image).map_err(|_| ())?;

        // Process mandatory PE metadata to make the image executable and compatible
        fix_imports(&pe, p_local_image as *mut u8).map_err(|_| ())?;
        fix_reloc(&pe, p_local_image as *mut u8).map_err(|_| ())?;
        fix_memory_permissions(&pe, p_local_image as *mut u8).map_err(|_| ())?;

        // Optional handlers that improve stability and support modern binary features
        let _ = register_exception_handlers(&pe, p_local_image as *mut u8);
        let _ = execute_tls_callbacks(&pe, p_local_image as *mut u8);

        // Notify the CPU that new instructions have been written to memory.
        // This prevents the execution of stale or invalid cache lines.
        let p_flush_cache = get_proc_address_h(h_kernel32, crc32_runtime("FlushInstructionCache")).map_err(|_| ())?;
        let flush_instruction_cache: FlushInstructionCacheFn = core::mem::transmute(p_flush_cache);
        flush_instruction_cache(-1isize as *mut c_void, ptr::null_mut(), 0);

        // Jump to the entry point of the now-mapped binary
        let entry_point_rva = pe.nt_headers().entry_point_rva();
        let entry_point: DllMainFn = core::mem::transmute(p_local_image.add(entry_point_rva as usize));

        entry_point(p_local_image, 1, ptr::null_mut());

        Ok(())
    };

    match bootstrap() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

// --- DLL PAYLOAD ---

/// This represents the actual work your DLL performs after being successfully mapped.
fn payload_function() {
    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            "Reflective Loading Successful!\0".as_ptr(),
            "Rust Mapper\0".as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _h_module: *mut c_void,
    dw_reason: u32,
    _lp_reserved: *mut c_void,
) -> i32 {
    // DLL_PROCESS_ATTACH = 1
    if dw_reason == 1 {
        payload_function();
    }
    1
}

// --- RUNTIME SUPPORT ---

#[global_allocator]
static ALLOCATOR: Win32Heap = Win32Heap;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // In a no_std reflective DLL, we spin on panic to avoid calling uninitialized OS handlers
    loop { core::hint::spin_loop(); }
}

/// Simple Global Allocator that redirects to the Windows Process Heap.
/// This is only safe to use after the 'kernel32.dll' imports have been resolved.
struct Win32Heap;
unsafe impl GlobalAlloc for Win32Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, layout.size()) as *mut u8
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        HeapFree(GetProcessHeap(), 0, _ptr as _);
    }
}