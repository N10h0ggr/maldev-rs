use core::ptr;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, PIMAGE_TLS_CALLBACK};
use crate::arch::native;
use crate::parser::PeImage;

/// Executes TLS callbacks for a manually mapped PE image.
///
/// TLS callbacks (if present) must run before the entry point.
pub fn execute_tls_callbacks(image: &PeImage, base: *mut u8) -> Result<(), ()> {
    let dir = image.tls_directory();
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return Ok(());
    }

    unsafe {
        let tls = base.add(dir.VirtualAddress as usize) as *const native::TlsDirectory;
        let mut cb = (*tls).AddressOfCallBacks as *const PIMAGE_TLS_CALLBACK;

        while let Some(func) = *cb {
            func(base as _, DLL_PROCESS_ATTACH, ptr::null_mut());
            cb = cb.add(1);
        }
    }

    Ok(())
}

