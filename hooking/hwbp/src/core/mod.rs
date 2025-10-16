pub mod breakpoint;
pub mod context;
pub mod thread;
pub mod veh;

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use std::ffi::CStr;

    use windows_sys::Win32::{
        Foundation::HWND,
        System::Diagnostics::Debug::CONTEXT,
        System::Threading::GetCurrentThreadId,
        UI::WindowsAndMessaging::{MB_OK, MessageBoxA},
    };

    use crate::detour::CallArgs;
    use crate::manager::{install_hwbp, uninstall_hwbp};

    /// Sets the Resume Flag (RF, bit 16) in EFLAGS so execution continues after the detour.
    ///
    /// Uses `CallArgs::as_mut_context_ptr()` to access the underlying CONTEXT.
    fn continue_execution(args: &mut CallArgs<'_>) {
        let ctx_ptr = args.as_mut_context_ptr();
        if ctx_ptr.is_null() {
            return;
        }
        unsafe {
            (*ctx_ptr).EFlags |= 1 << 16;
        }
    }

    /// Minimal detour for MessageBoxA.
    ///
    /// On x64 Windows ABI, the first four integer/pointer args are:
    /// 1: RCX (HWND), 2: RDX (LPCSTR lpText), 3: R8 (LPCSTR lpCaption), 4: R9 (UINT uType)
    ///
    /// We:
    ///  - print the original `lpText` and `lpCaption`,
    ///  - replace them,
    ///  - set `uType` to MB_ICONEXCLAMATION,
    ///  - set RF to resume.
    unsafe extern "system" fn message_box_a_detour(ctx: *mut CONTEXT) {
        if ctx.is_null() {
            return;
        }

        // SAFETY: VEH provides a valid pointer for the current thread's context.
        let mut args = unsafe { CallArgs::new(ctx) };

        #[cfg(target_arch = "x86_64")]
        {
            // Read current parameters via 1-based indices
            let _hwnd = unsafe { args.get(1) } as *const i8;
            let lp_text = unsafe { args.get(2) } as *const i8;
            let lp_caption = unsafe { args.get(3) } as *const i8;
            let _u_type = unsafe { args.get(4) };

            if !lp_text.is_null() {
                let text = unsafe { CStr::from_ptr(lp_text) }.to_string_lossy();
                log::debug!("MessageBoxA original text: {}", text);
            }
            if !lp_caption.is_null() {
                let cap = unsafe { CStr::from_ptr(lp_caption) }.to_string_lossy();
                log::debug!("MessageBoxA original caption: {}", cap);
            }

            // Overwrite: arg2 (lpText), arg3 (lpCaption), arg4 (uType)
            unsafe {
                args.set(2, b"This Is The Hook\0".as_ptr() as usize);
                args.set(3, b"MessageBoxADetour\0".as_ptr() as usize);
                args.set(4, 0x00000040); // MB_ICONEXCLAMATION
            }
        }

        // Ensure execution continues after returning from the detour
        continue_execution(&mut args);
    }

    /// Installs and triggers an HWBP hook on `MessageBoxA`, then uninstalls it.
    ///
    /// Flow:
    /// 1) Show a normal MessageBoxA (unhooked).
    /// 2) Install HWBP via public API (VEH auto-initializes).
    /// 3) Show a MessageBoxA to trigger the detour and parameter rewrite.
    /// 4) Uninstall using `uninstall_hwbp`.
    /// 5) Show a normal MessageBoxA again.
    #[test]
    fn test_messageboxa_detour_hook() {
        unsafe {
            // Baseline (unhooked)
            MessageBoxA(
                0 as HWND,
                b"This is a normal MsgBoxA call (0)\0".as_ptr(),
                b"Normal\0".as_ptr(),
                MB_OK,
            );

            // Install HWBP for all threads (public API; DRx auto-selected)
            install_hwbp(
                MessageBoxA as *const c_void,
                message_box_a_detour as *const c_void,
            )
            .expect("Failed to install HWBP hook on MessageBoxA");

            // Optional sanity: ensure at least one registry entry exists for this TID
            // (we don't assert DRx because selection is automatic)
            let _cur_tid = GetCurrentThreadId() as usize;

            // Trigger the detour
            MessageBoxA(
                0 as HWND,
                b"This won't execute\0".as_ptr(),
                b"Will it?\0".as_ptr(),
                MB_OK,
            );

            // Uninstall (removes from all threads where installed)
            uninstall_hwbp(MessageBoxA as *const c_void)
                .expect("Failed to uninstall HWBP hook for MessageBoxA");

            // Back to normal
            MessageBoxA(
                0 as HWND,
                b"This is a normal MsgBoxA call (1)\0".as_ptr(),
                b"Normal\0".as_ptr(),
                MB_OK,
            );
        }
    }
}
