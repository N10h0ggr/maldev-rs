use std::{mem, ptr, slice};
use std::ffi::{c_void, CStr};
use std::mem::size_of;

use windows::core::{PCSTR, s, w};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect};
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxA, MessageBoxW};

#[cfg(target_pointer_width = "64")]
const TRAMPOLINE_SIZE: usize = 13;

#[cfg(target_pointer_width = "32")]
const TRAMPOLINE_SIZE: usize = 7;

pub struct Hook {
    p_function_to_hook: *const u8,
    p_function_to_run: *const u8,
    v_original_bytes: Vec<u8>,
    dw_old_protection: *mut PAGE_PROTECTION_FLAGS,
}

impl Hook {
    pub unsafe fn new(p_function_to_hook: *const u8, p_function_to_run: *const u8) -> Option<Self> {
        if p_function_to_hook.is_null() || p_function_to_run.is_null() {
            return None;
        }

        let mut hook = Self {
            p_function_to_hook,
            p_function_to_run,
            v_original_bytes: Vec::new(),
            dw_old_protection: &mut PAGE_PROTECTION_FLAGS::default(),
        };

        hook.v_original_bytes = slice::from_raw_parts(p_function_to_hook, TRAMPOLINE_SIZE).to_vec();

        // Changing the protection to RWX to be able to modify the bytes
        // Saving the old protection to the struct (to re-place it at cleanup)
        VirtualProtect(p_function_to_hook as *const c_void, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, hook.dw_old_protection)
            .unwrap_or_else(|e| {
                panic!("[!] Create Hook: VirtualProtect Failed With Error: {e}");
            });

        Some(hook)
    }
}

pub fn install_hook(hook: &Hook) {
    #[cfg(target_pointer_width = "64")]
        let trampoline = prepare_x64_trampoline(&hook);
    #[cfg(target_pointer_width = "32")]
        let trampoline = prepare_x32_trampoline(&hook);

    unsafe {ptr::copy_nonoverlapping(
        trampoline.as_ptr(),                // Source pointer
        hook.p_function_to_hook as *mut u8, // Destination pointer
        trampoline.len()                    // Number of bytes to copy
    );}
}

pub fn prepare_x64_trampoline(hook: &Hook) -> Vec<u8> {
    let mut trampoline: Vec<u8> =  vec![
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
        0x41, 0xFF, 0xE2                                            // jmp r10
    ];

    let sliced_p_function_to_hook: [u8; 8] = unsafe { mem::transmute(hook.p_function_to_run as u64) };
    trampoline.splice(2..10, sliced_p_function_to_hook.iter().cloned());
    trampoline
}

pub fn prepare_x32_trampoline(hook: &Hook) -> Vec<u8> {
    let mut trampoline: Vec<u8> = vec![
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, pFunctionToRun
        0xFF, 0xE0                    // jmp eax
    ];
    unsafe {
        let source = slice::from_raw_parts(hook.p_function_to_hook, size_of::<usize>());
        trampoline[1..].copy_from_slice(source);
    }
    trampoline
}

pub fn remove_hook(mut hook: Hook) {
    // memcpy: copying the original bytes over
    unsafe {ptr::copy_nonoverlapping(
        hook.v_original_bytes.as_ptr(),     // Source pointer
        hook.p_function_to_hook as *mut u8, // Destination pointer
        TRAMPOLINE_SIZE,                    // Number of bytes to copy
    );
        // cleaning up our buffer
        hook.v_original_bytes.clear();
        // setting the old memory protection back
        VirtualProtect(hook.p_function_to_hook as *const c_void, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, hook.dw_old_protection)
            .unwrap_or_else(|e| {
                panic!("[!] Remove Hook: VirtualProtect Failed With Error: {e}");
            });
    }
    hook.p_function_to_hook = ptr::null();
    hook.p_function_to_run = ptr::null();
    hook.dw_old_protection = &mut PAGE_PROTECTION_FLAGS::default();
}

pub fn my_message_box_a(hwnd: HWND, p_text: PCSTR, p_caption: PCSTR, u_type: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    // Print original parameters
    println!("[+] Original Parameters:");
    unsafe {
        let s_text = CStr::from_ptr(p_text.0 as *const i8).to_str().expect("Invalid UTF-8 string");
        let s_caption = CStr::from_ptr(p_caption.0 as *const i8).to_str().expect("Invalid UTF-8 string");
        println!("\t - p_text   : {}", s_text);
        println!("\t - p_caption: {}", s_caption);
    }

    // Call MessageBoxW with modified parameters
    let new_text = w!("Malware Development Is Cool");
    let new_caption = w!("Hooked MsgBox");
    unsafe { MessageBoxW(hwnd, new_text, new_caption, u_type) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::s;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{MB_OK, MB_ICONQUESTION, MB_ICONWARNING, MB_ICONINFORMATION};

    #[test]
    fn test_hook_message_box_a() {
        let text = s!("What Do You Think About Malware Development?");
        let caption = s!("Question MsgBox");
        unsafe { MessageBoxA(HWND(0), text, caption, MB_OK | MB_ICONQUESTION); }

        let function_to_hook= MessageBoxA::<HWND, PCSTR, PCSTR> as *const u8;
        let function_to_run= my_message_box_a as *const u8;

        let hook = unsafe { Hook::new(function_to_hook, function_to_run) }
            .expect("[!] Failed to initialize hook structure.");

        println!("[i] Installing The Hook ... ");
        install_hook(&hook);
        println!("[+] DONE");

        let text = s!("Malware Development Is Bad");
        let caption = s!("Response MsgBox");
        unsafe { MessageBoxA(HWND(0), text, caption, MB_OK | MB_ICONWARNING); }

        println!("[i] Removing The Hook ... ");
        remove_hook(hook);
        println!("[+] DONE");

        let text = s!("Normal MsgBox Again");
        let caption = s!("Final MsgBox");
        unsafe { MessageBoxA(HWND(0), text, caption, MB_OK | MB_ICONINFORMATION); }
    }
}
