
use std::ffi::c_void;
use std::{ptr, slice};
use std::mem::size_of;
use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
#[cfg(target_pointer_width = "64")]
const TRAMPOLINE_SIZE: usize = 13;

#[cfg(target_pointer_width = "32")]
const TRAMPOLINE_SIZE: usize = 7;

struct Hook {
    p_function_to_hook: *mut c_void,
    p_function_to_run: *mut c_void,
    p_original_bytes: [u8; TRAMPOLINE_SIZE],
    dw_old_protection: *mut PAGE_PROTECTION_FLAGS,
}

impl Hook {
    fn new(p_function_to_hook: *mut c_void, p_function_to_run: *mut c_void) -> Option<Self> {
        if p_function_to_hook.is_null() || p_function_to_run.is_null() {
            return None;
        }

        let mut hook = Self {
            p_function_to_hook,
            p_function_to_run,
            p_original_bytes: [0; TRAMPOLINE_SIZE],
            dw_old_protection: Default::default(),
        };

        unsafe {
            // Copy original bytes to be able to do cleanups
            let source = slice::from_raw_parts(p_function_to_hook as *const u8, TRAMPOLINE_SIZE);
            hook.p_original_bytes.copy_from_slice(source);

            // Changing the protection to RWX to be able to modify the bytes
            // Saving the old protection to the struct (to re-place it at cleanup)
            VirtualProtect(p_function_to_hook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, hook.dw_old_protection)
                .unwrap_or_else(|e| {
                    panic!("[!] Create Hook: VirtualProtect Failed With Error: {e}");
                });
        }

        Some(hook)
    }
}

fn install_hook(hook: Hook){

    #[cfg(target_pointer_width = "64")]
        let trampoline = prepare_x64_trampoline(&hook);

    #[cfg(target_pointer_width = "32")]
        let trampoline = prepare_x32_trampoline(&hook);

    hook.p_function_to_hook.copy_from_slice(trampoline);
}

fn prepare_x64_trampoline(hook: &Hook) -> [u8; 13]{
    let mut trampoline: [u8; 13] = [
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
        0x41, 0xFF, 0xE2                                            // jmp r10
    ];

    unsafe {
        // Copy function pointer and embed it to trampoline
        let source = slice::from_raw_parts(hook.p_function_to_hook as *const u8, size_of::<u64>());
        trampoline[2].copy_from_slice(source);
    }
    trampoline
}

fn prepare_x32_trampoline(hook: &Hook) -> [u8; 7]{
    let trampoline: [u8; 7] = [
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, pFunctionToRun
        0xFF, 0xE0                    // jmp eax
    ];
    unsafe {
        let source = slice::from_raw_parts(hook.p_function_to_hook as *const u8, size_of::<u32>());
        trampoline[1].copy_from_slice(source);
    }
    trampoline
}

fn remove_hook(mut hook: Hook) {

    // memcpy: copying the original bytes over
    hook.p_function_to_hook.copy_from_slice(hook.p_original_bytes, TRAMPOLINE_SIZE);

    unsafe {
        // memset: cleaning up our buffer
        ptr::write_bytes(hook.p_original_bytes, 0, TRAMPOLINE_SIZE);
        // setting the old memory protection back
        VirtualProtect(hook.p_function_to_hook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, Default::default())
            .unwrap_or_else(|e| {
                panic!("[!] Remove Hook: VirtualProtect Failed With Error: {e}");
            });
    }
    hook.p_function_to_hook = Default::default();
    hook.p_function_to_run = Default::default();
    hook.dw_old_protection = Default::default();
}

fn my_message_box_a(hwnd: HWND, lp_text: *const i8, lp_caption: *const i8, u_type: u32) -> i32 {
    // Print original parameters
    println!("[+] Original Parameters:");
    unsafe {
        println!("\t - lpText   : {}", CString::from_raw(lp_text as *mut i8).to_str().unwrap_or("Invalid UTF-8"));
        println!("\t - lpCaption: {}", CString::from_raw(lp_caption as *mut i8).to_str().unwrap_or("Invalid UTF-8"));
    }

    // Call MessageBoxW with modified parameters
    let new_text = "Malware Development Is Cool";
    let new_caption = "Hooked MsgBox";
    let new_text_wide = to_wide(new_text);
    let new_caption_wide = to_wide(new_caption);
    unsafe {
        MessageBoxW(hwnd, new_text_wide.as_ptr(), new_caption_wide.as_ptr(), u_type)
    }
}

fn main() {
    let mut hook = Hook::new(None, None);

    let function_to_hook: *mut c_void = some_function_to_hook as *mut c_void;
    let function_to_run: *mut c_void = some_function_to_run as *mut c_void;

    if initialize_hook_struct(function_to_hook, function_to_run, &mut hook) == TRUE {
        println!("Hook structure initialized successfully.");
    } else {
        println!("Failed to initialize hook structure.");
    }
}
