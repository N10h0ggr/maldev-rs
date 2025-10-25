# Trampoline Hooking

This crate implements a simple inline trampoline-style hook for Windows targets. It overwrites a function prologue with a small jump that redirects execution to a user-supplied detour and restores the original bytes when the hook is removed.

The implementation focuses on clarity and a minimal API: create a Hook, install it, and remove it. It keeps the unsafe, platform-specific parts isolated so the high-level usage is straightforward.

## How the technique works

Trampoline or inline hooking generally follows three steps:

1. Save the original prologue bytes of the target function.
2. Overwrite the prologue with a jump (or small trampoline) that transfers execution to your detour.
3. When you remove the hook, restore the original prologue bytes.

This crate uses those steps. On x64 the replacement prologue is a small sequence that moves the detour pointer into a register and jumps to it. On x86 the replacement is a mov-to-eax followed by jmp eax. The crate stores the original bytes in the Hook struct so they can be copied back when the hook is removed. Memory protections are changed with VirtualProtect when writing to code pages.

## Library layout

High-level mapping between code and purpose

* `Hook` struct: Holds `p_function_to_hook`, `p_function_to_run`, the saved original bytes vector, and the saved protection value. Create a Hook via `Hook::new(...)`.
* `prepare_x64_trampoline`, `prepare_x32_trampoline`: Build the exact byte sequence that will be copied over the function prologue to redirect execution to the detour.
* `install_hook`: Copies the trampoline bytes into the target function prologue (after changing page protection).
* `remove_hook`: Restores the original bytes and resets the original page protection.
* `tests` example: The crate includes a test that demonstrates hooking MessageBoxA and replacing its behavior with a custom function.

## Example usage

Minimal pattern used in the crate

```rust
use std::ffi::c_void;
use trampoline::{Hook, install_hook, remove_hook};

// obtain pointers to the function to hook and to your detour
let function_to_hook = MessageBoxA::<HWND, PCSTR, PCSTR> as *const u8;
let function_to_run = my_message_box_a as *const u8;

// create the Hook structure (unsafe because it stores raw pointers)
let hook = unsafe { Hook::new(function_to_hook, function_to_run) }
    .expect("failed to prepare hook");

// install the hook (this overwrites the target prologue)
install_hook(&hook);

// when done, remove the hook (restores original bytes)
remove_hook(hook);
```

Example detour (signature must match the original)

```rust
use windows::core::PCSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MESSAGEBOX_STYLE, MESSAGEBOX_RESULT};

pub fn my_message_box_a(hwnd: HWND, p_text: PCSTR, p_caption: PCSTR, u_type: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    // inspect incoming args if desired
    // provide alternate behavior or call a different API
    let new_text = w!("Hooked text");
    let new_caption = w!("Hooked caption");
    unsafe { MessageBoxW(hwnd, new_text, new_caption, u_type) }
}
```

### How to call the original function from the detour

This crate does not build a "callable original" trampoline for you. Two common approaches to call the original are:
1. **Build a custom trampoline yourself**: allocate executable memory, copy the saved original prologue bytes into it, then append a relative jump back to the original function at address (target + TRAMPOLINE_SIZE). Call that allocated trampoline from your detour to execute the original function body.
2. **Temporarily remove the hook, call the original, then re-install the hook**. This approach is simpler but can race with other threads and requires careful synchronization.

## References

* [Microsoft Learn: VirtualProtect function](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) – Official documentation for changing memory protection on code pages.
* [Microsoft Learn: Writing a Windows x64 JUMP Instruction](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170) – Describes x64 calling conventions and relevant instruction encoding considerations when building trampolines.
* [Geoff Chappell – Windows Function Hooking](https://www.geoffchappell.com/studies/windows/km/hook.htm) – A detailed breakdown of inline hook mechanisms and their limitations.
* [CodeProject – “API Hooking Revealed” by Sergey Podobry](https://www.codeproject.com/Articles/2082/API-Hooking-Revealed) – Practical explanation of inline and trampoline hooking with examples.
* [Maddie Stone – Inline Hooking Overview (Project Zero)](https://googleprojectzero.blogspot.com/2018/11/inlining-hooking-on-windows.html) – Modern Windows analysis of inline/trampoline hooks and how they behave under mitigations like CFG.
* [pinvoke.dev – VirtualProtect](https://www.pinvoke.dev/dlls/kernel32/virtualprotect?utm_source=chatgpt.com) – C# signature reference for the same API used for memory protection changes.

