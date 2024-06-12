#![feature(asm)]
#![feature(global_asm)]

use std::arch::global_asm;
global_asm!(
    ".intel_syntax noprefix",
    ".data",
    "wSystemCall: .long 0x0000",

    ".text",
    ".global set_ssn",
    "set_ssn:",
    "    xor eax, eax",
    "    mov DWORD PTR wSystemCall[rip], eax",
    "    mov eax, ecx",
    "    mov r8d, eax",
    "    mov DWORD PTR wSystemCall[rip], r8d",
    "    ret",

    ".global prepare_shellcode",
    "prepare_shellcode:",
    "    xor eax, eax",                        // Clear RAX (set it to 0)
    "    mov al, dil",                         // Move the 8-bit value from DIL to AL (zero-extend to 64-bit)
    "    mov DWORD PTR wSystemCall[rip], eax", // Store the 32-bit value in EAX into wSystemCall using RIP-relative addressing
    "    ret",

    ".global run_syscall",
    "run_syscall:",
    "    xor r10, r10",                 // r10 = 0
    "    mov rax, rcx",                 // rax = rcx
    "    mov r10, rax",                 // r10 = rax = rcx
    "    mov eax, DWORD PTR wSystemCall[rip]",  // eax = ssn
    "    jmp Run",                      // execute 'Run'
    "    xor eax, eax",                 // won't run
    "    xor rcx, rcx",                 // won't run
    "    shl r10, 2",                   // won't run
    "Run:",
    "    syscall",                      // syscall
    "    ret"

);

extern "C" {
    pub fn set_ssn(ssn: u8);
    pub fn run_syscall(...);
}

#[cfg(test)]
mod private_tests {
    use std::ffi::c_void;
    use std::ptr::null;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use super::*;

    #[test]
    fn test_set_ssn() {
        unsafe { set_ssn(0x0001u8); }
    }

/*    #[test]
    fn test_run_syscall() {
        unsafe {
            run_syscall(HANDLE(-1), null() as *mut *mut c_void, 0, 32 as *mut usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
    }*/
}