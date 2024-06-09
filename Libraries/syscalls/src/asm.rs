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
    pub fn set_ssn(ssn: u32);
    pub fn run_syscall();
}
