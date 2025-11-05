#![feature(global_asm)]

use std::arch::global_asm;

#[cfg(target_arch = "x86_64")]
global_asm!(
    // DATA
    ".data",
    "wSystemCall:            .long 0x0000",
    "qSyscallInsAddress:     .quad 0x0000000000000000",
    // TEXT - Direct Syscall implementation
    ".text",
    ".global set_ssn_direct",
    "set_ssn_direct:",
    "    xor eax, eax",
    "    mov DWORD PTR [rip + wSystemCall], eax",
    "    mov eax, ecx",
    "    mov r8d, eax",
    "    mov DWORD PTR [rip + wSystemCall], r8d",
    "    ret",
    ".global run_direct_syscall",
    "run_direct_syscall:",
    "    xor r10, r10",                           // r10 = 0
    "    mov rax, rcx",                           // rax = rcx
    "    mov r10, rax",                           // r10 = rax = rcx
    "    mov eax, DWORD PTR [rip + wSystemCall]", // eax = ssn
    "    jmp run",                                // jump to inline 'run'
    "    xor eax, eax",                           // (won't run)
    "    xor rcx, rcx",                           // (won't run)
    "    shl r10, 2",                             // (won't run)
    "run:",
    "    syscall",
    "    ret",
    // TEXT - Inirect Syscall implementation
    ".global set_ssn_indirect",
    "set_ssn_indirect:",
    "    xor eax, eax",                                  // eax = 0
    "    mov DWORD PTR [rip + wSystemCall], eax",        // reset wSystemCall
    "    mov QWORD PTR [rip + qSyscallInsAddress], rax", // reset qSyscallInsAddress (rax = 0)
    "    mov eax, ecx",                                  // eax = ssn
    "    mov DWORD PTR [rip + wSystemCall], eax",        // store ssn
    "    mov r8, rdx", // r8 = address of syscall instruction (passed in rdx)
    "    mov QWORD PTR [rip + qSyscallInsAddress], r8", // store syscall instruction address
    "    ret",
    ".global run_indirect_syscall",
    "run_indirect_syscall:",
    "    xor r10, r10",                           // r10 = 0
    "    mov rax, rcx",                           // rax = rcx
    "    mov r10, rax",                           // r10 = rax = rcx
    "    mov eax, DWORD PTR [rip + wSystemCall]", // eax = ssn
    "    jmp run_indirect",                       // execute run_indirect
    "    xor eax, eax",                           // (won't run)
    "    xor rcx, rcx",                           // (won't run)
    "    shl r10, 2",                             // (won't run)
    "run_indirect:",
    "    jmp QWORD PTR [rip + qSyscallInsAddress]", // jump to stored 'syscall' instruction
    "    xor r10, r10",                             // clear (won't run if jumped)
    "    mov QWORD PTR [rip + qSyscallInsAddress], r10", // clear qSyscallInsAddress
    "    ret"
);

extern "C" {
    // original direct syscall functions
    pub fn set_ssn_direct(ssn: usize);
    pub fn run_direct_syscall(...) -> usize;

    // new indirect syscall versions
    pub fn set_ssn_indirect(ssn: usize, syscall_inst_addr: usize);
    pub fn run_indirect_syscall(...) -> usize;
}

#[cfg(test)]
mod private_tests {
    use super::*;

    #[test]
    fn test_set_ssn() {
        unsafe {
            set_ssn_direct(0x18);
        }
    }

    #[test]
    fn test_set_ssn_indirect() {
        unsafe {
            let fake_syscall_addr = 0x7FF700000000usize;
            set_ssn_indirect(0x33, fake_syscall_addr);
        }
    }
}
