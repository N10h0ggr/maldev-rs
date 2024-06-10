mod asm;

use windows;
use std::collections::HashMap;
use utils::hash::Crc32;

#[derive(Debug)]
pub struct NtApiFunc {
    syscalls: HashMap<u32, NtSyscall>, // crc32 hash, NtSyscall
}

#[derive(Debug)]
struct NtSyscall {
    pub ssn: u8, // The syscall number
    pub p_syscall_address: *const u8, // The address of the syscall
}

impl NtApiFunc {

    pub fn new() -> Self {
        let mut syscalls = HashMap::new();

        // This is a placeholder for the actual enumeration and hashing logic
        // Fill syscalls with NtSyscall structs
        // 1. fetches all the exported functions from ntdll.dll
        // 2. computes the hashes for the name functions
        // 3. creates an entry for the NtApiFunc.syscalls where <hash, NtSyscall::Default()>

        NtApiFunc { syscalls }
    }

    pub fn call(function_hash: u32) {
        // crafts the asm shellcode with the function values
        // runs the shellcode
    }

    pub fn get_function_ssn(function_hash: u32) //-> *const u8
    {
        // Seek in self.syscalls
    }

    pub fn get_function_pointer(function_hash: u32) //-> *const u8
    {
        // Seek in self.syscalls
    }
}

fn fetch_nt_functions(){
    // Use syswhisper2 or equivalent to enumerate functions
    // Fill syscalls with NtSyscall structs
}

fn compute_str_hash(crc32: &Crc32, s_function: &str) -> u32 {
    crc32.compute_hash(s_function.as_ref())
}

fn prepare_shellcode(function: NtSyscall){
    // Prepares the shellcode for the call
}

#[cfg(test)]
mod private_tests {
    use super::*;

    fn hash_test() {
        let crc32 = Crc32::new();
        assert_eq!(compute_str_hash(&crc32, "NtAllocateVirtualMemory"), 0xE0762FEB);
        assert_eq!(compute_str_hash(&crc32,"NtProtectVirtualMemory"), 0x5C2D1A97);
        assert_eq!(compute_str_hash(&crc32,"NtCreateThreadEx"), 0x2073465A);
        assert_eq!(compute_str_hash(&crc32,"NtWaitForSingleObject"), 0xDD554681);
    }
}