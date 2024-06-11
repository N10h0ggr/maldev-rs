mod asm;

use windows;
use std::collections::HashMap;
use utils::get_dll_exported_functions_by_hash;
use utils::hash::{FastCrc32};
use crate::asm::set_ssn;

const NT_DLL_CRC32: u32 = 0x6030EF91u32;

struct Syscall {
    pub ssn: u8, // The syscall number
    pub p_syscall_address: u8, // The address of the syscall
}

impl Syscall {
    pub fn default() -> Self {
        Syscall { ssn: 0, p_syscall_address: 0 }
    }
}

pub struct NtApiFunc {
    syscalls: HashMap<u32, Syscall>, // crc32 hash, NtSyscall
}

impl NtApiFunc {

    pub unsafe fn new() -> Self {
        let mut syscalls = HashMap::new();
        let crc32 = FastCrc32::new();

        // This is a placeholder for the actual enumeration and hashing logic
        // Fill syscalls with NtSyscall structs
        // 1. fetches all the exported functions from ntdll.dll
        let exported_function = get_dll_exported_functions_by_hash(NT_DLL_CRC32);
        // 2. computes the hashes for the name functions
        // 3. creates an entry for the NtApiFunc
        for function in exported_function {
            let hash = crc32.compute_hash(function.to_uppercase().as_bytes());
            syscalls.insert(hash, Syscall::default());
        }

        NtApiFunc { syscalls }
    }

    pub unsafe fn call(&self, function_hash: u32) {
        let ssn = self.syscalls.get(&function_hash).map(|syscall| syscall.ssn).unwrap();
        // crafts the asm shellcode with the function values
        set_ssn(ssn);
        // runs the shellcode
    }

    pub fn get_function_ssn(&self, function_hash: u32) -> Option<u8>
    {
        self.syscalls.get(&function_hash).map(|syscall| syscall.ssn)
    }

    pub fn get_function_syscall_address(&self, function_hash: u32) -> Option<u8>
    {
        self.syscalls.get(&function_hash).map(|syscall| syscall.p_syscall_address)
    }
}

unsafe fn prepare_shellcode(function: Syscall){
    // Prepares the shellcode for the call
    set_ssn(function.ssn);
}