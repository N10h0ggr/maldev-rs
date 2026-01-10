#[cfg(test)]
mod integration_tests {
    use string_hasher::{calc_hash, Crc32, Djb2, Fnv1a, Sdbm, Jenkins, get_crc32_const};
    use std::ffi::CString;

    // Import Windows types to simulate real OS structures
    use windows_sys::core::{PCSTR, PCWSTR, PWSTR};
    use windows_sys::Win32::Foundation::UNICODE_STRING;

    // ========================================================================
    //   1. Core Logic & Consistency Tests
    // ========================================================================

    /// **CRITICAL TEST**: Verifies that the Compile-Time logic matches the Runtime logic.
    ///
    /// In malware development, you hardcode the Compile-Time hash (e.g., `0xE0762FEB`)
    /// to hide the string "NtAllocateVirtualMemory". At runtime, you hash the
    /// string found in `ntdll.dll`'s export table. If these two calculation methods
    /// drift (due to seed mismatch or logic error), your implant will fail blindly.
    #[test]
    fn test_compile_vs_runtime_consistency() {
        let func_name = "NtAllocateVirtualMemory";

        // 1. Compile Time (String Stripping Mode)
        // This is calculated by rustc. The string does NOT exist in the binary.
        const HASH_CONST: u32 = calc_hash!("NtAllocateVirtualMemory");

        // 2. Runtime (Candidate Mode)
        // This is calculated by the CPU. The string exists in memory (from std variable).
        let hash_runtime = calc_hash!(func_name);

        assert_eq!(HASH_CONST, hash_runtime, "FATAL: Compile-time and Runtime hashes do not match!");
    }

    /// Verifies that normalization (lowercase) works for both modes.
    /// Windows is case-insensitive, so "NtAllocateVirtualMemory" must match "ntallocatevirtualmemory".
    #[test]
    fn test_normalization() {
        const HASH_UPPER: u32 = calc_hash!("NtAllocateVirtualMemory");
        const HASH_LOWER: u32 = calc_hash!("ntallocatevirtualmemory");

        // Mixed case test
        const HASH_MIXED: u32 = calc_hash!("NtAlLoCaTeViRtUaLmEmOrY");

        assert_eq!(HASH_UPPER, HASH_LOWER, "Hashing failed case-insensitivity check");
        assert_eq!(HASH_UPPER, HASH_MIXED, "Hashing failed mixed-case check");
    }

    // ========================================================================
    //   2. Algorithm Agility Tests
    // ========================================================================

    /// Demonstrates how to switch hashing algorithms.
    /// You might change algorithms to evade signatures that look for specific CRC32 constants.
    #[test]
    fn test_algorithm_switching() {
        let func = "NtCreateThreadEx";

        // Calculate using different strategies
        let h_crc = calc_hash!(func, Crc32);
        let h_djb = calc_hash!(func, Djb2);
        let h_fnv = calc_hash!(func, Fnv1a);
        let h_sdb = calc_hash!(func, Sdbm);
        let h_jen = calc_hash!(func, Jenkins);

        // Ensure they are actually different
        assert_ne!(h_crc, h_djb);
        assert_ne!(h_crc, h_fnv);

        // Verify Compile-Time support for specific algos
        const H_DJB_CONST: u32 = calc_hash!("NtCreateThreadEx", Djb2);
        assert_eq!(h_djb, H_DJB_CONST, "DJB2 Compile vs Runtime mismatch");

        const H_FNV_CONST: u32 = calc_hash!("NtCreateThreadEx", Fnv1a);
        assert_eq!(h_fnv, H_FNV_CONST, "FNV1a Compile vs Runtime mismatch");
    }

    // ========================================================================
    //   3. Windows Interop Tests (The "Malware Guide" Section)
    // ========================================================================

    /// **Scenario**: Retrieving a function address using `GetProcAddress` or manual parsing.
    /// Input: Standard C-String (`char*` / `PCSTR`).
    #[test]
    fn test_pcstr_hashing() {
        let func_name = "NtClose";

        // Simulate getting a pointer from a C API
        let c_string = CString::new(func_name).unwrap();
        // PCSTR is *const u8 in windows-sys
        let pcstr: PCSTR = c_string.as_ptr() as *const u8;

        // Usage: Pass the raw pointer directly to the macro
        let hash = calc_hash!(pcstr);

        assert_eq!(hash, calc_hash!("NtClose"), "PCSTR (char*) hash mismatch");
    }

    /// **Scenario**: Parsing PE resources or File Paths.
    /// Input: Wide String (`wchar_t*` / `PCWSTR`).
    #[test]
    fn test_pcwstr_hashing() {
        let func_name = "NtCreateThreadEx";

        // Simulate a Wide String in memory (UTF-16 + Null Terminator)
        let mut wide_chars: Vec<u16> = func_name.encode_utf16().collect();
        wide_chars.push(0);

        // PCWSTR is *const u16
        let pcwstr: PCWSTR = wide_chars.as_ptr();

        // Usage: Pass the wide pointer directly
        let hash = calc_hash!(pcwstr);

        assert_eq!(hash, calc_hash!("NtCreateThreadEx"), "PCWSTR (wchar_t*) hash mismatch");
    }

    /// **Scenario**: Walking the PEB (Process Environment Block) to find DLLs.
    /// Input: `UNICODE_STRING` structure.
    #[test]
    fn test_unicode_string_hashing() {
        let dll_name = "ntdll.dll";

        // 1. Mock the memory layout of a DLL name in the PEB
        let mut wide_chars: Vec<u16> = dll_name.encode_utf16().collect();
        wide_chars.push(0); // Ldr entries are null-terminated in memory

        // 2. Mock the UNICODE_STRING struct found in LDR_DATA_TABLE_ENTRY
        let mut unicode_str = UNICODE_STRING {
            Length: (dll_name.len() * 2) as u16,
            MaximumLength: (wide_chars.len() * 2) as u16,
            Buffer: wide_chars.as_mut_ptr(), // *mut u16 (PWSTR)
        };

        // 3. USAGE: Hash the .Buffer field directly
        // The library automatically handles *mut u16 -> casts to u8 -> normalizes -> hashes
        let hash = calc_hash!(unicode_str.Buffer);

        // 4. Verification
        // Matches the standard string hash?
        assert_eq!(hash, calc_hash!("ntdll.dll"), "UNICODE_STRING Buffer hash mismatch");

        // Matches the target hash we would use in our evasion code?
        // (Note the mixed case in the target to ensure normalization works)
        const TARGET_DLL_HASH: u32 = calc_hash!("NtDll.Dll");
        assert_eq!(hash, TARGET_DLL_HASH, "PEB Walk simulation failed: Case mismatch");
    }

    // ========================================================================
    //   4. Edge Cases
    // ========================================================================

    #[test]
    fn test_empty_string() {
        // Should not panic
        let empty_hash = calc_hash!("");
        // Runtime
        let empty_runtime = calc_hash!(CString::new("").unwrap().as_ptr());

        assert_eq!(empty_hash, empty_runtime, "Empty string consistency check");
    }
}