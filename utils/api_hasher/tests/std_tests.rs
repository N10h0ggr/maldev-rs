#[cfg(test)]
mod tests {
    use api_hasher::resolve_api;

    // -------------------------------------------------------------------------
    // Custom hash provider (only compiled when feature is enabled)
    // -------------------------------------------------------------------------
    #[cfg(feature = "hash-custom")]
    #[no_mangle]
    pub fn custom_hash_provider(data: &[u8]) -> u32 {
        // Simple deterministic hash for test visibility
        data.iter().fold(0u32, |acc, &b| acc ^ b as u32)
    }

    type FnGetTickCount = unsafe extern "system" fn() -> u32;
    type FnGetCurrentProcessId = unsafe extern "system" fn() -> u32;

    // -------------------------------------------------------------------------
    // Full happy-path test (resolve + call)
    // -------------------------------------------------------------------------
    #[test]
    fn resolves_and_calls_get_tick_count() {
        let func: FnGetTickCount =
            resolve_api!("kernel32.dll", "GetTickCount", FnGetTickCount)
                .expect("Failed to resolve GetTickCount from kernel32.dll");

        let ticks = unsafe { func() };

        // GetTickCount is milliseconds since boot; it must be non-zero
        assert!(
            ticks > 0,
            "GetTickCount returned an invalid value: {}",
            ticks
        );
    }

    // -------------------------------------------------------------------------
    // Full happy-path test using the custom hash feature
    // -------------------------------------------------------------------------
    #[test]
    #[cfg(feature = "hash-custom")]
    fn resolves_and_calls_get_current_process_id_with_custom_hash() {
        let func: FnGetCurrentProcessId =
            resolve_api!(
                "kernel32.dll",
                "GetCurrentProcessId",
                FnGetCurrentProcessId
            )
                .expect("Failed to resolve GetCurrentProcessId with custom hash");

        let pid = unsafe { func() };

        // Windows PIDs are always non-zero for a running process
        assert!(
            pid > 0,
            "GetCurrentProcessId returned an invalid PID: {}",
            pid
        );
    }

    // -------------------------------------------------------------------------
    // Negative test: valid DLL, invalid export
    // -------------------------------------------------------------------------
    #[test]
    fn fails_to_resolve_nonexistent_export() {
        type DummyFn = unsafe extern "C" fn();

        let result: Result<DummyFn, _> = resolve_api!(
            "kernel32.dll",
            "DefinitelyNotARealExport_123",
            DummyFn
        );

        assert!(
            result.is_err(),
            "Resolution unexpectedly succeeded for a nonexistent export"
        );
    }
}
