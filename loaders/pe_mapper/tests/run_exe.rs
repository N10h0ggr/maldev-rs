//! Integration test for executing a test PE image.

use std::path::PathBuf;

use pe_mapper::run;

/// Returns the path to the test executable matching the host architecture.
///
/// Layout:
/// - payload/x64/mimikatz.exe   (64-bit)
/// - payload/Win32/mimikatz.exe (32-bit)
fn test_exe_path() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let arch_dir = if cfg!(target_pointer_width = "64") {
        "payload\\x64"
    } else {
        "payload\\Win32"
    };

    root.join(arch_dir).join("mimikatz.exe")
}

#[test]
#[cfg(windows)]
fn run_test_executable_commandline() {
    let exe = test_exe_path();

    assert!(exe.exists(), "test executable not found at {:?}", exe);

    // These should be executed by mimikatz in "commandline" mode.
    let args = vec!["coffee".to_string(), "exit".to_string()];

    let result = run(&exe, args);

    assert!(result.is_ok(), "execution failed: {result:?}");
}
