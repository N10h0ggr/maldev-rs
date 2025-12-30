#![no_std]

use api_hasher::resolve_api;

#[test]
fn resolve_api_macro_is_no_std_compatible() {
    // This test ensures that the resolve_api! macro:
    // - expands correctly
    // - does not require std
    // - produces a well-typed Result

    type FnBeep = unsafe extern "system" fn(u32, u32) -> i32;

    let result: Result<FnBeep, _> =
        resolve_api!("kernel32.dll", "Beep", FnBeep);

    let _ = result;
}
