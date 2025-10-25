use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

/// Converts a UTF-8 Rust string (`&str`) into a null-terminated wide string (`Vec<u16>`).
///
/// This is commonly used when interacting with Windows APIs that expect
/// UTF-16 encoded strings with a trailing null character.
///
/// # Example
/// ```ignore
/// let wide = to_wide_null("C:\\\\Temp");
/// assert_eq!(*wide.last().unwrap(), 0);
/// ```
///
/// # Returns
/// A vector of 16-bit values (`Vec<u16>`) representing the UTF-16 encoding of the input string,
/// including a terminating null character.
pub fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(once(0))
        .collect()
}

/// Compares a raw wide string pointer (`*const u16`) with a Rust UTF-8 string (`&str`).
///
/// This function safely compares the contents of a null-terminated wide string located
/// at `ptr` with the UTF-16 representation of the given Rust string.
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer. The caller must ensure:
/// - `ptr` is valid and points to a properly null-terminated UTF-16 string.
/// - The memory region is accessible for reading until the null terminator.
///
/// # Arguments
/// * `ptr` - Pointer to a null-terminated UTF-16 string.
/// * `s` - Rust string slice to compare against.
///
/// # Returns
/// * `true` if both strings are equal, `false` otherwise.
///
/// # Example
/// ```ignore
/// use std::ffi::OsStr;
/// use std::os::windows::ffi::OsStrExt;
/// use std::iter::once;
///
/// let rust_str = "Test";
/// let wide: Vec<u16> = OsStr::new(rust_str).encode_wide().chain(once(0)).collect();
///
/// unsafe {
///     assert!(wide_ptr_eq(wide.as_ptr(), rust_str));
/// }
/// ```
pub unsafe fn wide_ptr_eq(ptr: *const u16, s: &str) -> bool {
    if ptr.is_null() {
        return false;
    }

    // Determine the length of the null-terminated UTF-16 string.
    let mut len = 0usize;
    loop {
        let v = unsafe { *ptr.add(len) };
        if v == 0 {
            break;
        }
        len += 1;
    }

    // Create a slice view of the wide string in memory.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

    // Encode the Rust string to UTF-16 for comparison.
    let target: Vec<u16> = OsStr::new(s).encode_wide().collect();

    slice == target.as_slice()
}
