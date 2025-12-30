/// Case-insensitive comparison between an ASCII slice and a UTF-16 buffer.
/// Used for comparing Rust-macro strings with Windows PEB strings.
#[inline(always)]
pub fn compare_ascii_utf16_ci(ascii: &[u8], utf16: *const u16, utf16_len: usize) -> bool {
    if utf16.is_null() {
        return false;
    }

    // Trim trailing NULs from ASCII (your macro used to include one)
    let mut a_len = ascii.len();
    while a_len > 0 && ascii[a_len - 1] == 0 {
        a_len -= 1;
    }

    if a_len != utf16_len {
        return false;
    }

    for i in 0..a_len {
        let a = ascii[i];
        let w = unsafe { *utf16.add(i) };

        // Only handle ASCII DLL names (kernel32.dll etc.)
        if w > 0x7F {
            return false;
        }

        let wl = (w as u8).to_ascii_lowercase();
        let al = a.to_ascii_lowercase();

        if al != wl {
            return false;
        }
    }

    true
}
