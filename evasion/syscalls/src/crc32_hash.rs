/// Standard CRC32 polynomial (reversed)
const CRC32_POLY: u32 = 0xEDB88320;

/// Compile-time CRC32 hashing (case-insensitive).
///
/// This function is intended to be used through the `crc32!` macro.
pub const fn crc32_const(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut crc = 0xFFFF_FFFF;
    let mut i = 0;

    while i < bytes.len() {
        let mut byte = bytes[i];
        // Convert to lowercase manually for const context
        if byte >= b'A' && byte <= b'Z' {
            byte += 32;
        }

        crc ^= byte as u32;
        let mut j = 0;
        while j < 8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ CRC32_POLY
            } else {
                crc >> 1
            };
            j += 1;
        }

        i += 1;
    }

    !crc
}

/// Runtime CRC32 hashing (case-insensitive).
///
/// # Arguments
/// * `s` - ASCII string to hash
///
/// # Returns
/// CRC32 hash of the string
pub fn crc32_runtime(s: &str) -> u32 {
    crc32_const(s)
}
