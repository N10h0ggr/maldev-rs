pub mod crc32;
pub mod djb2;
pub mod fnv1a;

/// Normalizes an ASCII byte to lowercase if it's an uppercase letter.
#[inline(always)]
pub const fn normalize_byte(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

/// The core hashing dispatcher.
/// This handles normalization and selects the algorithm based on features.
#[inline(always)]
pub const fn const_hash(data: &[u8]) -> u32 {
    #[cfg(feature = "hash-djb2")]
    { return djb2::Djb2::hash(data); }

    #[cfg(all(feature = "hash-fnv1a", not(feature = "hash-djb2")))]
    { return fnv1a::Fnv1a::hash(data); }

    #[cfg(all(feature = "hash-crc32", not(feature = "hash-djb2"), not(feature = "hash-fnv1a")))]
    { return crc32::Crc32::hash(data); }

    #[cfg(all(feature = "hash-custom", not(feature = "hash-djb2"), not(feature = "hash-fnv1a"), not(feature = "hash-crc32")))]
    { return crate::custom_hash(data); }

    #[cfg(not(any(feature = "hash-djb2", feature = "hash-fnv1a", feature = "hash-crc32", feature = "hash-custom")))]
    { 0 }
}

/// Runtime wrapper for const_hash.
#[inline(always)]
pub fn get_default_hash(data: &[u8]) -> u32 {
    const_hash(data)
}

/// Hashing for UTF-16 (used for PEB DLL name matching).
/// This ensures that the same algorithm selected for the macro is used
/// for the PEB walk, maintaining consistency.
#[inline(always)]
pub fn hash_utf16(data: *const u16, len: usize) -> u32 {
    // We convert the UTF-16 (ignoring high bytes as standard for Windows DLL names)
    // into a temporary normalized ASCII buffer to pass to our const_hash.
    let mut buffer = [0u8; 256];
    let mut i = 0;
    while i < len && i < 256 {
        unsafe {
            let c = *data.add(i);
            // Convert to lowercase ASCII
            buffer[i] = normalize_byte((c & 0xff) as u8);
        }
        i += 1;
    }
    const_hash(&buffer[..i])
}