pub mod djb2;
pub mod fnv1a;
mod crc32;

/// The core trait that all hashing algorithms must implement.
pub trait HashAlg {
    /// Returns the hash of the given byte slice.
    fn hash(data: &[u8]) -> u32;
}

/// Dispatcher function used by the macro.
/// It selects the algorithm based on the enabled cargo features.
#[inline(always)]
pub fn get_default_hash(data: &[u8]) -> u32 {
    #[cfg(feature = "hash-djb2")]
    { return djb2::Djb2::hash(data); }

    #[cfg(all(feature = "hash-fnv1a", not(feature = "hash-djb2")))]
    { return fnv1a::Fnv1a::hash(data); }

    #[cfg(all(feature = "hash-crc32", not(feature = "hash-djb2"), not(feature = "hash-fnv1a")))]
    { return crc32::Crc32::hash(data); }

    #[cfg(all(feature = "hash-custom", not(feature = "hash-djb2"), not(feature = "hash-fnv1a")))]
    {
        // This expects a function defined elsewhere with this exact signature
        extern "Rust" {
            fn custom_hash_provider(data: &[u8]) -> u32;
        }
        unsafe { custom_hash_provider(data) }
    }

    #[cfg(not(any(feature = "hash-djb2", feature = "hash-fnv1a", feature = "hash-custom")))]
    {
        // Fallback or compile error if no algorithm is selected
        compile_error!("You must select at least one hashing algorithm feature.");
    }
}