/// Defines a generic hashing state machine.
///
/// Algorithms implement this trait to maintain their internal state
/// while processing byte streams.
pub trait Hasher {
    /// Initialize the hasher with the global (or specific) seed.
    fn new(seed: u32) -> Self;

    /// Update the state with a single byte.
    fn update(&mut self, byte: u8);

    /// Finalize the state and return the resulting 32-bit hash.
    fn finalize(&self) -> u32;
}

/// Defines types that can be normalized and hashed.
///
/// This trait ensures consistency. Whether you pass a Rust `&str`, a C `*const i8`,
/// or a Wide `*const u16`, they are all converted to a **lowercase byte stream**
/// before hashing. This guarantees that `hash("NtDll")` == `hash(L"ntdll.dll")`.
pub trait Hashable {
    /// Calculate hash using the default global seed.
    fn get_hash<H: crate::Hasher>(&self) -> u32;

    /// Calculate hash using a custom seed.
    fn get_hash_with_seed<H: crate::Hasher>(&self, seed: u32) -> u32;
}