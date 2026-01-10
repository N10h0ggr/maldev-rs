#![no_std]
#![allow(non_snake_case)]

// Link to std only during testing to allow CString/Vec usage in unit tests.
#[cfg(test)]
extern crate std;

pub mod traits;
pub mod algorithms;

// Re-export common types for ease of use
pub use traits::{Hasher, Hashable};
pub use algorithms::crc32::{Crc32, get_crc32_const};
pub use algorithms::djb2::{Djb2, get_djb2_const};
pub use algorithms::fnv1a::{Fnv1a, get_fnv1a_const};
pub use algorithms::sdbm::{Sdbm, get_sdbm_const};
pub use algorithms::jenkins::{Jenkins, get_jenkins_const};


/// The global seed used for all hashing algorithms.
///
/// # OPsec Note
/// Change this value before every campaign. Changing this single constant
/// alters the signature of every API call resolution in your payload,
/// breaking static analysis tools looking for standard CRC32/DJB2 constants.
///
/// To make this dynamic per-build, consider using `option_env!` or a build script.
pub const HASH_SEED: u32 = 0x5EED_0001; // Change me!


/// The primary interface for hashing. It automatically selects Compile-Time or Runtime execution.
///
/// # Modes
/// 1. **Compile-Time (String Hiding):** If you pass a string literal (e.g., `"NtOpen"`),
///    the macro calculates the hash during compilation. The string will **NOT** appear in the binary.
/// 2. **Runtime:** If you pass a variable (e.g., a pointer `ptr`), it calculates the hash at runtime.
///
/// # Examples
/// ```ignore
/// // Compile-time (Target)
/// const HASH: u32 = calc_hash!("NtAllocateVirtualMemory");
///
/// // Runtime (Candidate from memory)
/// if calc_hash!(function_ptr) == HASH { ... }
///
/// // Select Algorithm
/// const HASH_DJB: u32 = calc_hash!("NtAllocateVirtualMemory", Djb2);
/// ```
#[macro_export]
macro_rules! calc_hash {
    // Case 1: Literal String + Default Algo (CRC32) -> Compile Time
    ($s:literal) => {{
        // Crucial: Pass HASH_SEED to match runtime logic
        const H: u32 = $crate::get_crc32_const($s, $crate::HASH_SEED);
        H
    }};

    // Case 2: Literal String + Explicit Algo -> Compile Time
    ($s:literal, Crc32) => {{
        const H: u32 = $crate::get_crc32_const($s, $crate::HASH_SEED);
        H
    }};
    ($s:literal, Djb2) => {{
        const H: u32 = $crate::get_djb2_const($s, $crate::HASH_SEED);
        H
    }};
    ($s:literal, Fnv1a) => {{
        const H: u32 = $crate::get_fnv1a_const($s, $crate::HASH_SEED);
        H
    }};
    ($s:literal, Sdbm) => {{
        const H: u32 = $crate::get_sdbm_const($s, $crate::HASH_SEED);
        H
    }};
    ($s:literal, Jenkins) => {{
        const H: u32 = $crate::get_jenkins_const($s, $crate::HASH_SEED);
        H
    }};

    // Case 3: Expression (Variable/Pointer) + Default Algo -> Runtime
    ($item:expr) => {{
        use $crate::{Hashable, Crc32};
        $item.get_hash::<Crc32>()
    }};

    // Case 4: Expression (Variable/Pointer) + Explicit Algo -> Runtime
    ($item:expr, $algo:ident) => {{
        use $crate::{Hashable, $algo};
        $item.get_hash::<$algo>()
    }};
}


/// Normalizes a byte to lowercase (ASCII).
///
/// This is `const` to support both runtime and compile-time hashing.
#[inline(always)]
pub(crate) const fn to_lowercase(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' {
        c + 32
    } else {
        c
    }
}

// ============================================================================
//   Implementations
// ============================================================================

// Macro to implement Hashable for different types cleanly
macro_rules! impl_hashable {
    ($type:ty, $iterator:expr) => {
        impl Hashable for $type {
            fn get_hash<H: Hasher>(&self) -> u32 {
                self.get_hash_with_seed::<H>(HASH_SEED)
            }

            fn get_hash_with_seed<H: Hasher>(&self, seed: u32) -> u32 {
                let mut hasher = H::new(seed);
                $iterator(self, &mut hasher);
                hasher.finalize()
            }
        }
    };
}

// Implementation for &str (Safe)
impl_hashable!(&str, |s: &&str, h: &mut H| {
    for b in s.bytes() {
        h.update(to_lowercase(b));
    }
});

// Implementation for C-Strings (*const i8) (Unsafe dereference)
impl_hashable!(*const i8, |s: &*const i8, h: &mut H| {
    let mut ptr = *s;
    if !ptr.is_null() {
        unsafe {
            while *ptr != 0 {
                h.update(to_lowercase(*ptr as u8));
                ptr = ptr.add(1);
            }
        }
    }
});

// Implementation for Wide Strings (*const u16) (Unsafe dereference)
// Casts u16 to u8 (safe for ASCII function names in Windows)
impl_hashable!(*const u16, |s: &*const u16, h: &mut H| {
    let mut ptr = *s;
    if !ptr.is_null() {
        unsafe {
            while *ptr != 0 {
                h.update(to_lowercase(*ptr as u8));
                ptr = ptr.add(1);
            }
        }
    }
});

// Implementation for PCSTR (*const u8)
// Windows defines PCSTR as *const u8, while CString is *const i8. We need both.
impl_hashable!(*const u8, |s: &*const u8, h: &mut H| {
    let mut ptr = *s;
    if !ptr.is_null() {
        unsafe {
            while *ptr != 0 {
                h.update(to_lowercase(*ptr));
                ptr = ptr.add(1);
            }
        }
    }
});

// Implementation for PWSTR (*mut u16)
// UNICODE_STRING.Buffer is often *mut u16.
impl_hashable!(*mut u16, |s: &*mut u16, h: &mut H| {
    let mut ptr = *s;
    if !ptr.is_null() {
        unsafe {
            while *ptr != 0 {
                // Cast u16 to u8 for normalization
                h.update(to_lowercase(*ptr as u8));
                ptr = ptr.add(1);
            }
        }
    }
});