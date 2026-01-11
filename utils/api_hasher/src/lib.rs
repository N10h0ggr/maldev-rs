//! # api_hasher
//!
//! `api_hasher` is a lightweight, `no_std` compatible library designed for
//! dynamic Windows API resolution using compile-time hashing.
//!
//! ## Overview
//!
//! The primary goal of this crate is to eliminate static imports and cleartext
//! string literals (e.g., "NtCreateThreadEx") from the final compiled binary.
//! This is achieved by shifting the hashing logic from runtime to compile-time
//! using Rust's `const fn` capabilities.
//!
//! ## How It Works
//!
//! 1. **Compile-Time Transformation**: The [`resolve_api!`] macro takes string
//!    literals and computes their hashes during compilation. The resulting
//!    `u32` constants are embedded in the binary, while the original strings
//!    are discarded by the linker as dead code.
//! 2. **PEB Traversal**: At runtime, the library accesses the Process Environment
//!    Block (PEB) to locate loaded modules without calling `GetModuleHandle`.
//! 3. **EAT Parsing**: It manually parses the Export Address Table (EAT) of the
//!    target DLL, hashing each exported function name on-the-fly to find a
//!    match against the pre-computed compile-time hash.
//!
//!
//!
//! ## Architecture
//!
//! * **`algorithms`**: Contains `const fn` implementations of hashing algorithms
//!   (DJB2, FNV1a, CRC32).
//! * **`platform`**: Contains architecture-specific logic for PEB traversal
//!   (supporting x86 and x86_64).
//! * **`error`**: Defines [`ResolveError`] for robust failure handling.

#![no_std]

pub mod algorithms;
pub mod error;
pub mod platform;
pub use crate::platform::resolve_symbol;

#[doc(hidden)]
pub mod __private {
    pub use crate::algorithms::const_hash;
    pub use crate::platform::resolve_symbol;
    pub use core::mem::transmute;
}

/// The primary entry point for dynamic API resolution using compile-time hashing.
///
/// This macro computes the hashes for the DLL and function names at compile-time,
/// ensuring that no cleartext strings are stored in the resulting binary.
///
/// # Parameters
/// * `$dll`: A string literal of the target DLL (e.g., "kernel32.dll"). Case-insensitive.
/// * `$func`: A string literal of the function name (e.g., "GetTickCount").
/// * `$type`: The function signature type to cast the resulting pointer to.
///
/// # Returns
/// Returns a `Result<$type, ResolveError>`.
///
/// # Errors
/// This macro can return the following variants of [`crate::error::ResolveError`]:
/// * `ModuleNotFound`: The specified DLL is not currently loaded in the process.
/// * `SymbolNotFound`: The function was not found in the DLL's export table.
///
/// # Safety
/// This macro is `unsafe` because it:
/// 1. Transmutes a raw memory address into a function pointer of type `$type`.
/// 2. Relies on the user providing the correct function signature. Calling the
///    resulting function with an incorrect signature will result in Undefined Behavior.
///
/// # Examples
/// ```rust
/// type GetTickCountFn = unsafe extern "system" fn() -> u32;
///
/// let get_tick_count = unsafe {
///     resolve_api!("kernel32.dll", "GetTickCount", GetTickCountFn)?
/// };
///
/// let uptime = unsafe { get_tick_count() };
/// ```
#[macro_export]
macro_rules! resolve_api {
    ($dll:literal, $func:literal, $type:ty) => {
        unsafe {
            const DLL_HASH: u32 = $crate::__private::const_hash($dll.as_bytes());
            const FUNC_HASH: u32 = $crate::__private::const_hash($func.as_bytes());

            $crate::__private::resolve_symbol(DLL_HASH, FUNC_HASH)
                .map(|ptr| $crate::__private::transmute::<*const (), $type>(ptr))
        }
    };
}