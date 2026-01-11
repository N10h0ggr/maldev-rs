use crate::error::ResolveError;

#[cfg(target_os = "windows")]
pub mod windows;

/// Resolves a symbol address using pre-calculated hashes.
///
/// This function is the lower-level implementation used by [`resolve_api!`].
/// It is useful when you want to provide hashes as raw `u32` literals instead
/// of using the macro.
///
/// # Parameters
/// * `dll_hash`: The pre-calculated hash of the DLL name (case-insensitive).
/// * `func_hash`: The pre-calculated hash of the function name.
///
/// # Returns
/// Returns a pointer to the function if found, otherwise a [`ResolveError`].
///
/// # Examples
/// ```rust
/// // Hashes for "kernel32.dll" and "GetTickCount" pre-calculated via DJB2
/// const KERNEL32_HASH: u32 = 0x70b46e14;
/// const GETTICKCOUNT_HASH: u32 = 0x5fb27c52;
///
/// let ptr = resolve_symbol(KERNEL32_HASH, GETTICKCOUNT_HASH)?;
/// let func: GetTickCountFn = unsafe { core::mem::transmute(ptr) };
/// ```
#[inline(always)]
pub fn resolve_symbol(dll_hash: u32, func_hash: u32) -> Result<*const (), ResolveError> {
    #[cfg(target_os = "windows")]
    {
        windows::resolve_symbol(dll_hash, func_hash)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = dll_hash;
        let _ = func_hash;
        Err(ResolveError::PlatformSpecificError(0xDEAD))
    }
}