use crate::error::ResolveError;

#[cfg(target_os = "windows")]
pub mod windows;

/// Resolves a symbol by searching the specified module for a matching name hash.
#[inline(always)]
pub fn resolve_symbol(dll_name: &[u8], func_hash: u32) -> Result<*const (), ResolveError> {
    #[cfg(target_os = "windows")]
    {
        windows::find_symbol(dll_name, func_hash)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Placeholder for Linux/MacOS implementations
        Err(ResolveError::PlatformSpecificError(0xDEAD))
    }
}