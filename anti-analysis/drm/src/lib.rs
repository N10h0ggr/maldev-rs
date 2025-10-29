mod drm;
mod errors;
mod fingerprint;
mod image_pe;

use errors::DrmError;

/// Entry point for DRM validation and first-run initialization.
///
/// Behavior:
/// - If the embedded machine ID equals the built-in default, the function
///   patches the on-disk image with the current machine fingerprint and returns `Ok(true)`.
/// - If the binary was already patched, it verifies that the current machine fingerprint
///   matches the embedded one and returns:
///     - `Ok(true)` on match
///     - `Ok(false)` on mismatch
/// - Returns `Err(_)` on internal failures (I/O, parsing, environment).
pub fn drm_check() -> Result<bool, DrmError> {
    drm::drm_check()
}
