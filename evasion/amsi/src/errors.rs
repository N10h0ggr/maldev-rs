use thiserror::Error;

/// Errors produced when attempting to locate AMSI symbols and install the HWBP detour.
#[derive(Debug, Error)]
pub enum AmsiError {
    /// `GetModuleHandleA` failed. Contains the raw Win32 `GetLastError()` code.
    #[error("GetModuleHandleA failed: Win32 error {0}")]
    GetModuleHandleFailed(u32),

    /// `GetProcAddress` failed. Contains the raw Win32 `GetLastError()` code.
    #[error("GetProcAddress failed: Win32 error {0}")]
    GetProcAddressFailed(u32),

    /// Hardware breakpoint installation failed. We capture a textual representation
    /// of the underlying error returned by the `hwbp` crate.
    #[error("install_hwbp failed: {0}")]
    InstallHwBpFailed(String),
}
