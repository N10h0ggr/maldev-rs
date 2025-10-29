use thiserror::Error;

/// DRM-specific errors returned by public APIs
#[derive(Debug, Error)]
pub enum DrmError {
    /// Standard IO errors (file operations, etc.)
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Windows API error (GetLastError)
    #[error("Windows API error: {0}")]
    WinApi(u32),

    /// PE image format or address mapping issue
    #[error("Image layout error: {0}")]
    ImageLayout(&'static str),

    /// Slot has inconsistent magic/version/state -> tampering
    #[error("Corrupted or unrecognized embedded data")]
    SlotFormat,

    /// Fingerprint acquisition failed
    #[error("Fingerprint error: {0}")]
    Fingerprint(&'static str),

    /// DRM not locked to this machine
    #[error("Machine mismatch")]
    Mismatch,

    /// FSM state: executable has just been locked, restart required
    #[error("Executable locked, restart required")]
    NotLocked,

    /// Payload modified or erased illegally
    #[error("DRM modified or corrupted")]
    Tampered,

    /// Bad caller inputs or malformed internal data (e.g. hex decoding)
    #[error("Invalid data: {0}")]
    Invalid(&'static str),
}
