use std::fmt;

/// Represents possible errors that can occur while managing
/// hardware breakpoints on a thread.
#[derive(Debug)]
pub enum BreakpointError {
    /// The provided address was null or otherwise invalid.
    InvalidAddress,

    /// The specified thread could not be found or accessed.
    ThreadNotFound(u32),

    /// The specified debug register (Dr0–Dr3) is already in use.
    RegisterInUse,

    /// The operation failed to read the thread’s context.
    ContextReadFailed(u32),

    /// The operation failed to write the thread’s context.
    ContextWriteFailed(u32),

    /// No free debug registers were available in the thread context.
    NoAvailableRegisters,

    /// A general or unspecified error occurred.
    Unknown(u32),
}

impl fmt::Display for BreakpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use BreakpointError::*;
        match self {
            InvalidAddress => write!(f, "The provided address was null or invalid"),
            ThreadNotFound(code) => write!(
                f,
                "Target thread not found or inaccessible (Win32 error: {code})"
            ),
            RegisterInUse => write!(f, "The selected debug register is already in use"),
            ContextReadFailed(code) => {
                write!(f, "Failed to read the thread context (Win32 error: {code})")
            }
            ContextWriteFailed(code) => write!(
                f,
                "Failed to write the thread context (Win32 error: {code})"
            ),
            NoAvailableRegisters => write!(f, "No available hardware breakpoint registers"),
            Unknown(code) => write!(f, "An unknown error occurred (Win32 error: {code})"),
        }
    }
}

impl std::error::Error for BreakpointError {}
