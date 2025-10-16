use std::fmt;

/// Represents all possible errors that can occur while managing
/// hardware breakpoints or the VEH subsystem.
#[derive(Debug)]
pub enum HwbpError {
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

    /// AddVectoredExceptionHandler failed; carries GetLastError() code.
    VehRegistrationFailed(u32),

    /// A required pointer argument was null.
    NullPointer { what: &'static str },

    /// Failed to initialize the vectored exception handler (VEH).
    VehInitFailed(&'static str),

    /// Thread enumeration via NtQuerySystemInformation failed.
    ThreadEnumerationFailed,

    /// The global hook registry mutex was poisoned.
    RegistryPoisoned,

    /// Failed to install a breakpoint for at least one thread.
    InstallFailed,

    /// Failed to remove a breakpoint or cleanup an existing one.
    RemoveFailed,

    /// Attempted to install a hook that already exists.
    AlreadyInstalled,

    /// A general or unspecified error occurred.
    Unknown(u32),
}

impl fmt::Display for HwbpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use HwbpError::*;

        match self {
            InvalidAddress => write!(f, "The provided address was null or invalid"),
            ThreadNotFound(code) => {
                write!(
                    f,
                    "Target thread not found or inaccessible (Win32 error: {code})"
                )
            }
            RegisterInUse => write!(f, "The selected debug register is already in use"),
            ContextReadFailed(code) => {
                write!(f, "Failed to read the thread context (Win32 error: {code})")
            }
            ContextWriteFailed(code) => {
                write!(
                    f,
                    "Failed to write the thread context (Win32 error: {code})"
                )
            }
            NoAvailableRegisters => write!(f, "No available hardware breakpoint registers"),
            VehRegistrationFailed(code) => {
                write!(
                    f,
                    "AddVectoredExceptionHandler failed (Win32 error: {code})"
                )
            }
            NullPointer { what } => write!(f, "The parameter `{what}` cannot be null"),

            VehInitFailed(msg) => write!(f, "Failed to initialize VEH: {msg}"),
            ThreadEnumerationFailed => write!(f, "Failed to enumerate process threads"),
            RegistryPoisoned => write!(f, "Global hook registry is poisoned"),
            InstallFailed => write!(f, "Failed to install a hardware breakpoint"),
            RemoveFailed => write!(f, "Failed to remove a hardware breakpoint"),
            AlreadyInstalled => write!(f, "A breakpoint is already installed for this target"),
            Unknown(code) => write!(f, "An unknown error occurred (Win32 error: {code})"),
        }
    }
}

impl std::error::Error for HwbpError {}
