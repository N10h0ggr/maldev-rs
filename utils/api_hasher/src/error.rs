use core::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ResolveError {
    ModuleNotFound,
    SymbolNotFound,
    InvalidInterface,
    PlatformSpecificError(u32),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleNotFound => write!(f, "The specified DLL/Library was not found."),
            Self::SymbolNotFound => write!(f, "The function symbol hash could not be resolved."),
            Self::InvalidInterface => write!(f, "Invalid interface or null pointer encountered."),
            Self::PlatformSpecificError(code) => write!(f, "Platform error code: {:#x}", code),
        }
    }
}

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
impl std::error::Error for ResolveError {}
