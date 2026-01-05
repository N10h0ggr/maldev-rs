use thiserror::Error;

/// Architecture of a PE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArch {
    X86,
    X64,
}

impl std::fmt::Display for PeArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeArch::X86 => write!(f, "x86"),
            PeArch::X64 => write!(f, "x64"),
        }
    }
}

/// Top-level application errors.
///
/// This enum represents failures that occur during orchestration
/// (argument parsing, file I/O, architecture mismatch, etc.).
#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error while reading PE file")]
    Io(#[from] std::io::Error),

    #[error("invalid PE image")]
    InvalidPe(#[from] PeError),

    #[error("architecture mismatch: PE is {pe} but host process is {host}")]
    ArchMismatch {
        pe: PeArch,
        host: PeArch,
    },
}

/// PE loader and execution errors.
///
/// These errors represent failures while parsing, mapping, fixing,
/// or executing a PE image.
#[derive(Debug, Error)]
pub enum PeError {
    #[error("invalid DOS signature")]
    InvalidDosSignature,

    #[error("invalid NT signature")]
    InvalidNtSignature,

    #[error("unsupported PE architecture")]
    UnsupportedArch,

    #[error("structure extends beyond file bounds")]
    OutOfBounds,

    #[error("failed to allocate memory")]
    MemoryAllocationFailed,

    #[error("relocation directory is missing but relocations are required")]
    RelocationsRequired,

    #[error("failed to load imported DLL '{0}'")]
    DllLoadFailed(String),

    #[error("failed to resolve import '{symbol}' from DLL '{dll}'")]
    ImportResolveFailed {
        dll: String,
        symbol: String,
    },

    #[error("failed to change memory protection for section '{name}'")]
    SectionProtectionFailed {
        name: String,
    },

    #[error("failed to register exception handlers")]
    ExceptionHandlerRegistrationFailed,

    #[error("export directory not present")]
    ExportDirectoryMissing,

    #[error("exported function not found: {0}")]
    ExportNotFound(String),

    #[error("failed to join export execution thread")]
    ExportThreadJoinFailed,

    #[error("invalid PEB pointer")]
    InvalidPeb,

    #[error("invalid process parameters")]
    InvalidProcessParameters,

    #[error("heap allocation failed")]
    HeapAllocationFailed,

    #[error("PE image has no entry point")]
    MissingEntryPoint,

    #[error("export execution requested on non-DLL image")]
    ExportOnNonDll,

    #[error("CreateThread failed with Win32 error {0}")]
    CreateThreadFailed(u32),
}
