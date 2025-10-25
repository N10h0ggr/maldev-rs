use thiserror::Error;

/// Represents all possible errors that can occur while using the ETW hijacker.
///
/// This enum provides structured error information to help diagnose failures
/// originating from Windows API calls, string conversions, or internal logic.
#[derive(Error, Debug)]
pub enum EtwError {
    /// A Windows API function returned a failure code.
    ///
    /// The inner value stores the raw Win32 error code (`GetLastError()`).
    /// Prefer using [`Self::from_winapi`] to convert from an error code with context.
    #[error("Windows API error {code} during {context}")]
    WinApi {
        code: i32,
        context: &'static str,
    },

    /// Failed to convert between UTF-8 and UTF-16 strings.
    ///
    /// This usually occurs when interacting with Windows functions that
    /// require wide (UTF-16) strings.
    #[error("String conversion failed")]
    StringConversion,

    /// Failed to create or manage a thread.
    #[error("Thread creation or management error: {0}")]
    Thread(String),

    /// Failed to start or attach to an ETW session.
    #[error("ETW session error: {0}")]
    EtwSession(String),

    /// Unexpected internal logic failure.
    ///
    /// Used for errors that don't fall into a specific category.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl EtwError {
    /// Convenience constructor for wrapping a raw Win32 error with context.
    ///
    /// # Example
    /// ```ignore
    /// let err = EtwError::from_winapi(5, "StartTraceW");
    /// ```
    pub fn from_winapi(code: i32, context: &'static str) -> Self {
        Self::WinApi { code, context }
    }
}

impl From<i32> for EtwError {
    fn from(code: i32) -> Self {
        // Generic fallback when context is unknown.
        EtwError::WinApi {
            code,
            context: "unknown",
        }
    }
}
