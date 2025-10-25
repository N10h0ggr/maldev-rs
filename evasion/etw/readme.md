# ETW Hijacking

Event Tracing for Windows (ETW) is a native Windows telemetry subsystem used by many monitoring tools and EDRs. This project locates an active ETW session by name, stops it, and starts a replacement session that writes to a chosen file. The library exposes a small API so the operation runs in a detached background thread while the caller continues execution.

## Technique and how it is implemented in this library

ETW sessions are named objects that aggregate events from providers and deliver them to consumers or to disk. Windows exposes control APIs that allow querying, stopping and starting sessions. If a process that has the required privileges stops a session and then starts a new session under the same name but with a different target (for example a disk file), a consumer that stays attached to the original session instance can be left receiving no live events. The Binarly research documents practical ways this behavior can blind monitoring tools; this library implements the core control workflow from that analysis. [Binarly][1]

### How the library applies the technique

The library implements a compact control loop that performs three main actions in sequence: lookup, stop, and restart. The code uses the documented ETW APIs and a single safe memory layout for the `EVENT_TRACE_PROPERTIES` structure required by those APIs.

#### 1. Looking for the ETW session

The code tries a direct lookup using `QueryTraceW` first. The crate prepares a contiguous properties buffer using `make_properties_buffers(session_w, None)`, then calls `QueryTraceW`. On success the kernel fills the properties buffer and publishes the session handle in `Wnode.Anonymous1.HistoricalContext`. If the direct lookup fails or the instance is not visible, the code falls back to `QueryAllTracesW` and compares logger names to find the session.

Conceptual code snippet that references the library helper and API wrapper:

```rust
// Build the properties buffer that holds EVENT_TRACE_PROPERTIES + names
let (buf, props) = make_properties_buffers(Some(&session_wide), None);

// QueryTraceW with a default handle to lookup the instance
let status = unsafe {
    QueryTraceW(CONTROLTRACE_HANDLE::default(), session_wide.as_ptr(), props)
};
if status == ERROR_SUCCESS {
    // The kernel-published handle is stored in the Wnode header
    let kernel_handle = unsafe { (*props).Wnode.Anonymous1.HistoricalContext };
    // kernel_handle is used later with stop_trace(...)
}
```

The actual helper in the library is `make_properties_buffers(session_w: Option<&[u16]>, logfile_w: Option<&[u16]>) -> (Vec<u8>, *mut EVENT_TRACE_PROPERTIES)`. The direct lookup function is `query_trace_direct(session_w: &[u16]) -> Result<Option<CONTROLTRACE_HANDLE>, EtwError>`.

#### 2. Stop and restart

After locating the session handle (the kernel handle), the library calls `stop_trace(handle, session_w)` to stop the discovered instance. Immediately after a successful stop, the library constructs a new properties buffer that includes the same session name and a fake log file path, then calls `start_trace_with_file(session_w, fake_w)` which wraps `StartTraceW` and configures the new session to write to a sequential log file. This keeps the session name identical while changing the instance and the consumer-visible output.

Conceptual code snippet that references the library functions:

```rust
// Stop the original instance using the handle discovered earlier
let _ = stop_trace(kernel_handle, &session_wide)?;

// Prepare a properties buffer that contains both the session name and our fake file
let (buf2, props2) = make_properties_buffers(Some(&session_wide), Some(&fake_file_wide));
unsafe {
    (*props2).LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_REAL_TIME_MODE;
}

// Start a replacement session that writes to a disk file
let start_status = start_trace_with_file(&session_wide, &fake_file_wide)?;
```

The library exposes `stop_trace(handle: CONTROLTRACE_HANDLE, session_w: &[u16]) -> Result<(), EtwError>` and `start_trace_with_file(session_w: &[u16], fake_w: &[u16]) -> Result<(), EtwError>` as the wrappers that perform those operations and convert Win32 error codes into `EtwError`.

#### 3. Memory layout and helpers

`EVENT_TRACE_PROPERTIES` must be followed in memory by the UTF-16 logger name and the UTF-16 log file name. The library implements `make_properties_buffers(...)` which allocates a single `Vec<u8>` containing the header and both trailing name regions, writes the UTF-16 data into the trailing parts, and returns a typed `*mut EVENT_TRACE_PROPERTIES` pointing at the header. This single-buffer strategy matches the API expectation while keeping ownership clear and avoiding repeated heap allocations.

Key helpers in the codebase used by the loop are:

* `make_properties_buffers(session_w, logfile_w)` - builds the contiguous buffer expected by ETW control APIs.
* `query_trace_direct(session_w)` - direct `QueryTraceW` lookup, returns the kernel handle when available.
* `query_trace_enumerate_by_name(session)` - fallback using `QueryAllTracesW` and in-place name comparison.
* `stop_trace(...)` and `start_trace_with_file(...)` - wrappers around `StopTraceW` and `StartTraceW` with contextual `EtwError`.

### Runtime model

The public API exposes a `Config` and a `run(cfg)` function. `run` spawns a single detached thread that executes the loop described above; the caller is free to continue. When the process exits the operating system terminates the background thread. The library surfaces contextual errors (`EtwError`) for API failures (permission issues, missing instance, etc.) so callers can log or react to control problems.

#### Example of use

A minimal binary that starts the hijacker:

```rust
use etw_hijack_rs::{Config, run};

fn main() {
    let cfg = Config {
        session: "PROCMON TRACE".to_string(),
        fake_log_file: r"C:\Windows\Temp\fake.etl".to_string(),
    };

    // run spawns a detached background thread that executes the hijack loop
    run(cfg).expect("failed to start ETW hijacker");

    // main program continues while the background loop executes
}
```

## References

* [Binarly - Design issues of modern EDRs: bypassing ETW-based solutions][1]
* [Microsoft Learn - Event Tracing for Windows overview][2]
* [Microsoft Docs - QueryTraceW][3]
* [Microsoft Docs - QueryAllTracesW][4]
* [Microsoft Docs - StartTraceW][5]
* [Microsoft Docs - EVENT_TRACE_PROPERTIES][6]

[1]: https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions
[2]: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-
[3]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-querytracew
[4]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-queryalltracesw
[5]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
[6]: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
