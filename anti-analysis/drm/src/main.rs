// src/main.rs
use std::process::ExitCode;

fn main() -> ExitCode {
    // Default to info-level logs for the `drm` crate if RUST_LOG is unset.
    if std::env::var_os("RUST_LOG").is_none() {
        unsafe { std::env::set_var("RUST_LOG", "drm=info"); }
    }
    env_logger::init();

    match drm::drm_check() {
        Ok(true) => {
            println!("[ OK ] DRM allowed execution");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("[FAIL] DRM says wrong machine. Terminating.");
            ExitCode::FAILURE
        }
        Err(e) => {
            println!("[ERR] DRM internal failure: {e}");
            ExitCode::FAILURE
        }
    }
}
