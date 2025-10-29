//! Machine fingerprint generation
//!
//! Simple, offline‐reliable fingerprint based on Windows identifiers:
//!  - ProductId from Registry
//!  - System drive volume serial
//!  - Hostname
//!
//! This fingerprint is converted into a SHA-256 hash for stability.
//!
//! Future expansion may include BIOS UUID, Machine SID, TPM IDs, etc.

use log::{debug, info, warn};
use sha2::{Digest, Sha256};

use crate::errors::DrmError;

/// Strong type representing the machine fingerprint hash.
///
/// Always 32 bytes — do not convert to string unless needed at the edge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; 32]);

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint([32 bytes])")
    }
}

impl Fingerprint {
    /// Computes a fresh fingerprint of the current machine.
    pub fn new() -> Result<Self, DrmError> {
        info!("DRM: computing machine fingerprint");

        let mut data = Vec::new();

        if let Ok(pid) = read_product_id() {
            debug!("Fingerprint: ProductId found");
            data.extend_from_slice(pid.as_bytes());
        } else {
            warn!("Fingerprint: ProductId unavailable");
        }

        if let Ok(serial) = read_volume_serial("C:\\") {
            debug!("Fingerprint: volume serial found");
            data.extend_from_slice(&serial.to_le_bytes());
        } else {
            warn!("Fingerprint: volume serial unavailable");
        }

        if let Ok(host) = std::env::var("COMPUTERNAME") {
            debug!("Fingerprint: hostname found");
            data.extend_from_slice(host.as_bytes());
        } else {
            warn!("Fingerprint: hostname unavailable");
        }

        if data.is_empty() {
            warn!("Fingerprint: no fields available");
            return Err(DrmError::Fingerprint("No fingerprint fields"));
        }

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash: [u8; 32] = hasher.finalize().into();

        debug!("DRM: fingerprint generated");

        Ok(Fingerprint(hash))
    }

    /// Access raw bytes immutably.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Retrieve Windows ProductId from Registry (UTF-8 converted).
fn read_product_id() -> Result<String, DrmError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Registry::*;

    unsafe {
        let key_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0";
        let value = "ProductId\0";

        let mut hkey = HKEY::default();
        let status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr() as _,
            0,
            KEY_READ,
            &mut hkey,
        );

        if status != 0 {
            return Err(DrmError::WinApi(status));
        }

        let mut buf = [0u8; 256];
        let mut len = buf.len() as u32;
        let mut _ty = 0u32;

        let status = RegQueryValueExA(
            hkey,
            value.as_ptr() as _,
            std::ptr::null_mut(),
            &mut _ty,
            buf.as_mut_ptr(),
            &mut len,
        );

        RegCloseKey(hkey);

        if status != 0 || len == 0 {
            let err = GetLastError();
            return Err(DrmError::WinApi(err));
        }

        // Drop trailing null
        let s = String::from_utf8_lossy(&buf[..len as usize - 1]).to_string();
        Ok(s)
    }
}

/// Retrieve volume serial for a given root path (e.g. "C:\\").
fn read_volume_serial(root: &str) -> Result<u32, DrmError> {
    use windows_sys::Win32::{
        Foundation::GetLastError, Storage::FileSystem::GetVolumeInformationA,
    };

    unsafe {
        let path = format!("{root}\0");

        let mut serial = 0u32;
        let ok = GetVolumeInformationA(
            path.as_ptr() as _,
            std::ptr::null_mut(),
            0,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );

        if ok == 0 {
            let err = GetLastError();
            return Err(DrmError::WinApi(err));
        }

        Ok(serial)
    }
}
