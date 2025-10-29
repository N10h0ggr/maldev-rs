use log::{debug, error, info, warn};
use std::{ffi::OsString, os::windows::ffi::OsStringExt, slice};
use windows_sys::Win32::Foundation::GetLastError;

use crate::errors::DrmError;
use crate::fingerprint::Fingerprint;
use crate::image_pe::PeImage;
use winapi::get_peb;
use winapi::{list_sections, parse_dos_header, parse_nt_headers};

/// Built-in default bytes for the machine-ID slot.
///
/// Kept as a single constant so the two statics below can reference the same data
/// without duplicating literals in multiple places.
pub(crate) const DEFAULT_HASH_BYTES: [u8; 32] = [
    0xAA, 0xBB, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
];

/// Fingerprint slot embedded in the binary.
///
/// Placed in a dedicated read-only subsection to make it easy to find in the PE.
/// Not exported by default; enable the `expose_symbols` feature to give it a fixed symbol name.
#[cfg_attr(feature = "expose_symbols", no_mangle)]
#[unsafe(link_section = ".rdata.g_machine_id")]
#[used]
pub(crate) static G_MACHINE_ID: [u8; 32] = DEFAULT_HASH_BYTES;

/// Independent copy of the default bytes to compare against at runtime.
///
/// Kept in a distinct subsection to avoid accidental folding with the slot.
/// Not exported by default; enable the `expose_symbols` feature to give it a fixed symbol name.
#[cfg_attr(feature = "expose_symbols", no_mangle)]
#[unsafe(link_section = ".rdata.default_hash")]
#[used]
pub(crate) static DRM_DEFAULT_HASH: [u8; 32] = DEFAULT_HASH_BYTES;

/// Returns `true` if the embedded `G_MACHINE_ID` still equals the builtin default.
///
/// Uses volatile reads to force actual memory loads and avoid constant folding/inlining.
#[inline(always)]
pub(crate) fn machine_id_is_default() -> bool {
    // Safety: reading POD statics by value
    let g = unsafe { core::ptr::read_volatile(&G_MACHINE_ID) };
    let d = unsafe { core::ptr::read_volatile(&DRM_DEFAULT_HASH) };
    g == d
}

/// Run once to patch the on-disk image with the current machine fingerprint.
///
/// Finds the `.rdata` slot, replaces the 32-byte default with the computed fingerprint,
/// deletes the original image, and writes the patched image back to the same path.
pub(crate) fn initialize_drm() -> Result<(), DrmError> {
    if !machine_id_is_default() {
        warn!("G_MACHINE_ID is not default; initialization skipped");
        return Err(DrmError::Mismatch);
    }

    let peb = get_peb().ok_or_else(|| DrmError::WinApi(unsafe { GetLastError() }))?;
    let process_params = unsafe { &*peb.ProcessParameters };
    let unicode_str = &process_params.ImagePathName;

    if unicode_str.Buffer.is_null() || unicode_str.Length == 0 {
        error!("PEB ImagePathName is empty or invalid");
        return Err(DrmError::ImageLayout("empty ImagePathName"));
    }

    let len = (unicode_str.Length / 2) as usize;
    let wide = unsafe { slice::from_raw_parts(unicode_str.Buffer, len) };
    let file_path = OsString::from_wide(wide).to_string_lossy().into_owned();

    debug!("Current executable path: {}", file_path);

    let pe = PeImage { file_path };
    let (buffer, file_size) = pe.read_self_from_disk()?;
    if buffer.is_empty() {
        error!("Loaded PE image is empty");
        return Err(DrmError::ImageLayout("empty image file"));
    }

    let dos_hdr = parse_dos_header(&buffer).map_err(DrmError::ImageLayout)?;
    let nt_hdrs = parse_nt_headers(&buffer, dos_hdr).map_err(DrmError::ImageLayout)?;
    let sections = list_sections(&buffer, nt_hdrs).map_err(DrmError::ImageLayout)?;

    info!(
        "Loaded PE image: {} sections, file size: {} bytes",
        sections.len(),
        file_size
    );

    // Locate the slot inside .rdata* and compute absolute file offset
    let mut absolute_offset: Option<usize> = None;

    'sections: for sec in sections {
        let name = String::from_utf8_lossy(&sec.Name);
        let section_name = name.trim_end_matches('\0');

        if !section_name.starts_with(".rdata") {
            continue;
        }

        let start = sec.PointerToRawData as usize;
        let size = sec.SizeOfRawData as usize;

        if start + size > buffer.len() {
            error!(".rdata section out of bounds");
            return Err(DrmError::ImageLayout(".rdata section out of range"));
        }

        let rdata = &buffer[start..start + size];

        for i in 0..=(rdata.len().saturating_sub(G_MACHINE_ID.len())) {
            if rdata[i..i + G_MACHINE_ID.len()] == G_MACHINE_ID {
                let abs = start + i;
                debug!(
                    "G_MACHINE_ID ({} bytes) found in {} at file offset 0x{:X} (section+0x{:X})",
                    G_MACHINE_ID.len(),
                    section_name,
                    abs,
                    i
                );
                absolute_offset = Some(abs);
                break 'sections;
            }
        }
    }

    if let Some(abs_off) = absolute_offset {
        info!("G_MACHINE_ID located — preparing to patch with machine fingerprint");

        let fingerprint = Fingerprint::new()?;
        let new_hash = fingerprint.as_bytes(); // &[u8; 32]
        debug!("Fingerprint generated: {:02X?}", new_hash);

        if abs_off + new_hash.len() > buffer.len() {
            error!("Calculated patch offset exceeds buffer size");
            return Err(DrmError::ImageLayout("fingerprint patch out of bounds"));
        }

        let mut patched_buffer = buffer.clone();
        debug!(
            "Overwriting G_MACHINE_ID at file offset 0x{:X} with new {}-byte fingerprint",
            abs_off,
            new_hash.len()
        );
        patched_buffer[abs_off..abs_off + new_hash.len()].copy_from_slice(new_hash);

        debug!("Deleting current executable (contains DEFAULT_HASH)...");
        pe.delete_self_from_disk()?;
        info!("Original executable successfully deleted");

        let target_path = &pe.file_path;
        debug!(
            "Writing patched executable to '{}' (new G_MACHINE_ID applied)",
            target_path
        );
        pe.write_self_to_disk(target_path, &patched_buffer)?;
        info!("Patched executable written to disk successfully");

        return Ok(());
    }

    warn!("No G_MACHINE_ID found in image; nothing patched");
    Ok(())
}

/// Compare the current machine fingerprint with the embedded `G_MACHINE_ID`.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, or `Err(_)` on failures.
pub(crate) fn compare_machine_hash() -> Result<bool, DrmError> {
    if machine_id_is_default() {
        debug!("G_MACHINE_ID equals DEFAULT — DRM not yet initialized");
        return Ok(true);
    }

    debug!("Computing live machine fingerprint for comparison...");
    let fingerprint = Fingerprint::new()?;
    let current_hash = fingerprint.as_bytes();

    if current_hash != &G_MACHINE_ID {
        warn!("Machine fingerprint mismatch detected");
        debug!("Embedded: {:02X?}", &G_MACHINE_ID);
        debug!("Current : {:02X?}", current_hash);
        return Ok(false);
    }

    info!("Machine fingerprint matches embedded G_MACHINE_ID");
    Ok(true)
}

/// High-level orchestration used by the crate’s public `drm_check()`.
///
/// - On first run, patches the image and returns `Ok(true)`.
/// - On subsequent runs, verifies the fingerprint and returns:
///   `Ok(true)` on match, `Ok(false)` on mismatch.
pub(crate) fn drm_check() -> Result<bool, DrmError> {
    if machine_id_is_default() {
        info!("First time running — initializing DRM protection...");
        initialize_drm()?;
        info!("DRM successfully initialized and image patched");
        return Ok(true);
    }

    info!("Existing DRM fingerprint detected — verifying integrity...");
    compare_machine_hash()
}
