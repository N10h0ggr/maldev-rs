#![allow(unsafe_op_in_unsafe_fn)]
//! This crate provides an ergonomic API to manually map, protect, and execute
//! PE images (EXE or DLL) within the current process.

use std::fs;
use std::path::{Path, PathBuf};

use crate::arch::HOST_ARCH;
use crate::errors::AppError;
use crate::pe_executor::{
    execute_dll_main,
    execute_exe_entry_point,
    execute_requested_export,
    execute_tls_callbacks,
    fix_arguments,
};
use crate::pe_mapper::{
    fix_imports,
    fix_memory_permissions,
    fix_reloc,
    map_pe_image,
    register_exception_handlers,
};
use crate::pe_parser::PeImage;

pub mod arch;
pub mod arg_parser;
pub mod errors;
pub mod pe_executor;
pub mod pe_mapper;
pub mod pe_parser;
pub mod pe_fluctuation;

/// Load and execute a PE image from disk.
///
/// If the image is an EXE, it executes the entry point.
/// If it is a DLL, it executes DllMain with DLL_PROCESS_ATTACH.
pub fn run(path: impl AsRef<Path>, args: Vec<String>) -> Result<(), AppError> {
    run_internal(path.as_ref(), args, None)
}

/// Load a DLL from disk and execute a specific named export.
pub fn run_with_export(
    path: impl AsRef<Path>,
    args: Vec<String>,
    export: impl Into<String>,
) -> Result<(), AppError> {
    run_internal(path.as_ref(), args, Some(export.into()))
}


fn run_internal(pe_path: &Path, args: Vec<String>, export: Option<String>) -> Result<(), AppError> {
    let pe_path: PathBuf = pe_path.to_path_buf();
    let pe_bytes = fs::read(&pe_path)?;
    let pe = PeImage::parse(pe_bytes)?;

    let pe_arch = pe.arch();
    if pe_arch != HOST_ARCH {
        return Err(AppError::ArchMismatch {
            pe: pe_arch,
            host: HOST_ARCH,
        });
    }

    // Manual Mapping
    let base = map_pe_image(&pe)?;

    fix_reloc(&pe, base)?;
    fix_imports(&pe, base)?;

    // Ensure the mapped image's PEB points to the provided arguments
    fix_arguments(&args)?;

    register_exception_handlers(&pe, base)?;

    let rx_region = fix_memory_permissions(&pe, base)?;

    // Fluctuation Initialization
    if let Some((rx_addr, rx_size)) = rx_region {
        println!("[*] Initializing Fluctuation: 0x{:X} ({} bytes)", rx_addr, rx_size);
        unsafe {
            if let Err(e) = pe_fluctuation::initialize_fluctuation(rx_addr, rx_size) {
                log::error!("Fluctuation initialization failed: {}", e);
            } else {
                log::info!("Fluctuation timer active.");
            }
        }
    } else {
        log::warn!("No RX section detected. Fluctuation will not be enabled.");
    }

    // Execution
    execute_tls_callbacks(&pe, base)?;

    if pe.is_dll() {
        execute_dll_main(&pe, base)?;
        execute_requested_export(&pe, base, export.as_deref())?;
    } else {
        execute_exe_entry_point(&pe, base)?;
    }

    Ok(())
}