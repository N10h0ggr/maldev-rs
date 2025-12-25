#![allow(unsafe_op_in_unsafe_fn)]
//! Nitinol – Manual PE loader (library interface)
//!
//! This crate provides a small, ergonomic API to manually map and execute
//! PE images (EXE or DLL) inside the current process.

use std::fs;
use std::path::{Path, PathBuf};

use crate::arch::HOST_ARCH;
use crate::errors::AppError;
use crate::pe_executor::{
    execute_dll_main, execute_exe_entry_point, execute_requested_export, execute_tls_callbacks,
    fix_arguments_for_image,
};
use crate::pe_mapper::{
    fix_imports, fix_memory_permissions, fix_reloc, map_pe_image, register_exception_handlers,
};
use crate::pe_parser::PeImage;

pub mod arch;
pub mod errors;
pub mod pe_executor;
pub mod pe_mapper;
pub mod pe_parser;

/// Load and execute a PE image from disk.
///
/// - If the image is an EXE: executes its entry point.
/// - If the image is a DLL: calls `DllMain(DLL_PROCESS_ATTACH)`.
///
/// `args` are exposed to the mapped image via the PEB process parameters
/// (ImagePathName + CommandLine).
pub fn run(path: impl AsRef<Path>, args: Vec<String>) -> Result<(), AppError> {
    run_internal(path.as_ref(), args, None)
}

/// Load a DLL and execute a named export.
///
/// The export is executed via the existing executor implementation.
pub fn run_with_export(
    path: impl AsRef<Path>,
    args: Vec<String>,
    export: impl Into<String>,
) -> Result<(), AppError> {
    run_internal(path.as_ref(), args, Some(export.into()))
}

/* -------------------------------------------------------------------------- */
/* Internal implementation                                                    */
/* -------------------------------------------------------------------------- */

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

    let base = map_pe_image(&pe)?;

    fix_reloc(&pe, base)?;
    fix_imports(&pe, base)?;

    // Critical: make the mapped image see the *real* PE path as argv[0]
    // and the provided args as argv[1..].
    fix_arguments_for_image(&pe_path, &args)?;

    // x64: registers unwind metadata; x86: no-op
    register_exception_handlers(&pe, base)?;

    fix_memory_permissions(&pe, base)?;
    execute_tls_callbacks(&pe, base)?;

    if pe.is_dll() {
        execute_dll_main(&pe, base)?;
        execute_requested_export(&pe, base, export.as_deref())?;
    } else {
        execute_exe_entry_point(&pe, base)?;
    }

    Ok(())
}
