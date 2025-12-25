#![allow(unsafe_op_in_unsafe_fn)]

use std::error::Error as StdError;
use std::fs;

use env_logger::{Builder, Env};
use log::{info, LevelFilter};

use crate::arg_parser::parse_args;
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

mod arg_parser;
mod arch;
mod errors;
mod pe_executor;
mod pe_mapper;
mod pe_parser;

fn main() {
    init_logging();

    if let Err(err) = run() {
        log::error!("{err}");

        // Print chained causes (useful with #[from]).
        let mut source = err.source();
        while let Some(cause) = source {
            log::error!("  caused by: {cause}");
            source = cause.source();
        }

        std::process::exit(1);
    }
}

/// Initializes logging.
///
/// Behavior:
/// - Respects `RUST_LOG` (e.g. `RUST_LOG=nitinol=debug`)
/// - Defaults to `info`
/// - Compact format with timestamp, level and target
fn init_logging() {
    let env = Env::default().filter_or("RUST_LOG", "info");

    Builder::from_env(env)
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            use std::io::Write;

            writeln!(
                buf,
                "[{} {:<5} {}] {}",
                buf.timestamp_millis(),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();
}

fn run() -> Result<(), AppError> {
    let args = parse_args();

    info!("host architecture: {}", HOST_ARCH);

    /* ------------------------------------------------------------------ */
    /* Parse PE                                                            */
    /* ------------------------------------------------------------------ */

    let pe_bytes = fs::read(&args.pe)?;
    let pe = PeImage::parse(pe_bytes)?;

    let pe_arch = pe.arch();
    if pe_arch != HOST_ARCH {
        return Err(AppError::ArchMismatch {
            pe: pe_arch,
            host: HOST_ARCH,
        });
    }

    info!("loaded PE '{}' ({})", args.pe, pe_arch);

    /* ------------------------------------------------------------------ */
    /* Manual mapping                                                      */
    /* ------------------------------------------------------------------ */

    let base = map_pe_image(&pe)?;

    fix_reloc(&pe, base)?;
    fix_imports(&pe, base)?;
    fix_arguments(&args.param)?;

    // x64: registers unwind metadata
    // x86: no-op
    register_exception_handlers(&pe, base)?;

    fix_memory_permissions(&pe, base)?;

    /* ------------------------------------------------------------------ */
    /* Execution                                                           */
    /* ------------------------------------------------------------------ */

    execute_tls_callbacks(&pe, base)?;

    if pe.is_dll() {
        execute_dll_main(&pe, base)?;
        execute_requested_export(&pe, base, args.export.as_deref())?;
    } else {
        execute_exe_entry_point(&pe, base)?;
    }

    Ok(())
}
