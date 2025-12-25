
# Local PE Mapper

This library is a Windows manual PE loader written in Rust.

Instead of creating a new process with `CreateProcess`, it maps a PE file
(EXE or DLL) directly into the current process and executes it. The goal is to
replicate the essential behavior of the Windows loader while keeping the design
simple and explicit.

The project can be used either as a standalone binary or as a Rust library.

## How it works

At a high level, performs the following steps:

- Parses the PE file (headers, sections, directories)
- Allocates memory and maps the image into the process
- Applies base relocations if the image is not loaded at its preferred address
- Resolves imported functions using `LoadLibrary` and `GetProcAddress`
- Fixes memory protections for each section (RX, RW, etc.)
- Executes TLS callbacks if present
- Transfers execution to the PE entry point (EXE) or calls `DllMain` (DLL)

Because the image is manually mapped, no new process is created. This means
there is no real process startup sequence, no new PEB, and no full CRT
initialization like Windows would normally perform.

To make common tools work correctly, it patches the command line stored in
the PEB so the mapped image can read its arguments via `GetCommandLineW`.

## Building

THis library targets Windows and requires a Rust toolchain using MSVC.

To build the project for x64:

```powershell
cargo build --release
````

For a release build x86:

```powershell
cargo build --release --target i686-pc-windows-msvc
```

## Usage

### As a binary

When used as a CLI tool, Nitinol loads and executes a PE file inside the current
process:

```powershell
manual_map.exe --pe mimikatz.exe --parm coffee exit
```

The arguments are exposed to the mapped image through the patched command line.

### As a library

Nitinol can also be embedded into other Rust projects:

```rust
use manual_map::run;

run(
    "payload/x64/mimikatz.exe",
    vec!["coffee".into(), "exit".into()],
)?;
```

For DLLs, it is possible to execute a specific exported function:

```rust
use manual_map::run_with_export;

run_with_export(
    "payload/x64/test.dll",
    vec![],
    "ExportedFunction",
)?;
```
