# Self-Patching Machine-Locked DRM

This crate implements a machine-locked DRM system that modifies its own file on first execution. The goal is simple: prevent an executable from running on any system other than the one where it was first launched.

During the initial run, a 32-byte placeholder embedded in the program’s `.rdata` is replaced in the file on disk with a fingerprint derived from the machine’s identity. Future runs recompute that fingerprint and only allow execution if it matches the embedded one.

## How the technique works

The process has three pieces that work together: locating the placeholder, patching the file, and checking identity on every run.

### Placeholder lookup
The PE file is read back from disk and parsed. `.rdata`-related sections are scanned until the default static 32-byte pattern is found. Placing the placeholder in a dedicated read-only subsection makes this search reliable.

### Self-patching
A machine fingerprint is generated (for example via Product ID, volume serial, hostname). That fingerprint overwrites the placeholder in the file buffer. The original file is deleted and replaced with the patched one, so future executions see the fingerprint rather than the default.

### Runtime verification
Each run recomputes the fingerprint. If it matches what is embedded in `.rdata`, the environment is the same machine and execution is allowed. If not, the application can deny execution.

## Library architecture

- `drm.rs` hosts the runtime controller: first-run patching, fingerprint comparison, and the public `drm_check()` used by consumers.

- `errors.rs` defines a clean error enum used across PE parsing, file IO, and fingerprint generation.

- `lib.rs` exposes a minimal public surface: a single `drm_check()` entrypoint.

- `main.rs` shows the intended startup usage in a real application.

- `image_pe.rs` reading/writing the executable image from/to disk and helpers for safe file-level operations.

- `fingerprint.rs` gathers host identifiers and produces the 32-byte fingerprint.

## Usage example

Call the library at the beginning of your program. That’s all the user needs to integrate.

```rust
// src/main.rs
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "drm=info");
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
```

This function handles both installation (first run) and verification (every run). It returns a boolean for allow/deny, and structured errors for internal issues.

## Characteristics of the library

The fingerprint placeholder is stored in a custom `.rdata` subsection (`.rdata.g_machine_id`). A separate copy of the default bytes is kept in a different subsection (`.rdata.default_hash`). This prevents unintended merging and lets the library reliably detect whether the image has been patched.

Only a single function is publicly exposed (`drm_check`). All other internals are crate-private to reduce the static “signature surface” of the library. Symbol export is optional; names remain hidden unless a debug feature is intentionally enabled.

The library modifies the on-disk file rather than the running process, keeping the mechanism compatible with normal OS protections. If execution is copied to a different system, the embedded fingerprint no longer matches, so the application can refuse to execute.


## References

* M Ahmadvand et al., *A Taxonomy of Software Integrity Protection Techniques* (2018). [https://www.doc.ic.ac.uk/~fkelbert/papers/aic18.pdf](https://www.doc.ic.ac.uk/~fkelbert/papers/aic18.pdf)  — discusses techniques such as self-checksumming and binary transformations that closely align with your method. ([doc.ic.ac.uk][1])
* Mohsen Ahmadvand, Daniel Below, Sebastian Banescu & Alexander Pretschner, *VirtSC: Combining Virtualization Obfuscation with Self-Checksumming* (2019). [https://arxiv.org/abs/1909.11404](https://arxiv.org/abs/1909.11404)  — presents a layered protection approach where a binary is adjusted post-build, similar in spirit to your fingerprint replacement. ([arXiv][2])
* J.F. Reid, “DRM, Trusted Computing and Operating System Architecture” (2005). [https://web2.qatar.cmu.edu/cs/15349/dl/DRM-TC.pdf](https://web2.qatar.cmu.edu/cs/15349/dl/DRM-TC.pdf)  — explores the concept of fingerprinting executables and system state for trust-based execution, which matches your binding-to-machine idea. ([Carnegie Mellon University Qatar][3])

[1]: https://www.doc.ic.ac.uk/~fkelbert/papers/aic18.pdf?utm_source=chatgpt.com "A Taxonomy of Software Integrity Protection Techniques"
[2]: https://arxiv.org/abs/1909.11404?utm_source=chatgpt.com "VirtSC: Combining Virtualization Obfuscation with Self-Checksumming"
[3]: https://web2.qatar.cmu.edu/cs/15349/dl/DRM-TC.pdf?utm_source=chatgpt.com "DRM, Trusted Computing and Operating System Architecture"
[4]: https://d3fend.mitre.org/technique/d3f%3AProcessSelf-ModificationDetection/?utm_source=chatgpt.com "Process Self-Modification Detection - Technique D3-PSMD"
[5]: https://revflash.medium.com/its-morphin-time-self-modifying-code-sections-with-writeprocessmemory-for-edr-evasion-9bf9e7b7dced?utm_source=chatgpt.com "It's Morphin' Time: Self-Modifying Code Sections with ..."
