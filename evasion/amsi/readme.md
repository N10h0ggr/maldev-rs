# AMSI HWBP Patch

Small Rust crate that installs a hardware-breakpoint detour on `AmsiScanBuffer` so calls return `AMSI_RESULT_CLEAN`. It finds the AMSI export, installs a hardware breakpoint via the `hwbp` crate, and the detour mutates the interrupted thread `CONTEXT` to short-circuit the real call.

## What it does 

* Locates `AmsiScanBuffer` in `amsi.dll` using loader APIs and resolves the function address. ([Microsoft Learn][1])
* Installs a hardware breakpoint detour via `hwbp::manager::install_hwbp`.
* Detour runs in the target thread context and updates the `CONTEXT`/return value so the scan reports `AMSI_RESULT_CLEAN`. ([Microsoft Learn][3])

## API

```rust
pub fn patch() -> Result<(), AmsiError>
```

Returns `Ok(())` when the breakpoint is installed. Errors are typed in `errors::AmsiError`:

* `GetModuleHandleFailed(u32)`
* `GetProcAddressFailed(u32)`
* `InstallHwBpFailed(String)`

## Usage

```rust
use amsi_hwbp_patch::patch;

fn main() {
    match patch() {
        Ok(()) => println!("AmsiScanBuffer detour installed"),
        Err(e) => eprintln!("install failed: {}", e),
    }
    // The detour executes whenever a thread hits the HWBP.
}
```

## References

* AMSI overview (Antimalware Scan Interface). ([Microsoft Learn][4])
* `AmsiScanBuffer` function reference. ([Microsoft Learn][3])
* `GetProcAddress` / loader APIs (used to resolve the export). ([Microsoft Learn][1])
* `CONTEXT` structure (thread register context manipulated by the detour). ([Microsoft Learn][5])

[1]: https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress?utm_source=chatgpt.com "GetProcAddress function (libloaderapi.h) - Win32 apps"
[3]: https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer?utm_source=chatgpt.com "AmsiScanBuffer function (amsi.h) - Win32 apps"
[4]: https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal?utm_source=chatgpt.com "Antimalware Scan Interface (AMSI) - Win32 apps"
[5]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context?utm_source=chatgpt.com "CONTEXT structure (x86 64-bit) - Win32"
