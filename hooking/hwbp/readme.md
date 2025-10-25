# Hardware Breakpoints Hooking

Hardware Breakpoints use CPU debug registers (Dr0–Dr3) and a process-wide Vectored Exception Handler (VEH) to implement function hooks without patching target code. The crate installs per-thread hardware breakpoints that transfer control to a user-supplied detour when the monitored instruction executes.

This project writes the target address into thread CONTEXT debug registers (Dr0–Dr3) and enables the breakpoint via Dr7. When the CPU raises a single-step exception for a hardware breakpoint, the global VEH inspects the exception and dispatches to the registered detour. To cover threads created after installation, the library intercepts NtCreateThreadEx and seeds new threads with the configured breakpoints before they start running.

## How the technique works

At a glance the technique has three parts: breakpoint installation, exception dispatch, and thread propagation.

- **Breakpoint Instalation**: A breakpoint is placed by writing the target address into one of Dr0..Dr3 for a thread and setting the enable bits in Dr7. The library chooses a free Drx per thread, writes the thread CONTEXT (GetThreadContext / SetThreadContext) and records the mapping in a global registry. 
- **Exception dispatch**: A single process-wide VEH receives STATUS_SINGLE_STEP events caused by hardware breakpoints. The VEH determines which Drx fired, looks up the registered hook for the current thread, and calls the user detour with the thread CONTEXT pointer. The detour can inspect or modify arguments, return values, and the instruction pointer before allowing execution to continue.
- **Thread propagation**: Debug registers are per-thread, so hooks installed earlier must be mirrored into threads created later. The library detours NtCreateThreadEx so created threads are forced to start suspended, a callback seeds the debug registers in the freshly-created thread, and then the thread is resumed. This ensures breakpoints exist before user code runs.

If readers want the exact implementation details, the code is organized to keep low-level unsafe operations isolated and readable; consult the relevant source files for full behavior.

## Library architecture

Key modules and what they do

* `src/core/breakpoint.rs` - low-level routines that read/modify thread CONTEXT to set/clear Dr0..Dr3 and Dr7.
* `src/core/context.rs` - helpers for manipulating Dr7 control bits (type, length, enable).
* `src/core/veh.rs` - VEH registration and the vectored exception callback that dispatches to detours.
* `src/detour/callargs.rs` - `CallArgs` wrapper around a raw `CONTEXT` pointer for safe argument and return-value manipulation.
* `src/detour/callbacks.rs` - NtCreateThreadEx detour and the timed callback that propagates hooks into new threads.
* `src/manager/*` - public install/uninstall APIs and the in-process hook registry.

## Example: Installing breakpoints

Basic install/uninstall pattern

```rust
use std::ffi::c_void;
use hwbp::manager;

// target: pointer to the monitored instruction (for example a function entry)
// detour: pointer to your detour function (see CallArgs example below)

let target_addr: *const c_void = 0x12345678 as *const c_void;
let my_detour: *const c_void = my_detour_fn as *const c_void;

// Install the hardware-breakpoint hook across existing threads and enable propagation
manager::install_hwbp(target_addr, my_detour).expect("install failed");

// To remove the hook for that target
manager::uninstall_hwbp(target_addr).expect("uninstall failed");

// To remove all hooks installed by the library
manager::uninstall_all_hwbp().expect("uninstall all failed");
```

All public manager APIs are in `src/manager/mod.rs`. `install_hwbp` ensures the VEH is initialized, installs the HWBP on all current threads, and arranges propagation for new threads.

## Example: Writing a detour

The crate exposes `CallArgs`, a small helper around a raw Windows `CONTEXT` pointer. When the VEH calls your detour it passes a `*mut CONTEXT`. The expected detour signature is:

```rust
unsafe extern "system" fn detour(ctx: *mut windows_sys::Win32::System::Diagnostics::Debug::CONTEXT)
```

Create a `CallArgs` from that pointer and use its methods to read or modify function arguments, set return values, change the instruction pointer, or resume normal execution. `CallArgs` methods you will commonly use:

* `CallArgs::new(ctx)` - construct from `*mut CONTEXT` (unsafe).
* `get(index)` / `get_ptr<T>(index)` - read the Nth argument (1-based).
* `set(index, value)` - write the Nth argument (1-based).
* `set_return_usize(value)` / `set_return_ptr<T>(ptr)` - set integer/pointer return value.
* `set_rip(addr)` - set the instruction pointer where execution will resume.
* `continue_execution()` - mark the context so execution continues after the detour.

Example detour that inspects and modifies the first argument, then continues:

```rust
use hwbp::CallArgs;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

unsafe extern "system" fn my_detour(ctx: *mut CONTEXT) {
    // SAFETY: `ctx` is provided by the OS inside the VEH callback and is valid for the current thread.
    let mut args = unsafe { CallArgs::new(ctx) };

    // Read first argument (1-based). On x64 this reads RCX.
    let a1 = unsafe { args.get(1) };

    // Example: increment the first argument before the original function sees it.
    unsafe { args.set(1, a1.wrapping_add(1)) };

    // Optionally force a return value immediately and skip the original instruction:
    // unsafe { args.set_return_usize(0); }
    // unsafe { args.set_rip(return_resume_address); }

    // Mark context so execution resumes. VEH will continue execution using the modified CONTEXT.
    unsafe { args.continue_execution() };
}
```

**Notes and safety considerations**

* `CallArgs` is intentionally low-level and unsafe: modifying registers or stack slots must be done carefully and only when you understand the target ABI and stack layout.
* Use the `get`/`set` index semantics shown above (1-based). On x64 the first four integer args map to RCX, RDX, R8, R9; others are on the stack. On x86 arguments are always on the stack.
* If you change the instruction pointer with `set_rip`, make sure the address is valid and the control flow you create is consistent with expected stack/return semantics.
* The detour signature is `unsafe extern "system" fn(*mut CONTEXT)` because the VEH invokes it from native exception callback code.

## References

* LingSec - Hardware breakpoints and exceptions on Windows. (technical deep dive) ([LingSec][1])
* Microsoft Learn - Vectored Exception Handling. ([Microsoft Learn][2])
* Microsoft Learn - Using a Vectored Exception Handler (sample and guidance). ([Microsoft Learn][4])
* pinvoke.dev - NtCreateThreadEx reference and thread-create flags. ([pinvoke.dev][3])
* Example repository implementing similar strategies. ([GitHub][5])

[1]: https://ling.re/hardware-breakpoints/?utm_source=chatgpt.com
[2]: https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling?utm_source=chatgpt.com
[3]: https://www.pinvoke.dev/ntdll/ntcreatethreadex?utm_source=chatgpt.com
[4]: https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler?utm_source=chatgpt.com
[5]: https://github.com/rad9800/hwbp4mw?utm_source=chatgpt.com
