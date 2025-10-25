# Early Bird APC Injection

Early Bird APC Injection injects and executes shellcode in a newly created process by queuing an Asynchronous Procedure Call (APC) to the process main thread before that thread runs user code. The technique commonly creates or attaches to a process early (for example using the DEBUG_PROCESS flag), writes shellcode into the target address space, queues an APC that points at that shellcode, then detaches so the target resumes and the APC runs.

## Introduction

This library implements the Early Bird APC approach using Windows APIs: CreateProcessA with DEBUG_PROCESS, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx and QueueUserAPC, and finally DebugActiveProcessStop to detach. The goal is a compact, runnable example you can read and adapt. ([Microsoft Learn][2])

## How the technique works (concise, code-oriented)

At a high level the file implements these steps:

1. Create a process set as debugged. The code calls CreateProcessA with the DEBUG_PROCESS flag so the current process becomes the debugger for the new process. This gives the creator write access to the child process memory and control over its lifecycle. ([Adrià Pagès][1])
2. Allocate memory inside the target using VirtualAllocEx and write the payload there with WriteProcessMemory. After writing, the code uses VirtualProtectEx to set executable permissions for the allocated region. Those APIs are the standard primitives for allocating and writing remote memory. ([Microsoft Learn][2])
3. Convert the address into an APC function pointer and call QueueUserAPC against the main thread handle returned by CreateProcessA. QueueUserAPC queues the function address into the target thread APC queue; the APC executes when that thread enters an alertable state or when execution resumes in a context that dispatches user APCs. The QueueUserAPC semantics are documented by Microsoft. ([Microsoft Learn][3])
4. Detach from the debugged process using DebugActiveProcessStop so the target is no longer controlled by the creator; once detached and resumed, the queued APC can run and execute the shellcode. Practical implementations often pause between steps to ensure writes and APC queuing complete reliably before detach. ([Cyberbit][4])

### Notes about the implementation in early_bird_apc.rs

* The file creates the process with DEBUG_PROCESS (not CREATE_SUSPENDED). That means the new process is launched under the creator as debugger, and the code leverages that state to write and queue the APC before detaching. See function create_debugged_process.
* Memory allocation and writing happen in inject_shellcode_to_remote_process. It uses VirtualAllocEx with MEM_COMMIT | MEM_RESERVE, WriteProcessMemory to copy the bytes, then VirtualProtectEx to set PAGE_EXECUTE_READWRITE; this is indeed not a very good OPSEC. The function returns the allocated address. ([Microsoft Learn][2])
* The run function transmutes the returned address to a PAPCFUNC and calls QueueUserAPC(h_thread, p_apc, 0). The code then detaches via DebugActiveProcessStop(dw_process_id) so the target continues without the original process being its debugger. QueueUserAPC execution timing depends on the target thread behavior (alertable state), so the technique leverages the "early" window before typical user-mode hooks run in the target. ([Microsoft Learn][3])

## Example usage

The file exposes a single public function:

```rust
// signature in the file
pub fn run(target: &str, shellcode: &[u8])
```

Example invocation from a small driver program:

```rust
fn main() {
    // small example shellcode (replace with valid payload for testing)
    let shellcode: [u8; 8] = [0x90, 0x90, 0x90, 0x90, 0xC3, 0x00, 0x00, 0x00]; // NOP; NOP; NOP; NOP; RET
    // launches notepad.exe and attempts Early Bird APC injection
    early_bird_apc::run("notepad.exe", &shellcode);
}
```

What the run call does in practice:

* Creates the target process under DEBUG_PROCESS and returns the process and thread handles.
* Allocates RW memory in the remote process and writes your shellcode.
* Sets the region to executable.
* Queues an APC to the main thread that points to the shellcode address.
* Waits for user input, then calls DebugActiveProcessStop to detach and allow the APC to execute.

## Function mapping 

* `run` - orchestrates the whole sequence: create debugged process, inject, QueueUserAPC, detach, close handles.
* `create_debugged_process` - CreateProcessA with DEBUG_PROCESS and basic STARTUPINFOA/PROCESS_INFORMATION handling.
* `inject_shellcode_to_remote_process` - VirtualAllocEx, WriteProcessMemory, VirtualProtectEx; returns the remote address.
* platform/runtime notes - the code uses windows-rs types (HANDLE, PSTR, PAPCFUNC) and windows API wrappers.

## References

* Early Bird writeup by Adrià Pagès: Early Bird Injection. ([Adrià Pagès][1])
* Cyberbit analysis: New Early Bird Code Injection Technique Discovered. ([Cyberbit][4])
* Microsoft Learn: QueueUserAPC function (APC semantics and usage). ([Microsoft Learn][3])
* Microsoft Learn: VirtualAllocEx function (allocating remote memory). ([Microsoft Learn][2])
* Microsoft Learn: WriteProcessMemory function (writing into remote process memory). ([Microsoft Learn][5])

[1]: https://blog.adriapt.com/posts/EarlyBird/?utm_source=chatgpt.com "Early Bird Injection - Adrià Pagès"
[2]: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex?utm_source=chatgpt.com "VirtualAllocEx function (memoryapi.h) - Win32 apps - Microsoft Learn"
[3]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc?utm_source=chatgpt.com "QueueUserAPC function (processthreadsapi.h) - Win32 apps"
[4]: https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/?utm_source=chatgpt.com "New 'Early Bird' Code Injection Technique Discovered"
[5]: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory?utm_source=chatgpt.com "WriteProcessMemory function (memoryapi.h) - Win32 apps"
