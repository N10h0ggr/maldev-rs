
# maldev-rs

maldev-rs is a collection of malware-development samples and reusable Rust libraries I build for research, learning and experimentation. The objective is to provide ready-to-use libraries you can drop into larger projects, learn from, and have fun with while exploring low-level Windows techniques in Rust.

I try to document the code and the techniques used in the libraries. If you have questions, check the README files inside each library and read the implementation. 

> **Warning:** These samples are potentially harmful and some are not widely tested. Do not compile or run them on production systems without proper testing and containment.

## Project overview

This repo provides focused examples of low-level techniques such as process injection, direct syscalls, ETW evasion and API hooking. Each folder contains small, self-contained examples and helper libraries that illustrate a single idea or primitive : the intention is practical reference code that’s easy to reuse or adapt for research and testing.

## Repository structure

- `evasion/`
  - `etw/`: Event Tracing for Windows (ETW) hijacking / evasion techniques

- `hooking/`
  - `hwbp/`: Hardware Breakpoints (HWBP) implementation with helpers to create detours
  - `trampoline/`: Patch functions at assembly level to redirect execution flow

- `injections/`
  - `apc/`: Early Bird APC (Asynchronous Procedure Call) injection using debug permissions

- `syscalls/`
  - `hells_gate/`: Direct syscall invocation techniques (Hell’s Gate style)

- `utils/`
  - `hashing/`: Custom hashing implementations for obfuscation
  - `winapi/`: Custom Windows structures and utility functions

I plan to keep adding libraries and folders over time as new techniques, crates and approaches appear, so expect this structure to expand.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/N10h0ggr/maldev-rs.git
   cd maldev-rs
   ```

2. Pick a sample or library, for example:

   ```bash
   cd evasion/etw
   ```

3. Build with Cargo:

   ```bash
   cargo build --release
   ```

4. The resulting `.rlib` or binaries will be under `target/` (for example `target/release/`).


