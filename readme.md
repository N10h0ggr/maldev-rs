# maldev-rs

maldev-rs is a collection of malware-development samples and reusable Rust libraries I build for research, learning and experimentation. The objective is to provide ready-to-use libraries you can drop into larger projects, learn from, and have fun with while exploring low-level Windows techniques in Rust.

I document code and techniques as clearly as I can. If something is unclear, check the README inside each library or the implementation, and feel free to ask.

## Project overview

This repo provides focused examples of low-level techniques such as process injection, direct syscalls, ETW evasion, and API hooking. Each folder contains small, self-contained examples and helper libraries that illustrate a single idea or primitive. The intention is practical reference code that’s easy to reuse or adapt for research and testing.


> **Warning:** These samples are potentially harmful since some of them are not widely tested and can be unstable. Do not compile or execute them on production systems without testing them beforehand.

### Repository structure

```
maldev-rs/
├── evasion/
│   └── etw/           # Event Tracing for Windows (ETW) hijacking / evasion techniques
├── hooking/
│   ├── hwbp/          # Hardware Breakpoints implementation and detour helpers
│   └── trampoline/    # Assembly-level function patching to redirect execution flow
├── injections/
│   └── apc/           # Early Bird APC injection using debug permissions
├── syscalls/
│   └── hells_gate/    # Direct syscall invocation techniques (Hell's Gate style)
└── utils/
    ├── hashing/       # Custom hashing implementations for obfuscation
    └── winapi/        # Custom Windows structures and utility functions
```

I plan to keep adding libraries and folders over time as new techniques, crates and approaches appear, so expect this structure to expand.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/N10h0ggr/maldev-rs.git
   cd maldev-rs
   ```

2. Pick a sample or library to build, for example:

   ```bash
   cd evasion/etw
   cargo build --release
   ```

3. To use any of the libraries in your own project, link them as a **path dependency** in your `Cargo.toml`.
   Example:

   ```toml
   [dependencies]
   hashing = { path = "../utils/hashing" }
   winapi_utils = { path = "../utils/winapi" }
   ```

   Then import and use them normally in your code:

   ```rust
   use hashing::hash_function;
   use winapi_utils::get_process_handle;
   ```

4. Build your project as usual:

   ```bash
   cargo build --release
   ```

This way Cargo handles compilation, linking, and dependency management automatically, while keeping IDE features like autocompletion and inline documentation fully functional.


## Contact

Feel free to reach out or open an Issue for bugs or feature requests.

- Twitter: [@NoelCarrasco16](https://x.com/NoelCarrasco16)
- Blog: [n10h0ggr.github.io](https://n10h0ggr.github.io/)


