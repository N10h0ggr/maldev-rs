# api_hasher

`api_hasher` is a lightweight, `no_std` compatible Rust crate designed for dynamic Windows API resolution using compile-time hashing.

The main goal is to avoid static imports and cleartext API names, which is useful in low-level tooling such as loaders, shellcode, and research-oriented payloads.

## Core Features

* **`no_std` Support:** Operates without the Rust standard library, ideal for shellcode or embedded environments.
* **Dynamic Resolution:** Manually parses the Process Environment Block (PEB) and Export Address Table (EAT) to resolve symbols at runtime.
* **Compile-Time Hashing:** Supports multiple algorithms via Cargo features to eliminate runtime overhead.
* **Zero-Cost Abstraction:** Use of macros ensures that resolution logic is direct and casts function pointers to their correct signatures efficiently.

## How It Works

The crate bypasses the standard Windows Loader by performing the following steps:

1. **Module Enumeration:** Accesses the PEB to find the base address of loaded DLLs.
2. **Name Hashing:** Computes the hash of exported function names within the target DLL.
3. **Symbol Matching:** Compares these hashes against your precomputed target hash.
4. **Pointer Retrieval:** Returns the memory address of the function, which is then cast to the user-defined function signature.


## Usage

### Basic Implementation

The `resolve_api!` macro is the recommended way to use this crate. It ensures that string literals are processed at compile-time and never reach the final binary.

```rust
use api_hasher::resolve_api;

// Define the function signature
type GetLastErrorFn = unsafe extern "system" fn() -> u32;

let get_last_error = unsafe {
    // Both strings are hashed at compile-time
    // only u32 constants remain in the binary
    resolve_api!("kernel32.dll", "GetLastError", GetLastErrorFn)
        .expect("Failed to resolve GetLastError")
};

let err = unsafe { get_last_error() };

```

### Manual Resolution (Literal Hashes)

If you prefer to use pre-calculated hashes (e.g., generated from an external tool) to avoid using the macro, you can call `resolve_symbol` directly.

```rust
use api_hasher::resolve_symbol;

// Pre-calculated DJB2 hashes for "kernel32.dll" and "GetTickCount"
const KERNEL32_HASH: u32 = 0x70b46e14;
const GETTICKCOUNT_HASH: u32 = 0x5fb27c52;

type GetTickCountFn = unsafe extern "system" fn() -> u32;

let ptr = resolve_symbol(KERNEL32_HASH, GETTICKCOUNT_HASH).expect("Symbol not found");
let get_tick_count: GetTickCountFn = unsafe { core::mem::transmute(ptr) };

```

### Selecting an Algorithm

Algorithms are toggled via Cargo features. All supported algorithms use **internal case-folding**, meaning `"KERNEL32.DLL"` and `"kernel32.dll"` will produce the same hash.

```toml
# Use FNV1a instead of the default DJB2
[dependencies]
api_hasher = { version = "0.1", default-features = false, features = ["hash-fnv1a"] }

```

To ensure users understand the importance of case normalization, we should update the documentation to emphasize that while the Windows Export Table is technically case-sensitive for function names, the **Process Environment Block (PEB)** is effectively case-insensitive for DLL names.

Here is the updated documentation section for **Custom Hashing**.

---

### Custom Hashing

To use a custom algorithm, enable the `hash-custom` feature.

> **Important:** Your custom function must be a `const fn` to support the `resolve_api!` macro. This allows the compiler to execute your hashing logic at build-time.

```toml
[dependencies]
api_hasher = { version = "0.1", default-features = false, features = ["hash-custom"] }

```

#### Implementing Case Normalization

When implementing a custom hash, you must decide how to handle character casing. In this crate, **case-folding (normalization) is highly recommended** for the following reasons:

1. **DLL Resolution:** Windows module names in the PEB are often stored in uppercase (e.g., `KERNEL32.DLL`). If your hash is generated from a lowercase literal without normalization, the resolution will fail.
2. **Signature Evasion:** Using a custom normalization scheme (or none at all) changes the resulting `u32` constant, helping to evade static signatures that look for well-known hashes of common APIs.

You must provide a `const fn` named `custom_hash` in your crate root:

```rust
/// Custom hashing implementation.
/// 
/// # Case Sensitivity Note:
/// We normalize 'A-Z' to 'a-z' here to ensure that "kernel32.dll" 
/// matches "KERNEL32.DLL" as found in the Windows PEB.
#[no_mangle]
pub const fn custom_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    let mut i = 0;
    
    while i < data.len() {
        // Perform manual lowercase normalization
        let b = if data[i] >= b'A' && data[i] <= b'Z' { 
            data[i] + 32 
        } else { 
            data[i] 
        };
        
        // Example algorithm: Rotate Left + XOR
        hash = hash.rotate_left(5) ^ (b as u32);
        i += 1;
    }
    hash
}
```

#### Why `const fn`?

By marking your function as `const fn`, the Rust compiler can run this logic during the compilation of your project. This is the mechanism that allows `api_hasher` to replace your strings with numbers, completely removing the plaintext API names from your binary's data sections.


## Architecture & Platform Support

* **Windows Only:** Currently supports `x86` and `x86_64` architectures.
* **Platform Isolation:** All architecture-specific assembly and PEB traversal logic is isolated in `src/platform/`, making the public API clean and portable across Windows versions.
* **Lazy Initialization:** For users wishing to cache pointers, see `api_table.rs` in the repository for a reference implementation of a lazily-loaded global API table.
