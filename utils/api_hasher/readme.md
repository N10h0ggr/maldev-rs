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

Using the default **DJB2** hash to resolve a function:

```rust
use api_hasher::resolve_api;

type GetLastErrorFn = unsafe extern "system" fn() -> u32;

let get_last_error = unsafe {
    resolve_api!("kernel32.dll", "GetLastError", GetLastErrorFn)
        .expect("Failed to resolve GetLastError")
};

let err = unsafe { get_last_error() };

```

### Selecting an Algorithm

Algorithms are toggled via Cargo features. Disable default features to switch algorithms:

```toml
[dependencies]
api_hasher = { version = "0.1", default-features = false, features = ["hash-fnv1a"] }
```

### Custom Hashing

For full control over hashing behavior, the crate exposes a hash-custom feature. This is intended for cases where you need to exactly replicate an existing hashing scheme, for example when porting a loader from another language or matching hashes generated offline.

First, enable the feature and disable defaults:
```toml
[dependencies]
api_hasher = { version = "*", default-features = false, features = ["hash-custom"] }
```

With this feature enabled, the crate expects you to provide the hashing logic. A minimal example, adapted from the test implementation, looks like this:

```rust
use api_hasher::hash::custom::custom_hash;


// Example custom hash (simple rotate-xor scheme)
pub const fn custom_hash(name: &str) -> u32 {
    let bytes = name.as_bytes();
    let mut hash: u32 = 0;
    let mut i = 0;
    
    while i < bytes.len() {
        hash = hash.rotate_left(5) ^ bytes[i] as u32;
        i += 1;
    }
    
    hash
}
```
As long as the same function is used consistently for both hash generation and API resolution, the rest of the crate operates identically. No changes to the resolver or macro usage are required.

## Architecture & Platform Support

* **Windows Only:** Currently supports `x86` and `x86_64` architectures.
* **Platform Isolation:** All architecture-specific assembly and PEB traversal logic is isolated in `src/platform/`, making the public API clean and portable across Windows versions.
* **Lazy Initialization:** For users wishing to cache pointers, see `api_table.rs` in the repository for a reference implementation of a lazily-loaded global API table.
