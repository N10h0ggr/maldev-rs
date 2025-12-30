#![no_std]

pub mod algorithms;
pub mod error;
pub mod platform;
pub mod utils;

/// Internal module to hide the implementation details from the user.
/// These must be public for the macro to access them, but marked as doc(hidden).
#[doc(hidden)]
pub mod __private {
    pub use crate::algorithms::get_default_hash;
    pub use crate::error::ResolveError;
    pub use crate::platform::resolve_symbol;
    pub use core::mem::transmute;
}

/// The single entry point to the library.
///
/// Usage:
/// let func: MyFuncType = resolve_api!("dll_name", "function_name", MyFuncType)?;
#[macro_export]
macro_rules! resolve_api {
    ($dll:literal, $func:literal, $type:ty) => {
        unsafe {
            let mut dll_arr = [0u8; $dll.len() + 1];
            let mut func_arr = [0u8; $func.len() + 1];

            let dll_bytes = $dll.as_bytes();
            let func_bytes = $func.as_bytes();

            let mut i = 0;
            while i < dll_bytes.len() {
                dll_arr[i] = dll_bytes[i];
                i += 1;
            }

            let mut j = 0;
            while j < func_bytes.len() {
                func_arr[j] = func_bytes[j];
                j += 1;
            }

            let func_hash = $crate::__private::get_default_hash(&func_arr[..$func.len()]);

            $crate::__private::resolve_symbol(&dll_arr[..$dll.len()], func_hash)
                .map(|ptr| $crate::__private::transmute::<*const (), $type>(ptr))
        }
    };
}
