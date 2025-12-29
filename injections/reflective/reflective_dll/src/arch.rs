/// Native (host) architecture–specific PE definitions.
///
/// Everything in this module is selected at compile time via `cfg`,
/// so no runtime branching is involved.
pub mod native {
    #[cfg(target_pointer_width = "64")]
    mod imp {
        use windows_sys::Win32::System::SystemServices::{
            IMAGE_ORDINAL_FLAG64,
            IMAGE_REL_BASED_DIR64,
            IMAGE_TLS_DIRECTORY64,
        };
        use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

        pub type ThunkData = IMAGE_THUNK_DATA64;
        pub type TlsDirectory = IMAGE_TLS_DIRECTORY64;

        pub const ORDINAL_FLAG: u64 = IMAGE_ORDINAL_FLAG64;
        pub const RELOC_TYPE: u16 = IMAGE_REL_BASED_DIR64 as u16;
    }

    #[cfg(target_pointer_width = "32")]
    mod imp {
        use windows_sys::Win32::System::SystemServices::{
            IMAGE_ORDINAL_FLAG32,
            IMAGE_REL_BASED_HIGHLOW,
            IMAGE_TLS_DIRECTORY32,
        };
        use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;

        pub type ThunkData = IMAGE_THUNK_DATA32;
        pub type TlsDirectory = IMAGE_TLS_DIRECTORY32;

        pub const ORDINAL_FLAG: u32 = IMAGE_ORDINAL_FLAG32;
        pub const RELOC_TYPE: u16 = IMAGE_REL_BASED_HIGHLOW as u16;
    }

    pub use imp::*;
}
