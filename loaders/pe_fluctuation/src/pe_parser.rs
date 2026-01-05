use std::mem::size_of;
use std::ptr;


use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
    IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

use crate::errors::PeError;
use crate::errors::PeArch;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"

const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

const IMAGE_FILE_DLL: u16 = 0x2000;

/// Parsed NT headers (PE32 vs PE32+).
#[derive(Clone)]
pub enum NtHeaders {
    Nt32 {
        file: IMAGE_FILE_HEADER,
        optional: IMAGE_OPTIONAL_HEADER32,
    },
    Nt64 {
        file: IMAGE_FILE_HEADER,
        optional: IMAGE_OPTIONAL_HEADER64,
    },
}

impl NtHeaders {
    /// Returns a reference to the COFF file header.
    pub fn file_header(&self) -> &IMAGE_FILE_HEADER {
        match self {
            NtHeaders::Nt32 { file, .. } | NtHeaders::Nt64 { file, .. } => file,
        }
    }

    /// Returns the RVA of the image entry point.
    pub fn entry_point_rva(&self) -> u32 {
        match self {
            NtHeaders::Nt32 { optional, .. } => optional.AddressOfEntryPoint,
            NtHeaders::Nt64 { optional, .. } => optional.AddressOfEntryPoint,
        }
    }

    /// Returns the preferred image base.
    pub fn image_base(&self) -> u64 {
        match self {
            NtHeaders::Nt32 { optional, .. } => optional.ImageBase as u64,
            NtHeaders::Nt64 { optional, .. } => optional.ImageBase,
        }
    }

    /// Returns a copy of the requested data directory entry.
    ///
    /// The PE optional header stores a fixed-size array of directories.
    /// Returning a copy is cheap and avoids lifetime issues.
    pub fn data_directory(&self, index: usize) -> IMAGE_DATA_DIRECTORY {
        match self {
            NtHeaders::Nt32 { optional, .. } => optional.DataDirectory[index],
            NtHeaders::Nt64 { optional, .. } => optional.DataDirectory[index],
        }
    }
}

/// Parsed Portable Executable (PE) backed by the original file bytes.
///
/// # Safety model
///
/// PE structures stored on disk are not guaranteed to be aligned according
/// to Rust's alignment rules. All structured reads therefore use
/// `read_unaligned` and are bounds-checked before loading.
#[derive(Clone)]
pub struct PeImage {
    buffer: Vec<u8>,
    section_headers_offset: usize,
    nt_headers: NtHeaders,
    is_dll: bool,
}

impl PeImage {
    /// Parses a PE image from raw file bytes.
    pub fn parse(buffer: Vec<u8>) -> Result<Self, PeError> {
        // DOS header is always at offset 0.
        let dos: IMAGE_DOS_HEADER = read_struct(&buffer, 0)?;

        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosSignature);
        }

        // e_lfanew points to the NT headers ("PE\0\0").
        let nt_offset = dos.e_lfanew as usize;

        let signature = read_u32_le(&buffer, nt_offset)?;
        if signature != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidNtSignature);
        }

        // IMAGE_FILE_HEADER follows the signature.
        let file_header_offset = nt_offset + size_of::<u32>();
        let file: IMAGE_FILE_HEADER = read_struct(&buffer, file_header_offset)?;

        // Optional header follows the file header.
        let optional_offset = file_header_offset + size_of::<IMAGE_FILE_HEADER>();
        let magic = read_u16_le(&buffer, optional_offset)?;

        // Section table begins after the optional header as sized by the file header.
        let section_headers_offset =
            optional_offset + file.SizeOfOptionalHeader as usize;

        let nt_headers = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                if (file.SizeOfOptionalHeader as usize)
                    < size_of::<IMAGE_OPTIONAL_HEADER32>()
                {
                    return Err(PeError::OutOfBounds);
                }

                let optional: IMAGE_OPTIONAL_HEADER32 =
                    read_struct(&buffer, optional_offset)?;

                NtHeaders::Nt32 { file, optional }
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                if (file.SizeOfOptionalHeader as usize)
                    < size_of::<IMAGE_OPTIONAL_HEADER64>()
                {
                    return Err(PeError::OutOfBounds);
                }

                let optional: IMAGE_OPTIONAL_HEADER64 =
                    read_struct(&buffer, optional_offset)?;

                NtHeaders::Nt64 { file, optional }
            }
            _ => return Err(PeError::UnsupportedArch),
        };

        // Validate that the section header table fits within the buffer.
        let section_count = nt_headers.file_header().NumberOfSections as usize;
        let table_size = section_count * size_of::<IMAGE_SECTION_HEADER>();
        require_range(&buffer, section_headers_offset, table_size)?;

        let is_dll =
            (nt_headers.file_header().Characteristics & IMAGE_FILE_DLL) != 0;

        Ok(Self {
            buffer,
            section_headers_offset,
            nt_headers,
            is_dll,
        })
    }

    /// Returns the architecture of this PE image.
    ///
    /// This reflects the *on-disk* architecture (PE32 vs PE32+),
    /// not the host process architecture.
    pub fn arch(&self) -> PeArch {
        match self.nt_headers {
            NtHeaders::Nt32 { .. } => PeArch::X86,
            NtHeaders::Nt64 { .. } => PeArch::X64,
        }
    }

    /// Returns a reference to the parsed NT headers.
    pub fn nt_headers(&self) -> &NtHeaders {
        &self.nt_headers
    }

    /// Returns the preferred image base.
    pub fn image_base(&self) -> u64 {
        self.nt_headers.image_base()
    }

    /// Returns the import directory entry.
    pub fn import_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers
            .data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT as usize)
    }

    /// Returns the base relocation directory entry.
    pub fn reloc_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers
            .data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC as usize)
    }

    /// Returns the TLS directory entry.
    pub fn tls_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers
            .data_directory(IMAGE_DIRECTORY_ENTRY_TLS as usize)
    }

    /// Returns the export directory entry.
    pub fn export_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers
            .data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT as usize)
    }

    /// Returns the exception directory entry.
    pub fn exception_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers
            .data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize)
    }

    /// Returns the section header at the given index (0-based).
    pub fn section_header(&self, index: usize) -> Option<IMAGE_SECTION_HEADER> {
        let count = self.nt_headers.file_header().NumberOfSections as usize;
        if index >= count {
            return None;
        }

        let offset =
            self.section_headers_offset + index * size_of::<IMAGE_SECTION_HEADER>();

        read_struct(&self.buffer, offset).ok()
    }

    /// Returns `true` if this image is a DLL.
    pub fn is_dll(&self) -> bool {
        self.is_dll
    }

    /// Returns a reference to the raw file bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

/// Ensures that `[offset, offset + len)` is within `buf`.
fn require_range(buf: &[u8], offset: usize, len: usize) -> Result<(), PeError> {
    offset
        .checked_add(len)
        .filter(|&end| end <= buf.len())
        .map(|_| ())
        .ok_or(PeError::OutOfBounds)
}

/// Reads a C struct from the buffer at the given offset using an unaligned load.
///
/// # Safety rationale
///
/// PE structures in files are not guaranteed to be aligned. Using
/// `read_unaligned` avoids undefined behavior while still allowing efficient
/// parsing of on-disk structures.
fn read_struct<T: Copy>(buf: &[u8], offset: usize) -> Result<T, PeError> {
    require_range(buf, offset, size_of::<T>())?;

    let ptr = unsafe { buf.as_ptr().add(offset) as *const T };
    Ok(unsafe { ptr::read_unaligned(ptr) })
}

/// Reads a little-endian `u16` from the buffer.
fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, PeError> {
    require_range(buf, offset, 2)?;
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

/// Reads a little-endian `u32` from the buffer.
fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, PeError> {
    require_range(buf, offset, 4)?;
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}
