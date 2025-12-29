use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;

use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
    IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

/// Enumeration of supported Processor Architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArch {
    X86,
    X64,
}

/// A container for NT Headers that abstracts over 32-bit and 64-bit variants.
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
    /// Returns a reference to the common File Header.
    pub fn file_header(&self) -> &IMAGE_FILE_HEADER {
        match self {
            NtHeaders::Nt32 { file, .. } | NtHeaders::Nt64 { file, .. } => file,
        }
    }

    /// Returns the Relative Virtual Address (RVA) of the entry point.
    pub fn entry_point_rva(&self) -> u32 {
        match self {
            NtHeaders::Nt32 { optional, .. } => optional.AddressOfEntryPoint,
            NtHeaders::Nt64 { optional, .. } => optional.AddressOfEntryPoint,
        }
    }

    /// Returns the preferred base address of the image.
    pub fn image_base(&self) -> u64 {
        match self {
            NtHeaders::Nt32 { optional, .. } => optional.ImageBase as u64,
            NtHeaders::Nt64 { optional, .. } => optional.ImageBase,
        }
    }

    /// Retrieves a specific Data Directory entry by index.
    pub fn data_directory(&self, index: usize) -> IMAGE_DATA_DIRECTORY {
        match self {
            NtHeaders::Nt32 { optional, .. } => optional.DataDirectory[index],
            NtHeaders::Nt64 { optional, .. } => optional.DataDirectory[index],
        }
    }

    /// Returns the total size of the image in memory (aligned).
    pub fn size_of_image(&self) -> u32 {
        match self {
            NtHeaders::Nt32 { optional, .. } => optional.SizeOfImage,
            NtHeaders::Nt64 { optional, .. } => optional.SizeOfImage,
        }
    }
}

/// A parsed view into a Portable Executable image.
#[derive(Clone)]
pub struct PeImage<'a> {
    buffer: &'a [u8],
    section_headers_offset: usize,
    nt_headers: NtHeaders,
    is_dll: bool,
}

impl<'a> PeImage<'a> {
    /// Parses a PE image from a byte slice.
    ///
    /// # Errors
    /// Returns `Err(())` if the buffer is too small or contains an invalid PE signature.
    pub fn parse_slice(buffer: &'a [u8]) -> Result<Self, ()> {
        // 1. Verify DOS Header ("MZ")
        let dos: IMAGE_DOS_HEADER = read_struct(buffer, 0)?;
        if dos.e_magic != 0x5A4D {
            return Err(());
        }

        // 2. Verify NT Signature ("PE\0\0")
        let nt_offset = dos.e_lfanew as usize;
        let signature = read_u32_le(buffer, nt_offset)?;
        if signature != 0x00004550 {
            return Err(());
        }

        // 3. Read File Header
        let file_header_offset = nt_offset + 4;
        let file: IMAGE_FILE_HEADER = read_struct(buffer, file_header_offset)?;

        // 4. Determine Magic and parse Optional Header
        let optional_offset = file_header_offset + size_of::<IMAGE_FILE_HEADER>();
        let magic = read_u16_le(buffer, optional_offset)?;
        let section_headers_offset = optional_offset + file.SizeOfOptionalHeader as usize;

        let nt_headers = match magic {
            0x010B => { // PE32
                if (file.SizeOfOptionalHeader as usize) < size_of::<IMAGE_OPTIONAL_HEADER32>() {
                    return Err(());
                }
                let optional: IMAGE_OPTIONAL_HEADER32 = read_struct(buffer, optional_offset)?;
                NtHeaders::Nt32 { file, optional }
            }
            0x020B => { // PE32+ (64-bit)
                if (file.SizeOfOptionalHeader as usize) < size_of::<IMAGE_OPTIONAL_HEADER64>() {
                    return Err(());
                }
                let optional: IMAGE_OPTIONAL_HEADER64 = read_struct(buffer, optional_offset)?;
                NtHeaders::Nt64 { file, optional }
            }
            _ => return Err(()),
        };

        // 5. Validate Section Table Range
        let section_count = nt_headers.file_header().NumberOfSections as usize;
        let table_size = section_count * size_of::<IMAGE_SECTION_HEADER>();
        require_range(buffer, section_headers_offset, table_size)?;

        // 0x2000 corresponds to IMAGE_FILE_DLL
        let is_dll = (nt_headers.file_header().Characteristics & 0x2000) != 0;

        Ok(Self {
            buffer,
            section_headers_offset,
            nt_headers,
            is_dll,
        })
    }

    /// Parses a PE image from a raw pointer in memory.
    ///
    /// # Safety
    /// The caller must ensure `base_ptr` points to a valid, mapped PE image.
    pub unsafe fn parse_from_ptr(base_ptr: *const c_void) -> Result<Self, ()> {
        if base_ptr.is_null() {
            return Err(());
        }

        let dos_ptr = base_ptr as *const IMAGE_DOS_HEADER;
        if (*dos_ptr).e_magic != 0x5A4D {
            return Err(());
        }

        let nt_offset = (*dos_ptr).e_lfanew as usize;
        let nt_ptr = (base_ptr as usize + nt_offset) as *const u32;
        if *nt_ptr != 0x00004550 {
            return Err(());
        }

        // Identify size of image to create a safe slice
        let opt_hdr_ptr = (base_ptr as usize + nt_offset + 4 + size_of::<IMAGE_FILE_HEADER>()) as *const u16;
        let size_of_image = match *opt_hdr_ptr {
            0x010B => (*(opt_hdr_ptr as *const IMAGE_OPTIONAL_HEADER32)).SizeOfImage,
            0x020B => (*(opt_hdr_ptr as *const IMAGE_OPTIONAL_HEADER64)).SizeOfImage,
            _ => return Err(()),
        } as usize;

        let buffer = core::slice::from_raw_parts(base_ptr as *const u8, size_of_image);
        Self::parse_slice(buffer)
    }

    pub fn arch(&self) -> PeArch {
        match self.nt_headers {
            NtHeaders::Nt32 { .. } => PeArch::X86,
            NtHeaders::Nt64 { .. } => PeArch::X64,
        }
    }

    pub fn nt_headers(&self) -> &NtHeaders { &self.nt_headers }

    pub fn image_base(&self) -> u64 { self.nt_headers.image_base() }

    pub fn import_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT as usize)
    }

    pub fn reloc_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC as usize)
    }

    pub fn tls_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers.data_directory(IMAGE_DIRECTORY_ENTRY_TLS as usize)
    }

    pub fn export_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT as usize)
    }

    pub fn exception_directory(&self) -> IMAGE_DATA_DIRECTORY {
        self.nt_headers.data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize)
    }

    pub fn section_header(&self, index: usize) -> Option<IMAGE_SECTION_HEADER> {
        let count = self.nt_headers.file_header().NumberOfSections as usize;
        if index >= count {
            return None;
        }

        let offset = self.section_headers_offset + index * size_of::<IMAGE_SECTION_HEADER>();
        read_struct(self.buffer, offset).ok()
    }

    pub fn size_of_image(&self) -> u32 { self.nt_headers.size_of_image() }

    pub fn is_dll(&self) -> bool { self.is_dll }

    pub fn as_bytes(&self) -> &[u8] { self.buffer }
}

// --- Internal Utilities ---

#[inline(always)]
fn require_range(buf: &[u8], offset: usize, len: usize) -> Result<(), ()> {
    offset.checked_add(len)
        .filter(|&end| end <= buf.len())
        .map(|_| ())
        .ok_or(())
}

fn read_struct<T: Copy>(buf: &[u8], offset: usize) -> Result<T, ()> {
    require_range(buf, offset, size_of::<T>())?;
    unsafe {
        let ptr = buf.as_ptr().add(offset) as *const T;
        Ok(ptr::read_unaligned(ptr))
    }
}

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, ()> {
    require_range(buf, offset, 2)?;
    let bytes = [buf[offset], buf[offset + 1]];
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, ()> {
    require_range(buf, offset, 4)?;
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    Ok(u32::from_le_bytes(bytes))
}