use crate::errors::DrmError;
use log::{debug, error};
use std::ffi::OsStr;
use std::os::windows::prelude::OsStrExt;

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO, FILE_RENAME_INFO, FILE_SHARE_READ, FileDispositionInfo, FileRenameInfo, GetFileSize, OPEN_EXISTING, ReadFile, SYNCHRONIZE, SetFileInformationByHandle, WriteFile, INVALID_FILE_SIZE};

/// PE image file utility for reading and deleting files
pub struct PeImage {
    pub file_path: String,
}

impl PeImage {
    /// Convert UTF-8 Rust string to UTF-16 for Win32 APIs
    fn to_wide(path: &str) -> Vec<u16> {
        OsStr::new(path)
            .encode_wide()
            .chain(Some(0)) // null terminate
            .collect()
    }

    /// Reads the PE image from disk into a Vec<u8>.
    /// Returns (buffer, file_size)
    pub fn read_self_from_disk(&self) -> Result<(Vec<u8>, u32), DrmError> {
        let wide_path = Self::to_wide(&self.file_path);
        debug!("Opening file: {}", self.file_path);

        unsafe {
            let file_handle = CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );

            if file_handle == INVALID_HANDLE_VALUE {
                let err = GetLastError();
                error!("CreateFileW failed for {}: {}", self.file_path, err);
                return Err(DrmError::WinApi(err));
            }

            let file_size = GetFileSize(file_handle, std::ptr::null_mut());
            if file_size == INVALID_FILE_SIZE {
                // Improper size or error occurred
                let err = GetLastError();
                error!("GetFileSize failed: {}", err);
                CloseHandle(file_handle);
                return Err(DrmError::WinApi(err));
            }

            debug!("File size: {} bytes", file_size);

            let mut file_buffer = vec![0u8; file_size as usize];
            let mut bytes_read: u32 = 0;

            let read_success = ReadFile(
                file_handle,
                file_buffer.as_mut_ptr() as _,
                file_size,
                &mut bytes_read,
                std::ptr::null_mut(),
            );

            CloseHandle(file_handle);

            if read_success == 0 || bytes_read != file_size {
                let err = GetLastError();
                error!(
                    "ReadFile failed: read {} out of {} bytes, err={}",
                    bytes_read, file_size, err
                );
                return Err(DrmError::WinApi(err));
            }

            debug!("Successfully read {} bytes", bytes_read);
            Ok((file_buffer, bytes_read))
        }
    }

    pub fn delete_self_from_disk(&self) -> Result<(), DrmError> {
        unsafe {
            let wide_path = Self::to_wide(&self.file_path);

            // Generate random ADS name similar to "%x%x"
            let rnd1 = rand::random::<u32>();
            let rnd2 = rand::random::<u32>().wrapping_mul(rand::random::<u32>());
            let ads = format!(":{:x}{:x}", rnd1, rnd2);
            let mut new_stream_wide = Self::to_wide(&ads);

            debug!("Renaming file to ADS: {}{}", self.file_path, ads);

            let mut rename_info: FILE_RENAME_INFO = std::mem::zeroed();
            rename_info.Anonymous.ReplaceIfExists = false;
            rename_info.RootDirectory = std::ptr::null_mut();
            rename_info.FileNameLength = (new_stream_wide.len() as u32 - 1) * 2; // length in bytes

            // Copy wide name into struct
            std::ptr::copy_nonoverlapping(
                new_stream_wide.as_mut_ptr(),
                rename_info.FileName.as_mut_ptr(),
                new_stream_wide.len(),
            );

            let mut disp_info = FILE_DISPOSITION_INFO { DeleteFile: true };

            // First: rename
            let file_r = CreateFileW(
                wide_path.as_ptr(),
                DELETE | SYNCHRONIZE,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            if file_r == INVALID_HANDLE_VALUE {
                let err = GetLastError();
                error!("CreateFileW for rename failed: {}", err);
                return Err(DrmError::WinApi(err));
            }

            let ok_rename = SetFileInformationByHandle(
                file_r,
                FileRenameInfo,
                &rename_info as *const _ as _,
                std::mem::size_of::<FILE_RENAME_INFO>() as u32,
            );

            CloseHandle(file_r);

            if ok_rename == 0 {
                let err = GetLastError();
                error!("SetFileInformationByHandle(rename) failed: {}", err);
                return Err(DrmError::WinApi(err));
            }

            debug!("File renamed into ADS successfully");

            // Second: disposition (actual delete)
            let file_d = CreateFileW(
                wide_path.as_ptr(),
                DELETE | SYNCHRONIZE,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            if file_d == INVALID_HANDLE_VALUE {
                let err = GetLastError();
                error!("CreateFileW for delete failed: {}", err);
                return Err(DrmError::WinApi(err));
            }

            let ok_disp = SetFileInformationByHandle(
                file_d,
                FileDispositionInfo,
                &mut disp_info as *mut _ as _,
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            );

            CloseHandle(file_d);

            if ok_disp == 0 {
                let err = GetLastError();
                error!("SetFileInformationByHandle(dispose) failed: {}", err);
                return Err(DrmError::WinApi(err));
            }

            debug!("File deletion scheduled successfully");
            Ok(())
        }
    }

    /// Writes current in-memory executable buffer to a NEW file on disk.
    /// Fails if file already exists.
    pub fn write_self_to_disk(&self, target_path: &str, image_base: &[u8]) -> Result<(), DrmError> {
        unsafe {
            let wide_path: Vec<u16> = OsStr::new(target_path)
                .encode_wide()
                .chain(Some(0))
                .collect();

            debug!(
                "Writing PE image to disk at {} ({} bytes)",
                target_path,
                image_base.len()
            );

            let file_handle = CreateFileW(
                wide_path.as_ptr(),
                GENERIC_WRITE,
                0,
                std::ptr::null(),
                CREATE_NEW, // match original: fail if exists
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );

            if file_handle == INVALID_HANDLE_VALUE {
                let err = GetLastError();
                error!("CreateFileW failed for {}: {}", target_path, err);
                return Err(DrmError::WinApi(err));
            }

            let mut bytes_written: u32 = 0;

            let ok = WriteFile(
                file_handle,
                image_base.as_ptr() as _,
                image_base.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            );

            CloseHandle(file_handle);

            if ok == 0 || bytes_written as usize != image_base.len() {
                let err = GetLastError();
                error!(
                    "WriteFile failed: wrote {} / {} bytes, err={}",
                    bytes_written,
                    image_base.len(),
                    err
                );
                return Err(DrmError::WinApi(err));
            }

            debug!("Successfully wrote {} bytes", bytes_written);
            Ok(())
        }
    }
}
