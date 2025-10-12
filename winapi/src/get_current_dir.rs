use crate::get_peb;
use crate::structs::RtlUserProcessParameters;

/// Retrieves the current process directory as a `String`.
///
/// # Returns
/// * `Ok(String)` - if the current directory is successfully retrieved.
/// * `Err(String)` - if the directory cannot be accessed or decoded.
///
/// # Safety
/// This function interacts with low-level Windows structures (PEB and
/// `RtlUserProcessParameters`), and therefore uses `unsafe` code blocks.
/// It should only be used in contexts where these structures are known to be valid.
pub fn get_current_dir() -> Result<String, String> {
    let peb = get_peb().ok_or_else(|| "Failed to obtain PEB".to_string())?;

    if peb.ProcessParameters.is_null() {
        return Err("ProcessParameters pointer is null".to_string());
    }

    // SAFETY: We ensure ProcessParameters is not null before dereferencing
    let process_parameters =
        unsafe { &*(peb.ProcessParameters as *const RtlUserProcessParameters) };

    // SAFETY: The Buffer may be null; we check before dereferencing
    let buffer_ptr = process_parameters.current_directory.dos_path.Buffer;
    if buffer_ptr.is_null() {
        return Err("Current directory buffer is null".to_string());
    }

    let length = process_parameters.current_directory.dos_path.Length as usize / 2; // UTF-16 characters
    let slice = unsafe { std::slice::from_raw_parts(buffer_ptr, length) };

    let current_dir = String::from_utf16(slice)
        .map_err(|_| "Error decoding the current directory (invalid UTF-16)".to_string())?;

    Ok(current_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_dir_safety() {
        let result = get_current_dir();

        match result {
            Ok(dir) => {
                println!("Current directory: {}", dir);
                assert!(!dir.is_empty(), "Directory string should not be empty");
            }
            Err(err) => {
                eprintln!("Function returned an error: {}", err);
            }
        }
    }
}
