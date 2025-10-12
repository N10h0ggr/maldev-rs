use crate::get_peb;
use crate::structs::RtlUserProcessParameters;

/// Retrieves the current process's command line as a UTF-8 [`String`].
///
/// This function reads the command line from the Windows Process Environment Block (PEB)
/// by accessing the [`RtlUserProcessParameters`] structure. It safely validates all pointers
/// before dereferencing them to avoid undefined behavior.
///
/// # Returns
///
/// - `Ok(String)` containing the process command line in UTF-8 format.
/// - `Err(String)` containing the error message 
///
pub fn get_cmd_line() -> Result<String, String> {
    let peb = get_peb().ok_or_else(|| "Failed to obtain PEB".to_string())?;

    if peb.ProcessParameters.is_null() {
        return Err("ProcessParameters pointer is null".to_string());
    }

    // SAFETY: We ensure ProcessParameters is not null before dereferencing
    let process_parameters =
        unsafe { &*(peb.ProcessParameters as *const RtlUserProcessParameters) };

    // SAFETY: The Buffer may be null; we check before dereferencing
    let buffer_ptr = process_parameters.command_line.Buffer;
    if buffer_ptr.is_null() {
        return Err("Command line buffer is null".to_string());
    }

    let length = process_parameters.current_directory.dos_path.Length as usize / 2; // UTF-16 characters
    let slice = unsafe { std::slice::from_raw_parts(buffer_ptr, length) };

    let command_line = String::from_utf16(slice)
        .map_err(|_| "Error decoding the command line (invalid UTF-16)".to_string())?;

    Ok(command_line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_command_line_safety() {
        let result = get_cmd_line();

        match result {
            Ok(command_line) => {
                println!("Current process command line: {}", command_line);
                assert!(!command_line.is_empty(), "Directory string should not be empty");
            }
            Err(err) => {
                eprintln!("Function returned an error: {}", err);
            }
        }
    }
}
