use crate::get_peb;
use crate::structs::RtlUserProcessParameters;

/// Searches for an environment variable by name within a vector of `KEY=VALUE` strings.
///
/// The comparison is **case-insensitive**, matching Windows behavior.
///
/// # Arguments
/// * `vars` - Slice of environment entries such as `"PATH=C:\\Windows"`.
/// * `key` - The name of the variable to search for (e.g. `"PATH"`).
///
/// # Returns
/// `Some(String)` containing the variable’s value if found, or `None` if absent.
pub fn get_env_value(vars: &[String], key: &str) -> Option<String> {
    let key_upper = key.to_ascii_uppercase();
    vars.iter().find_map(|v| {
        let mut parts = v.splitn(2, '=');
        let name = parts.next()?.to_ascii_uppercase();
        if name == key_upper {
            parts.next().map(|val| val.to_string())
        } else {
            None
        }
    })
}

/// Returns the temporary directory path (`TMP` or `TEMP`) from the process environment.
///
/// # Returns
/// * `Ok(String)` - the temporary directory path.
/// * `Err(String)` - if neither `TMP` nor `TEMP` is present.
pub fn get_tmp_path() -> Result<String, String> {
    let vars = get_all_env_values()?;
    get_env_value(&vars, "TMP")
        .or_else(|| get_env_value(&vars, "TEMP"))
        .ok_or_else(|| "TMP/TEMP not found".to_string())
}

/// Returns the `APPDATA` directory path for the current user.
///
/// # Returns
/// * `Ok(String)` containing the AppData path.
/// * `Err(String)` if `APPDATA` is not set.
pub fn get_appdata_path() -> Result<String, String> {
    let vars = get_all_env_values()?;
    get_env_value(&vars, "APPDATA").ok_or_else(|| "APPDATA not found".to_string())
}

/// Returns the Windows directory path (`WINDIR`) from the environment.
///
/// # Returns
/// * `Ok(String)` containing the Windows installation directory.
/// * `Err(String)` if `WINDIR` is not set.
pub fn get_win_dir_path() -> Result<String, String> {
    let vars = get_all_env_values()?;
    get_env_value(&vars, "WINDIR").ok_or_else(|| "WINDIR not found".to_string())
}

/// Returns the number of logical processors reported by the environment variable
/// `NUMBER_OF_PROCESSORS`.
///
/// # Returns
/// * `Ok(u32)` containing the processor count.
/// * `Err(String)` if the variable is missing or cannot be parsed as an integer.
pub fn get_number_of_processors() -> Result<u32, String> {
    let vars = get_all_env_values()?;
    let val = get_env_value(&vars, "NUMBER_OF_PROCESSORS")
        .ok_or_else(|| "NUMBER_OF_PROCESSORS not found".to_string())?;
    val.parse::<u32>()
        .map_err(|_| "NUMBER_OF_PROCESSORS is not a valid integer".to_string())
}

/// Reads the current process's environment block directly from the PEB and returns
/// all variables as UTF-8 `KEY=VALUE` strings.
///
/// # Safety
/// This function dereferences raw pointers obtained from the Windows PEB and
/// performs manual UTF-16 to UTF-8 conversion. It must only be called on Windows.
///
/// # Returns
/// * `Ok(Vec<String>)` - list of all environment variables.
/// * `Err(String)` - if the PEB or its `ProcessParameters` field is null.
pub fn get_all_env_values() -> Result<Vec<String>, String> {
    let mut option_peb = get_peb();
    let peb = option_peb
        .take()
        .ok_or_else(|| "Failed to get PEB structure".to_string())?;

    // Transform the pointer to our structure without reserved fields

    let p_rtl_user_process_parameters: &RtlUserProcessParameters =
        if !peb.ProcessParameters.is_null() {
            unsafe { &*(peb.ProcessParameters as *mut RtlUserProcessParameters) }
        } else {
            return Err("ProcessParameters atribute in PEB is null".to_string());
        };

    // Get the "Environment" pointer in "RTL_USER_PROCESS_PARAMETERS" structure
    // and cast to *mut u16 (UTF-16 characters)
    let mut env_cursor = p_rtl_user_process_parameters.environment as *mut u16;
    let mut v_env_variables = vec![];
    loop {
        // Check for double null terminator indicating end of the block
        if unsafe { *env_cursor } == 0 {
            break;
        }
        // Find the length of the string
        let mut len = 0;
        unsafe {
            while *env_cursor.add(len) != 0 {
                len += 1;
            }
        };
        // Convert the UTF-16 slice to a Rust string
        let wide_slice = unsafe { std::slice::from_raw_parts(env_cursor, len) };
        let var = String::from_utf16_lossy(wide_slice);
        v_env_variables.push(var);

        // Advance the saved string + terminator
        env_cursor = unsafe { env_cursor.add(len + 1) };
    }

    Ok(v_env_variables)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    // cargo test test_get_all_env_values_real -- --nocapture
    #[test]
    fn test_get_all_env_values_real() {
        // Run the function — it should succeed on Windows.
        let result = get_all_env_values();
        assert!(result.is_ok(), "get_all_env_values() returned an error");
        let vars = result.unwrap();

        for var in &vars {
            println!("{}", var);
        }

        // The Windows environment should always have at least PATH, SystemRoot, etc.
        assert!(!vars.is_empty(), "Environment variable list is empty");
        assert!(
            vars.iter().any(|v| v.to_uppercase().starts_with("PATH=")),
            "PATH variable not found in environment list"
        );
    }

    #[test]
    fn test_get_env_value_helper() {
        let vars = vec![
            "Path=C:\\Windows\\System32".to_string(),
            "TEMP=C:\\Temp".to_string(),
        ];

        assert_eq!(
            get_env_value(&vars, "PATH"),
            Some("C:\\Windows\\System32".to_string())
        );

        // Missing key
        assert_eq!(get_env_value(&vars, "NOT_EXIST"), None);

        // Verify TEMP lookup
        assert_eq!(get_env_value(&vars, "temp"), Some("C:\\Temp".to_string()));
    }
}
