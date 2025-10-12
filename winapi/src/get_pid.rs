use std::arch::asm;

/// Returns the current process identifier (PID).
///
/// Reads the PID from the Thread Environment Block (TEB) without calling
/// any Windows API functions.
///
/// # Safety
/// Uses inline assembly to access architecture-specific TEB offsets.
/// The offsets are stable but not documented by Microsoft.
#[cfg(target_arch = "x86_64")]
pub fn get_pid() -> u32 {
    let pid: u32;
    unsafe { asm!("mov {0:e}, gs:[0x40]", out(reg) pid) };
    pid
}

#[cfg(target_arch = "x86")]
pub fn get_pid() -> u32 {
    let pid: u32;
    unsafe { asm!("mov {0:e}, fs:[0x20]", out(reg) pid) };
    pid
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensures that `get_pid()` runs without crashing and returns a valid process ID.
    #[test]
    #[cfg(windows)]
    fn test_get_pid_sanity() {
        let pid = get_pid();
        assert_ne!(pid, 0, "PID should never be zero");
        println!("Current PID: {}", pid);
    }
}


