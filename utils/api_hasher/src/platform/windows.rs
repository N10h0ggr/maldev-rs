use core::arch::asm;
use crate::error::ResolveError;
use crate::algorithms::get_default_hash;

pub fn resolve_symbol(dll_hash: u32, func_hash: u32) -> Result<*const (), ResolveError> {
    let module_base = get_module_base_by_hash(dll_hash)?;
    search_export_table(module_base, func_hash)
}

fn get_module_base_by_hash(dll_hash: u32) -> Result<*const u8, ResolveError> {
    unsafe {
        let peb: *const u8;
        #[cfg(target_arch = "x86_64")]
        asm!("mov {}, gs:[0x60]", out(reg) peb);
        #[cfg(target_arch = "x86")]
        asm!("mov {}, fs:[0x30]", out(reg) peb);

        #[cfg(target_arch = "x86_64")]
        let ldr = *(peb.add(0x18) as *const *const u8);
        #[cfg(target_arch = "x86")]
        let ldr = *(peb.add(0x0c) as *const *const u8);

        let list_head = ldr.add(if cfg!(target_arch = "x86_64") { 0x10 } else { 0x0c });
        let mut current_link = *(list_head as *const *const u8);

        while current_link != list_head && !current_link.is_null() {
            let base_addr = *(current_link.add(if cfg!(target_arch = "x86_64") { 0x30 } else { 0x18 }) as *const *const u8);
            let length_ptr = current_link.add(if cfg!(target_arch = "x86_64") { 0x58 } else { 0x24 }) as *const u16;
            let buffer_ptr = *(current_link.add(if cfg!(target_arch = "x86_64") { 0x60 } else { 0x28 }) as *const *const u16);

            if !buffer_ptr.is_null() {
                let length_chars = (*length_ptr as usize) / 2;
                // Hash the UTF-16 name and compare
                if crate::algorithms::hash_utf16(buffer_ptr, length_chars) == dll_hash {
                    return Ok(base_addr);
                }
            }
            current_link = *(current_link as *const *const u8);
        }
        Err(ResolveError::ModuleNotFound)
    }
}

fn search_export_table(base: *const u8, target_hash: u32) -> Result<*const (), ResolveError> {
    unsafe {
        let dos_header = base;
        let nt_headers = base.add(*(dos_header.add(0x3c) as *const u32) as usize);

        // DataDirectory[0] is Export Directory
        // Offset is OptionalHeader + 112 (x64) or + 96 (x86)
        #[cfg(target_arch = "x86_64")]
        let export_dir_rva_ptr = nt_headers.add(0x88) as *const u32;
        #[cfg(target_arch = "x86")]
        let export_dir_rva_ptr = nt_headers.add(0x78) as *const u32;

        let export_dir_rva = *export_dir_rva_ptr as usize;
        if export_dir_rva == 0 { return Err(ResolveError::SymbolNotFound); }

        let export_dir = base.add(export_dir_rva);
        let num_names = *(export_dir.add(0x18) as *const u32) as usize;
        let names_rva = *(export_dir.add(0x20) as *const u32) as usize;
        let ordinals_rva = *(export_dir.add(0x24) as *const u32) as usize;
        let funcs_rva = *(export_dir.add(0x1c) as *const u32) as usize;

        let names_ptr = base.add(names_rva) as *const u32;
        let ordinals_ptr = base.add(ordinals_rva) as *const u16;
        let funcs_ptr = base.add(funcs_rva) as *const u32;

        for i in 0..num_names {
            let name_ptr = base.add(*names_ptr.add(i) as usize);

            // Manual strlen for no_std
            let mut len = 0;
            while *name_ptr.add(len) != 0 { len += 1; }

            let name_slice = core::slice::from_raw_parts(name_ptr, len);
            if get_default_hash(name_slice) == target_hash {
                let ordinal = *ordinals_ptr.add(i) as usize;
                let func_rva = *funcs_ptr.add(ordinal) as usize;
                return Ok(base.add(func_rva) as *const ());
            }
        }
        Err(ResolveError::SymbolNotFound)
    }
}