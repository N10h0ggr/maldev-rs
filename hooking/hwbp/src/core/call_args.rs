use core::{marker::PhantomData, mem, ptr};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

/// Safe and ergonomic wrapper around a raw Windows thread [`CONTEXT`] pointer,
/// focused on reading and modifying **function call arguments** when handling
/// hardware breakpoints (e.g., inside a vectored exception handler).
///
/// # Overview
///
/// Windows passes function parameters differently depending on architecture:
///
/// - **x64 (Windows ABI)** — the first four integer or pointer arguments are
///   stored in the registers **RCX**, **RDX**, **R8**, and **R9**. Any additional
///   parameters are placed on the stack, located at:
///
///   ```text
///   [RSP + 0x00] = return address
///   [RSP + 0x08..0x28) = 32-byte shadow space (home space)
///   [RSP + 0x28] = first stack argument (the 5th parameter)
///   ```
///
/// - **x86** — all arguments are pushed onto the stack:
///
///   ```text
///   [ESP + 0x00] = return address
///   [ESP + 0x04] = arg1
///   [ESP + 0x08] = arg2
///   ...
///   ```
///
/// This struct abstracts away these differences and provides safe, consistent
/// methods for reading and writing arguments by **1-based index** (i.e. `1` for
/// the first parameter, `2` for the second, etc.).
///
/// # Safety
///
/// - The provided `CONTEXT` pointer must be valid and correspond to the thread
///   that triggered the exception.
/// - Modifying registers or stack values can corrupt program state if used
///   incorrectly. Ensure the context represents a valid function entry frame.
pub struct CallArgs<'a> {
    ctx: *mut CONTEXT,
    _lt: PhantomData<&'a mut CONTEXT>,
}

impl<'a> CallArgs<'a> {
    /// Creates a new [`CallArgs`] wrapper from a raw [`CONTEXT`] pointer.
    ///
    /// # Safety
    /// - `ctx` must point to a valid thread context owned by the current thread.
    pub unsafe fn new(ctx: *mut CONTEXT) -> Self {
        Self {
            ctx,
            _lt: PhantomData,
        }
    }

    /// Returns the underlying raw [`CONTEXT`] pointer.
    #[inline]
    pub fn as_mut_context_ptr(&mut self) -> *mut CONTEXT {
        self.ctx
    }

    /// Fetches the Nth argument (1-based) by index.
    ///
    /// # Safety
    /// - Same as [`Self::get`].
    #[inline]
    pub unsafe fn get_const<const N: u32>(&self) -> usize {
        unsafe { self.get(N) }
    }

    /// Sets the Nth argument (1-based) to a new value.
    ///
    /// # Safety
    /// - Same as [`Self::set`].
    #[inline]
    pub unsafe fn set_const<const N: u32>(&mut self, value: usize) {
        unsafe { self.set(N, value) }
    }

    /// Reads the argument at the given index as a pointer.
    ///
    /// # Safety
    /// - Same as [`Self::get`].
    #[inline]
    pub unsafe fn get_ptr<T>(&self, index: u32) -> *mut T {
        unsafe { self.get(index) as *mut T }
    }

    /// Sets the argument at the given index to the specified pointer.
    ///
    /// # Safety
    /// - Same as [`Self::set`].
    #[inline]
    pub unsafe fn set_ptr<T>(&mut self, index: u32, ptr_val: *mut T) {
        unsafe { self.set(index, ptr_val as usize) }
    }
}

#[cfg(target_arch = "x86_64")]
impl<'a> CallArgs<'a> {
    /// Fetches the Nth argument (1-based) as a `usize` for x64 calling convention.
    ///
    /// # Safety
    /// - `self.ctx` must be valid.
    /// - For indices ≥ 5, reads from the stack; the address must be valid.
    pub unsafe fn get(&self, index: u32) -> usize {
        assert!(index >= 1, "argument index must be 1-based");
        let c = unsafe { &*self.ctx };

        match index {
            1 => c.Rcx as usize,
            2 => c.Rdx as usize,
            3 => c.R8 as usize,
            4 => c.R9 as usize,
            _ => {
                let rsp = c.Rsp as usize;
                let slot = (index - 5) as usize;
                let addr = rsp + 8 + 32 + slot * mem::size_of::<usize>();
                unsafe { ptr::read(addr as *const usize) }
            }
        }
    }

    /// Writes a new value into the Nth argument (1-based) for x64.
    ///
    /// # Safety
    /// - `self.ctx` must be valid and mutable.
    /// - For indices ≥ 5, writes into the stack; the address must be valid.
    pub unsafe fn set(&mut self, index: u32, value: usize) {
        assert!(index >= 1, "argument index must be 1-based");
        let c = unsafe { &mut *self.ctx };

        match index {
            1 => c.Rcx = value as u64,
            2 => c.Rdx = value as u64,
            3 => c.R8 = value as u64,
            4 => c.R9 = value as u64,
            _ => {
                let rsp = c.Rsp as usize;
                let slot = (index - 5) as usize;
                let addr = rsp + 8 + 32 + slot * mem::size_of::<usize>();
                unsafe { ptr::write(addr as *mut usize, value) };
            }
        }
    }
}

#[cfg(target_arch = "x86")]
impl<'a> CallArgs<'a> {
    /// Fetches the Nth argument (1-based) as a `usize` for x86 calling convention.
    ///
    /// # Safety
    /// - `self.ctx` must be valid.
    /// - Reads from the current stack frame; ensure address is valid.
    pub unsafe fn get(&self, index: u32) -> usize {
        assert!(index >= 1, "argument index must be 1-based");
        let c = unsafe { &*self.ctx };
        let esp = c.Esp as usize;
        let addr = esp + (index as usize) * mem::size_of::<usize>();
        unsafe { ptr::read(addr as *const usize) }
    }

    /// Writes a new value into the Nth argument (1-based) for x86.
    ///
    /// # Safety
    /// - `self.ctx` must be valid and mutable.
    /// - Writes into the current stack frame; ensure address is valid.
    pub unsafe fn set(&mut self, index: u32, value: usize) {
        assert!(index >= 1, "argument index must be 1-based");
        let c = unsafe { &mut *self.ctx };
        let esp = c.Esp as usize;
        let addr = esp + (index as usize) * mem::size_of::<usize>();
        unsafe { ptr::write(addr as *mut usize, value) };
    }
}
