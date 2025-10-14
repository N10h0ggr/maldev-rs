use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

/// Global registry tracking all hardware breakpoints (hooks) across threads.
///
/// This singleton holds a thread-safe `HookRegistry` that maps thread IDs
/// to their corresponding `ThreadHookContext`. It allows installing,
/// removing, and inspecting hardware breakpoints globally.
///
/// Access is synchronized using a `Mutex`, so operations on the registry
/// must lock it before modification:
pub static HOOK_REGISTRY: LazyLock<Mutex<HookRegistry>> =
    LazyLock::new(|| Mutex::new(HookRegistry::default()));

/// Represents the available hardware debug registers (Dr0–Dr3).
/// Each one can hold a hardware breakpoint address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrRegister {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

impl DrRegister {
    /// Returns the numeric index of the register (Dr0 = 0, Dr1 = 1, ...).
    #[inline]
    pub const fn index(&self) -> u8 {
        match self {
            DrRegister::Dr0 => 0,
            DrRegister::Dr1 => 1,
            DrRegister::Dr2 => 2,
            DrRegister::Dr3 => 3,
        }
    }

    /// Converts an index (0–3) into a DrRegister.
    #[inline]
    pub const fn from_index(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(DrRegister::Dr0),
            1 => Some(DrRegister::Dr1),
            2 => Some(DrRegister::Dr2),
            3 => Some(DrRegister::Dr3),
            _ => None,
        }
    }
}

/// Represents the current state of a hardware breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointState {
    /// The breakpoint is currently active and enabled in Dr7.
    Active,

    /// The breakpoint exists but is temporarily disabled.
    Disabled,

    /// The breakpoint slot is free (no address assigned).
    Free,
}

/// Describes a single hardware breakpoint (hook) installed on a thread.
///
/// Each `HookDescriptor` tracks which address is being monitored,
/// which detour function should be called, which register (Dr0–Dr3)
/// is used, and which thread owns it.
#[derive(Debug, Clone)]
pub struct HookDescriptor {
    /// The address of the target function being hooked.
    pub target_address: Option<usize>,

    /// The address of the detour (callback) function.
    pub detour_address: Option<usize>,

    /// Which debug register (Dr0–Dr3) is used for this hook.
    pub register: Option<DrRegister>,

    /// The current operational state of the breakpoint.
    pub state: BreakpointState,

    /// The thread ID that owns this hook (breakpoints are per-thread).
    pub thread_id: Option<usize>,
}

/// Global registry of all active hardware breakpoints (hooks) across threads.
///
/// This structure maintains a flat mapping of `(thread_id, DrRegister)` → [`HookDescriptor`].
/// Each entry uniquely identifies a single hardware breakpoint bound to a specific
/// thread and debug register (Dr0–Dr3).
///
/// - The key is a tuple `(usize, DrRegister)`, where:
///   - `usize` is the **thread ID** owning the breakpoint.
///   - [`DrRegister`] indicates which debug register (Dr0–Dr3) is used.
/// - The value is a [`HookDescriptor`] describing the breakpoint (target, detour, state, etc.).
///
/// This design simplifies global lookups (e.g. checking if any thread uses Dr0),
/// while still allowing efficient filtering per thread.
#[derive(Debug, Default)]
pub struct HookRegistry {
    /// Flat mapping of `(thread_id, DrRegister)` to an active [`HookDescriptor`].
    pub active: HashMap<(usize, DrRegister), HookDescriptor>,
}

impl HookRegistry {
    /// Returns all active hooks for a given thread as an iterator of `(DrRegister, &HookDescriptor)`.
    ///
    /// This allows you to easily enumerate or filter all hardware breakpoints
    /// associated with a single thread.
    pub fn filter_by_thread(
        &self,
        thread_id: usize,
    ) -> impl Iterator<Item = (DrRegister, &HookDescriptor)> {
        self.active.iter().filter_map(move |(key, desc)| {
            let (tid, reg) = *key;
            if tid == thread_id {
                Some((reg, desc))
            } else {
                None
            }
        })
    }

    /// Returns the number of active hooks currently installed for a specific thread.
    #[inline]
    pub fn count_for_thread(&self, thread_id: usize) -> usize {
        self.active
            .keys()
            .filter(|(tid, _)| *tid == thread_id)
            .count()
    }

    /// Checks if a specific `(thread_id, DrRegister)` combination is present in the registry.
    ///
    /// Returns `true` if that specific hardware breakpoint is currently active.
    #[inline]
    pub fn contains(&self, thread_id: usize, reg: DrRegister) -> bool {
        self.active.contains_key(&(thread_id, reg))
    }
}
