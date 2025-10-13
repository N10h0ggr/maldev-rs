/// Represents the available hardware debug registers (Dr0–Dr3).
/// Each one can hold a hardware breakpoint address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrRegister {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
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

/// Represents all hardware breakpoints (hooks) installed within a single thread.
///
/// Each thread can have up to four active hardware breakpoints,
/// corresponding to Dr0–Dr3.
#[derive(Debug, Clone)]
pub struct ThreadHookContext {
    /// The ID of the thread to which this context belongs.
    pub thread_id: Option<usize>,

    /// The list of hooks currently installed for this thread.
    ///
    /// In most cases, this vector should contain at most 4 entries
    /// (one per Dr register), but using a `Vec` makes management flexible.
    pub hooks: Vec<HookDescriptor>,
}
