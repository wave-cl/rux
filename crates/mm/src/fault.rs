use rux_klib::VirtAddr;

/// Action to take after handling a page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultAction {
    /// Fault resolved — the faulting instruction can be retried.
    Resolved = 0,
    /// Segmentation fault — no VMA covers this address, or permission denied.
    Segfault = 1,
    /// Bus error — alignment fault or hardware error.
    BusError = 2,
    /// Out of memory — could not allocate a frame to resolve the fault.
    Oom = 3,
}

/// Page fault handler.
///
/// Dispatches based on fault type:
/// 1. No VMA at fault address → Segfault
/// 2. VMA found, write fault, COW page → copy page, remap writable
/// 3. VMA found, demand paging (not yet mapped) → allocate + zero + map
/// 4. VMA found, permission violation → Segfault
pub trait PageFaultHandler {
    /// Handle a page fault at `addr`.
    /// - `is_write`: true if the fault was caused by a write.
    /// - `is_user`: true if the fault was from user mode.
    fn handle_fault(
        &mut self,
        addr: VirtAddr,
        is_write: bool,
        is_user: bool,
    ) -> FaultAction;
}
