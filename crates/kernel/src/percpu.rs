/// Per-CPU data structures.
///
/// Each CPU has its own `PerCpu` instance, indexed by CPU ID (0 for BSP).
/// The arch-specific register setup (GS_BASE on x86_64, TPIDR_EL1 on
/// aarch64) is provided by the PerCpuOps trait — no cfg/asm in this file.

use rux_arch::PerCpuOps;

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 16;

/// Per-CPU data layout. #[repr(C)] ensures stable field offsets for asm access.
///
/// x86_64 syscall_entry uses gs:[offset] to access saved_user_rsp,
/// saved_syscall_a5, and syscall_kstack_top. Offsets must match the
/// PERCPU_OFFSET_* constants below.
#[repr(C)]
pub struct PerCpu {
    // ── Fields accessed from assembly (offsets must be stable) ────
    /// Saved user RSP on SYSCALL entry (gs:[0]).
    pub saved_user_rsp: u64,        // offset 0
    /// Saved 6th syscall arg R9 (gs:[8]).
    pub saved_syscall_a5: u64,      // offset 8
    /// Kernel stack top for SYSCALL entry (gs:[16]).
    pub syscall_kstack_top: u64,    // offset 16

    // ── Fields accessed from Rust ────────────────────────────────
    /// This CPU's ID (APIC ID on x86_64, MPIDR on aarch64).
    pub cpu_id: u32,                // offset 24
    /// Whether this CPU is online and executing.
    pub online: bool,               // offset 28
    /// Whether this CPU is in the idle loop.
    pub idle: bool,                 // offset 29
    _pad: [u8; 2],                  // offset 30
    /// Index of the currently running task on this CPU.
    pub current_task_idx: usize,    // offset 32
    /// Kernel stack top (legacy, same as syscall_kstack_top).
    pub kstack_top: u64,            // offset 40
}

/// Assembly-accessible offsets into PerCpu (must match #[repr(C)] layout).
pub const PERCPU_OFFSET_SAVED_USER_RSP: usize = 0;
pub const PERCPU_OFFSET_SAVED_A5: usize = 8;
pub const PERCPU_OFFSET_KSTACK_TOP: usize = 16;

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            saved_user_rsp: 0, saved_syscall_a5: 0, syscall_kstack_top: 0,
            cpu_id: 0, online: false, idle: true, _pad: [0; 2],
            current_task_idx: 0, kstack_top: 0,
        }
    }
}

/// Per-CPU storage array.
static mut PERCPU: [PerCpu; MAX_CPUS] = {
    const EMPTY: PerCpu = PerCpu::new();
    [EMPTY; MAX_CPUS]
};

// AP stacks use KSTACKS[cpu_id] from task_table.rs (shared with tasks).
// With MAX_PROCS=16, APs 1..N consume N task stack slots.
// TODO: separate AP_KSTACKS when BSS layout issues are resolved.

/// Boot CPU ID (always 0).
static mut BSP_CPU_ID: usize = 0;

/// Enable per-CPU data access. Call after setting TPIDR_EL1 (aarch64)
/// or GS-base (x86_64) to point to the current CPU's PerCpu struct.
pub unsafe fn enable_hw_cpu_id() { /* activate per-CPU access */ }

/// Set the per-CPU hardware register to point to this CPU's PerCpu struct.
/// Delegates to the architecture's PerCpuOps implementation.
pub unsafe fn init_this_cpu(id: usize) {
    let base = &mut PERCPU[id] as *mut PerCpu as *mut u8;
    crate::arch::Arch::init_percpu(id, base);
}

/// Read the current CPU's ID. Uses per-CPU register (fast, no table lookup).
#[inline(always)]
pub unsafe fn cpu_id() -> usize {
    this_cpu().cpu_id as usize
}

/// Get the current CPU's per-CPU data.
/// Uses the arch per-CPU register (TPIDR_EL1 on aarch64, GS-base on x86_64).
/// Falls back to PERCPU[BSP_CPU_ID] if per-CPU registers not yet initialized.
#[inline(always)]
pub unsafe fn this_cpu() -> &'static mut PerCpu {
    let base = crate::arch::Arch::percpu_base();
    if !base.is_null() {
        return &mut *(base as *mut PerCpu);
    }
    &mut PERCPU[BSP_CPU_ID]
}

/// Get per-CPU data for a specific CPU.
#[inline(always)]
pub unsafe fn cpu(id: usize) -> &'static mut PerCpu {
    &mut PERCPU[id]
}

/// Initialize the BSP (Boot Strap Processor) per-CPU data.
pub unsafe fn init_bsp() {
    BSP_CPU_ID = 0;
    PERCPU[0].cpu_id = 0;
    PERCPU[0].online = true;
}

/// Number of online CPUs.
pub fn online_cpus() -> usize {
    unsafe { PERCPU.iter().filter(|c| c.online).count() }
}
