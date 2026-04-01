/// Per-CPU data structures.
///
/// Each CPU has its own `PerCpu` instance, indexed by CPU ID (0 for BSP).
/// Currently single-CPU: only slot 0 is used. The infrastructure is ready
/// for SMP when AP startup is implemented.

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 16;

/// Per-CPU data. Each CPU has its own instance to avoid sharing hot state.
#[repr(C)]
pub struct PerCpu {
    /// This CPU's ID (APIC ID on x86_64, MPIDR on aarch64).
    pub cpu_id: u32,
    /// Whether this CPU is online and executing.
    pub online: bool,
    /// Whether this CPU is in the idle loop (no runnable tasks).
    pub idle: bool,
    _pad: [u8; 2],
    /// Index of the currently running task on this CPU.
    pub current_task_idx: usize,
    /// Kernel stack top for this CPU's syscall entry (x86_64: loaded into RSP by SYSCALL).
    pub kstack_top: u64,
}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
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

/// Boot CPU ID (always 0 for now).
static mut BSP_CPU_ID: usize = 0;

/// Get the current CPU's per-CPU data.
///
/// # Safety
/// Must be called after `init_bsp()`. On SMP, must read the actual
/// CPU ID from hardware (APIC ID / MPIDR). Currently returns BSP slot.
#[inline(always)]
pub unsafe fn this_cpu() -> &'static mut PerCpu {
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
