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

/// Boot CPU ID (always 0).
static mut BSP_CPU_ID: usize = 0;

/// Cached CPU ID for the current core. Set once per CPU at init/AP entry.
/// Avoids expensive LAPIC MMIO reads on every syscall.
#[cfg(target_arch = "x86_64")]
static mut CACHED_CPU_ID: usize = 0;
#[cfg(target_arch = "aarch64")]
static mut CACHED_CPU_ID: usize = 0;
#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
static mut CACHED_CPU_ID: usize = 0;

/// Set the cached CPU ID for the current core. Called once per CPU.
pub unsafe fn set_cpu_id(id: usize) { CACHED_CPU_ID = id; }

/// Enable hardware CPU ID detection (legacy, now no-op — use set_cpu_id).
pub unsafe fn enable_hw_cpu_id() { /* no-op, kept for API compat */ }

/// Read the current CPU's ID (cached, no MMIO read).
#[inline(always)]
pub unsafe fn cpu_id() -> usize { CACHED_CPU_ID }

/// Get the current CPU's per-CPU data using hardware CPU ID.
#[inline(always)]
pub unsafe fn this_cpu() -> &'static mut PerCpu {
    &mut PERCPU[cpu_id()]
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
