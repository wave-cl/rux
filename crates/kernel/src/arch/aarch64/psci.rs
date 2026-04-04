/// PSCI (Power State Coordination Interface) for aarch64 AP startup.
///
/// PSCI is the standard interface for bringing up secondary CPUs on ARM.
/// On QEMU virt, PSCI is available via HVC (Hypervisor Call) or SMC.

/// PSCI function IDs (PSCI v1.0, aarch64 calling convention).
const PSCI_CPU_ON_64: u64 = 0xC4000003;

/// Start a secondary CPU using PSCI CPU_ON.
///
/// - `target_cpu`: MPIDR of the target CPU (affinity value)
/// - `entry_point`: physical address where the AP should start executing
/// - `context_id`: value passed in x0 to the AP entry point
///
/// Returns 0 on success, negative PSCI error code on failure.
///
/// # Safety
/// The entry point must be valid code, and the AP must not be already online.
pub unsafe fn cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "hvc #0",
        inout("x0") PSCI_CPU_ON_64 => ret,
        in("x1") target_cpu,
        in("x2") entry_point,
        in("x3") context_id,
        options(nostack)
    );
    ret
}

/// Get the MPIDR (CPU ID) of the current CPU.
#[allow(dead_code)]
pub unsafe fn current_cpu_id() -> u64 {
    let mpidr: u64;
    core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack));
    mpidr & 0xFF_FFFF // Aff0 + Aff1 + Aff2
}

/// Number of CPUs available (from DTB, simplified for now).
#[allow(dead_code)]
pub fn cpu_count() -> usize {
    1 // TODO: parse DTB /cpus node for cpu@ entries
}
