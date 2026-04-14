//! Architecture-specific kernel implementations.
//!
//! Each submodule contains the hardware-specific glue between
//! the generic kernel and the target architecture. The `Arch` type
//! alias selects the concrete implementation — adding a new arch
//! means implementing the traits and adding cfg lines here.

#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub mod x86_64;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub mod aarch64;
#[cfg(feature = "native")]
pub mod native;

/// The concrete architecture type. Implements all arch traits.
#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub type Arch = x86_64::X86_64;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub type Arch = aarch64::Aarch64;
#[cfg(feature = "native")]
pub type Arch = native::NativeArch;

/// The concrete page table type for the current architecture.
#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub type PageTable = x86_64::paging::PageTable4Level;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub type PageTable = aarch64::paging::PageTable4Level;
#[cfg(feature = "native")]
pub type PageTable = native::FlatPageTable;

/// The concrete PTE operations type for the current architecture.
#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub type ArchPte = rux_arch::x86_64::pte::X86_64Pte;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub type ArchPte = rux_arch::aarch64::pte::Aarch64Pte;
#[cfg(feature = "native")]
pub type ArchPte = native::NativePte;

pub use rux_arch::StatLayout;

/// Re-export arch-specific user_regs helpers (for ptrace GETREGS/SETREGS).
#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub use x86_64::syscall::{USER_REGS_SIZE, read_user_regs, write_user_regs};
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub use aarch64::syscall::{USER_REGS_SIZE, read_user_regs, write_user_regs};
#[cfg(feature = "native")]
pub use native::{USER_REGS_SIZE, read_user_regs, write_user_regs};

/// Re-export arch-specific device probes (used by boot.rs).
#[cfg(all(target_arch = "x86_64", not(feature = "native"), feature = "net"))]
pub use x86_64::probe_and_init_net;
#[cfg(all(target_arch = "aarch64", not(feature = "native"), feature = "net"))]
pub use aarch64::probe_and_init_net;
#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
pub use x86_64::probe_blk;
#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
pub use aarch64::probe_blk;
#[cfg(feature = "native")]
pub use native::probe_blk;
#[cfg(all(feature = "native", feature = "net"))]
pub use native::probe_and_init_net;

/// Increment preempt_count (prevents ISR from calling schedule).
#[inline(always)]
pub unsafe fn preempt_disable() {
    #[cfg(not(feature = "native"))]
    { crate::percpu::this_cpu().preempt_count += 1; }
}

/// Decrement preempt_count.
#[inline(always)]
pub unsafe fn preempt_enable() {
    #[cfg(not(feature = "native"))]
    {
        let pc = crate::percpu::this_cpu();
        if pc.preempt_count > 0 { pc.preempt_count -= 1; }
    }
}

/// Check if preemption is allowed (preempt_count == 0).
#[inline(always)]
pub unsafe fn preemptible() -> bool {
    #[cfg(not(feature = "native"))]
    { crate::percpu::this_cpu().preempt_count == 0 }
    #[cfg(feature = "native")]
    { true }
}

/// Disable hardware interrupts. Returns whether interrupts were previously enabled.
/// Also increments preempt_count to prevent ISR preemption.
#[inline(always)]
pub unsafe fn irq_disable() -> bool {
    #[cfg(target_arch = "x86_64")]
    let was = {
        let flags: u64;
        core::arch::asm!("pushfq; pop {}; cli", out(reg) flags);
        flags & 0x200 != 0
    };
    #[cfg(target_arch = "aarch64")]
    let was = {
        let daif: u64;
        core::arch::asm!("mrs {}, daif", out(reg) daif, options(nostack));
        core::arch::asm!("msr daifset, #2", options(nostack));
        daif & (1 << 7) == 0
    };
    #[cfg(feature = "native")]
    let was = false;
    preempt_disable();
    was
}

/// Restore hardware interrupts to a previous state.
/// Decrements preempt_count.
#[inline(always)]
pub unsafe fn irq_restore(was_enabled: bool) {
    preempt_enable();
    if was_enabled {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("sti", options(nostack, preserves_flags));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("msr daifclr, #2", options(nostack));
    }
}

/// Fill a Linux struct stat buffer from VFS InodeStat.
/// Delegates to the `StatLayout::fill_stat` default method in rux-arch.
pub unsafe fn fill_linux_stat<A: StatLayout>(buf: usize, s: &rux_fs::InodeStat) {
    A::fill_stat(buf, s.ino, s.nlink, s.mode, s.uid, s.gid, s.size, s.blocks);
    // Write rdev if the arch defines a non-zero offset for it
    if A::RDEV_OFF > 0 {
        *((buf + A::RDEV_OFF) as *mut u64) = s.rdev as u64;
    }
}

/// Map kernel identity pages into a user page table.
/// Each arch has different physical ranges and device maps.
///
/// # Safety
/// Modifies page table mappings.
pub unsafe trait KernelMapOps {
    unsafe fn map_kernel_pages(
        pt: &mut PageTable,
        alloc: &mut dyn rux_mm::FrameAllocator,
    );
}

