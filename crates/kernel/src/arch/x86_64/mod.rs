pub mod init;
pub mod console;
pub mod exit;
pub mod gdt;
pub mod idt;
pub mod pit;
pub mod context;
pub mod multiboot;
pub mod paging;
pub mod syscall;
pub mod acpi;
pub mod apic;
pub mod uaccess;
pub mod fork;
pub mod task_switch;

// Include boot assembly: multiboot1 header + 32→64 bit transition
core::arch::global_asm!(include_str!("boot.S"));
// AP trampoline: 16-bit → long mode startup code, copied to 0x8000 at runtime
core::arch::global_asm!(include_str!("ap_trampoline.S"));

/// Zero-sized marker type for x86_64 architecture trait implementations.
pub struct X86_64;

unsafe impl rux_arch::PerCpuOps for X86_64 {
    unsafe fn init_percpu(_id: usize, base: *mut u8) {
        let val = base as u64;
        let lo = val as u32;
        let hi = (val >> 32) as u32;
        // IA32_GS_BASE (0xC0000101) — active GS base (kernel before first swapgs)
        core::arch::asm!("wrmsr", in("ecx") 0xC0000101u32, in("eax") lo, in("edx") hi, options(nostack));
        // IA32_KERNEL_GS_BASE (0xC0000102) — swapped in by swapgs at syscall entry
        core::arch::asm!("wrmsr", in("ecx") 0xC0000102u32, in("eax") lo, in("edx") hi, options(nostack));
    }

    #[inline(always)]
    unsafe fn percpu_base() -> *mut u8 {
        // GS-relative access deferred for QEMU TCG compatibility.
        // Fall through to null — caller uses array fallback.
        core::ptr::null_mut()
    }
}

impl rux_arch::SyscallArgOps for X86_64 {
    #[inline(always)]
    fn saved_syscall_arg5() -> usize {
        unsafe { crate::percpu::this_cpu().saved_syscall_a5 as usize }
    }
}

impl rux_arch::ArchSpecificOps for X86_64 {
    fn arch_syscall(nr: usize, a0: usize, a1: usize) -> Option<isize> {
        match nr {
            158 => Some(syscall::syscall_arch_prctl(a0 as u64, a1 as u64) as isize),
            _ => None,
        }
    }
}

impl rux_arch::BootOps for X86_64 {
    fn boot_init(arg: usize) { init::x86_64_init(arg); }
}

impl rux_arch::TimerOps for X86_64 {
    fn ticks() -> u64 { pit::ticks() }
}

unsafe impl rux_arch::HaltOps for X86_64 {
    unsafe fn halt_until_interrupt() {
        core::arch::asm!("sti; hlt; cli", options(nostack, nomem));
    }
}

unsafe impl rux_arch::TimerControl for X86_64 {
    unsafe fn stop_timer() { pit::stop_timer(); }
    unsafe fn start_timer() { pit::start_timer(); }
}


impl rux_arch::ArchInfo for X86_64 {
    const MACHINE_NAME: &'static [u8] = b"x86_64";
}

impl super::StatLayout for X86_64 {
    const STAT_SIZE: usize = 144;
    const INO_OFF: usize = 8;
    const NLINK_OFF: usize = 16;
    const NLINK_IS_U64: bool = true;
    const MODE_OFF: usize = 24;
    const UID_OFF: usize = 28;
    const GID_OFF: usize = 32;
    const RDEV_OFF: usize = 0; // skip
    const SIZE_OFF: usize = 48;
    const BLKSIZE_OFF: usize = 56;
    const BLKSIZE_IS_I64: bool = true;
    const BLOCKS_OFF: usize = 64;
}

impl rux_arch::SigactionLayout for X86_64 {
    const MASK_OFF: usize = 24;      // after handler(8) + flags(8) + restorer(8)
    const HAS_RESTORER: bool = true;
    const RESTORER_OFF: usize = 16;  // after handler(8) + flags(8)
}

unsafe impl super::KernelMapOps for X86_64 {
    unsafe fn map_kernel_pages(
        pt: &mut super::PageTable,
        alloc: &mut dyn rux_mm::FrameAllocator,
    ) {
        use rux_klib::PhysAddr;
        use rux_mm::MappingFlags;
        // User PTs must use 4K pages for the kernel identity map (not huge pages).
        // User ELF segments (0x400000+) overlap the 0-128MB kernel identity map.
        // Huge pages at L1 (PD) level would prevent map_4k from creating user PTEs
        // in the same 2MB regions — ensure_table returns the huge PTE as a table
        // pointer, causing corruption. Boot kernel PT (no user mappings) uses huge
        // pages safely since no 4K user pages share its page directories.
        let kflags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::EXECUTE);
        pt.identity_map_range(PhysAddr::new(0), 128 * 1024 * 1024, kflags, alloc)
            .expect("kernel map");
        // Map LAPIC MMIO (0xFEE00000) for SMP support
        let dev_flags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::NO_CACHE);
        pt.identity_map_range(PhysAddr::new(0xFEE00000), 4096, dev_flags, alloc)
            .expect("lapic map");
    }
}
