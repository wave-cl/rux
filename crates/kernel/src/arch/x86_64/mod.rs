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

// Include boot assembly: multiboot1 header + 32→64 bit transition
core::arch::global_asm!(include_str!("boot.S"));

/// Zero-sized marker type for x86_64 architecture trait implementations.
pub struct X86_64;

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

unsafe impl super::KernelMapOps for X86_64 {
    unsafe fn map_kernel_pages(
        pt: &mut super::PageTable,
        alloc: &mut dyn rux_mm::FrameAllocator,
    ) {
        use rux_klib::PhysAddr;
        use rux_mm::MappingFlags;
        let kflags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::EXECUTE);
        pt.identity_map_range(PhysAddr::new(0), 128 * 1024 * 1024, kflags, alloc)
            .expect("kernel map");
    }
}
