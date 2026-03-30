pub mod init;
pub mod loader;
pub mod serial;
pub mod exit;
pub mod exception;
pub mod gic;
pub mod timer;
pub mod context;
pub mod devicetree;
pub mod paging;
pub mod syscall;

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("exception.S"));

/// Zero-sized marker type for aarch64 architecture trait implementations.
pub struct Aarch64;

impl rux_arch::ArchSpecificOps for Aarch64 {
    fn arch_syscall(_nr: u64, _a0: u64, _a1: u64) -> Option<i64> { None }
}

impl rux_arch::BootOps for Aarch64 {
    fn boot_init(arg: usize) { init::aarch64_init(arg); }
}

impl rux_arch::TimerOps for Aarch64 {
    fn ticks() -> u64 { timer::ticks() }
}

unsafe impl rux_arch::VforkOps for Aarch64 {
    fn vfork_jmp_active() -> bool { syscall::vfork_jmp_active() }
    unsafe fn vfork_longjmp_to_parent(child_pid: i64) -> ! {
        syscall::vfork_longjmp_to_parent(child_pid)
    }
}

impl rux_arch::ArchInfo for Aarch64 {
    const MACHINE_NAME: &'static [u8] = b"aarch64";
}

impl super::StatLayout for Aarch64 {
    const STAT_SIZE: usize = 128;
    const INO_OFF: usize = 8;
    const NLINK_OFF: usize = 20;
    const NLINK_IS_U64: bool = false;
    const MODE_OFF: usize = 16;
    const UID_OFF: usize = 24;
    const GID_OFF: usize = 28;
    const RDEV_OFF: usize = 32;
    const SIZE_OFF: usize = 48;
    const BLKSIZE_OFF: usize = 56;
    const BLKSIZE_IS_I64: bool = false;
    const BLOCKS_OFF: usize = 64;
}

unsafe impl super::KernelMapOps for Aarch64 {
    unsafe fn map_kernel_pages(
        pt: &mut super::PageTable,
        alloc: &mut dyn rux_mm::FrameAllocator,
    ) {
        use rux_klib::PhysAddr;
        use rux_mm::MappingFlags;
        let kflags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::EXECUTE);
        pt.identity_map_range(PhysAddr::new(0x40000000), 128 * 1024 * 1024, kflags, alloc)
            .expect("kernel map");
        let dev_flags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::NO_CACHE);
        pt.identity_map_range(PhysAddr::new(0x08000000), 0x20000, dev_flags, alloc)
            .expect("gic map");
        pt.identity_map_range(PhysAddr::new(0x09000000), 0x1000, dev_flags, alloc)
            .expect("uart map");
    }
}
