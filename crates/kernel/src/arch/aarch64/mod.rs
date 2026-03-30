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
    const STAT_MODE_OFF: usize = 16;
    const STAT_BLKSIZE_OFF: usize = 56;

    unsafe fn fill_stat(buf: u64, vfs_stat: &rux_vfs::InodeStat) {
        let p = buf as *mut u8;
        for i in 0..144 { *p.add(i) = 0; }
        *(buf as *mut u64) = 0;                            // st_dev
        *((buf + 8) as *mut u64) = vfs_stat.ino;           // st_ino
        *((buf + 16) as *mut u32) = vfs_stat.mode;         // st_mode (u32)
        *((buf + 20) as *mut u32) = vfs_stat.nlink;        // st_nlink (u32)
        *((buf + 24) as *mut u32) = vfs_stat.uid;          // st_uid
        *((buf + 28) as *mut u32) = vfs_stat.gid;          // st_gid
        *((buf + 32) as *mut u64) = 0;                     // st_rdev
        *((buf + 40) as *mut u64) = 0;                     // __pad1
        *((buf + 48) as *mut i64) = vfs_stat.size as i64;  // st_size
        *((buf + 56) as *mut i32) = 4096;                  // st_blksize (i32)
        *((buf + 64) as *mut i64) = vfs_stat.blocks as i64; // st_blocks
    }
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
