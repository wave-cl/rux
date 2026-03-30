pub mod init;
pub mod loader;
pub mod serial;
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

impl rux_arch::BootOps for X86_64 {
    fn boot_init(arg: usize) { init::x86_64_init(arg); }
}

impl rux_arch::TimerOps for X86_64 {
    fn ticks() -> u64 { pit::ticks() }
}

unsafe impl rux_arch::VforkOps for X86_64 {
    fn vfork_jmp_active() -> bool { syscall::vfork_jmp_active() }
    unsafe fn vfork_longjmp_to_parent(child_pid: i64) -> ! {
        syscall::vfork_longjmp_to_parent(child_pid)
    }
}

impl rux_arch::ArchInfo for X86_64 {
    const MACHINE_NAME: &'static [u8] = b"x86_64";
}

impl super::StatLayout for X86_64 {
    const STAT_MODE_OFF: usize = 24;
    const STAT_BLKSIZE_OFF: usize = 56;

    unsafe fn fill_stat(buf: u64, vfs_stat: &rux_vfs::InodeStat) {
        let p = buf as *mut u8;
        for i in 0..144 { *p.add(i) = 0; }
        *(buf as *mut u64) = 0;                            // st_dev
        *((buf + 8) as *mut u64) = vfs_stat.ino;           // st_ino
        *((buf + 16) as *mut u64) = vfs_stat.nlink as u64; // st_nlink (u64!)
        *((buf + 24) as *mut u32) = vfs_stat.mode;         // st_mode
        *((buf + 28) as *mut u32) = vfs_stat.uid;          // st_uid
        *((buf + 32) as *mut u32) = vfs_stat.gid;          // st_gid
        *((buf + 48) as *mut i64) = vfs_stat.size as i64;  // st_size
        *((buf + 56) as *mut i64) = 4096;                  // st_blksize
        *((buf + 64) as *mut i64) = vfs_stat.blocks as i64; // st_blocks
    }
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
