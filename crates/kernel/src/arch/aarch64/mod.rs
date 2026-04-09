pub mod init;
pub mod console;
pub mod exit;
pub mod exception;
pub mod gic;
pub mod timer;
pub mod context;
pub mod devicetree;
pub mod paging;
pub mod syscall;
pub mod psci;
pub mod uaccess;
pub mod fork;
pub mod task_switch;
pub mod rtc;

core::arch::global_asm!(include_str!("boot.S"));
core::arch::global_asm!(include_str!("exception.S"));
core::arch::global_asm!(include_str!("ap_entry.S"));

/// Zero-sized marker type for aarch64 architecture trait implementations.
pub struct Aarch64;

unsafe impl rux_arch::PerCpuOps for Aarch64 {
    unsafe fn init_percpu(_id: usize, base: *mut u8) {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) base as u64, options(nostack));
    }

    #[inline(always)]
    unsafe fn percpu_base() -> *mut u8 {
        let base: u64;
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) base, options(nostack));
        base as *mut u8
    }
}

impl rux_arch::SyscallArgOps for Aarch64 {
    #[inline(always)]
    fn saved_syscall_arg5() -> usize {
        unsafe { syscall::SAVED_SYSCALL_A5_PERCPU[crate::percpu::cpu_id()] as usize }
    }
}

impl rux_arch::ArchSpecificOps for Aarch64 {
    fn arch_syscall(_nr: usize, _a0: usize, _a1: usize) -> Option<isize> { None }
}

impl rux_arch::BootOps for Aarch64 {
    fn boot_init(arg: usize) { init::aarch64_init(arg); }
}

impl rux_arch::TimerOps for Aarch64 {
    fn ticks() -> u64 { timer::ticks() }
}

unsafe impl rux_arch::HaltOps for Aarch64 {
    unsafe fn halt_until_interrupt() {
        core::arch::asm!(
            "msr daifclr, #2", "wfi", "msr daifset, #2",
            options(nostack, nomem)
        );
    }
}

unsafe impl rux_arch::TimerControl for Aarch64 {
    unsafe fn stop_timer() { timer::stop_timer(); }
    unsafe fn start_timer() { timer::start_timer(); }
}

impl rux_arch::ArchInfo for Aarch64 {
    const MACHINE_NAME: &'static [u8] = b"aarch64";
}

impl rux_arch::MemoryLayout for Aarch64 {
    const USER_ADDR_LIMIT: u64 = 0x0001_0000_0000; // 4 GiB (full TTBR0 range)
    const INTERP_BASE: u64 = 0x20000000; // 512 MiB (avoids aarch64 identity map)
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

impl rux_arch::SigactionLayout for Aarch64 {
    const MASK_OFF: usize = 16;       // after handler(8) + flags(8)
    const HAS_RESTORER: bool = false;
    const RESTORER_OFF: usize = 0;    // unused
}

unsafe impl super::KernelMapOps for Aarch64 {
    unsafe fn map_kernel_pages(
        pt: &mut super::PageTable,
        alloc: &mut dyn rux_mm::FrameAllocator,
    ) {
        use rux_klib::PhysAddr;
        use rux_mm::MappingFlags;
        let kflags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::EXECUTE);
        pt.identity_map_range_huge(PhysAddr::new(0x40000000), 128 * 1024 * 1024, kflags, alloc)
            .expect("kernel map");
        let dev_flags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::NO_CACHE);
        pt.identity_map_range(PhysAddr::new(0x08000000), 0x20000, dev_flags, alloc)
            .expect("gic map");
        pt.identity_map_range(PhysAddr::new(0x09000000), 0x11000, dev_flags, alloc)
            .expect("uart+rtc map");
        // virtio-mmio region (for ext2 root disk access from any page table)
        pt.identity_map_range(PhysAddr::new(0x0a000000), 0x10000, dev_flags, alloc)
            .expect("virtio-mmio map");
    }
}

/// Static storage for the MMIO virtio-blk driver (needs 'static for ext2 ref).
static mut VIRTIO_BLK_MMIO: core::mem::MaybeUninit<rux_drivers::virtio::blk::VirtioBlk> = core::mem::MaybeUninit::uninit();

/// Probe and initialize virtio-blk via MMIO. Returns (device_ptr, capacity_sectors).
pub unsafe fn probe_blk(vq_addr: usize, log: fn(&str)) -> Option<(*const dyn rux_drivers::BlockDevice, u64)> {
    let base = rux_drivers::virtio::blk::probe_virtio_blk()?;
    log("rux: virtio-blk: probing at 0x");
    { use rux_arch::ConsoleOps; let mut hb = [0u8; 16]; Aarch64::write_bytes(rux_klib::fmt::usize_to_hex(&mut hb, base)); }
    log("\n");
    match rux_drivers::virtio::blk::VirtioBlk::new(base, vq_addr) {
        Ok(blk) => {
            let cap = blk.capacity_sectors();
            (*(&raw mut VIRTIO_BLK_MMIO)).write(blk);
            Some(((*(&raw const VIRTIO_BLK_MMIO)).assume_init_ref() as *const _, cap))
        }
        Err(_) => { log("rux: virtio-blk: init failed\n"); None }
    }
}

/// Probe and initialize virtio-net via MMIO. Called from boot.rs.
#[cfg(feature = "net")]
pub unsafe fn probe_and_init_net(alloc: &mut rux_mm::frame::BuddyAllocator, log: fn(&str)) {
    if let Some(net_base) = rux_drivers::virtio::net::probe_mmio() {
        let rx_pg = alloc.alloc_order(1).ok();
        let tx_pg = alloc.alloc_order(1).ok();
        if let (Some(rx), Some(tx)) = (rx_pg, tx_pg) {
            core::ptr::write_bytes(rx.as_usize() as *mut u8, 0, 8192);
            core::ptr::write_bytes(tx.as_usize() as *mut u8, 0, 8192);
            if rux_drivers::virtio::net::init_mmio(net_base, rx.as_usize(), tx.as_usize()) {
                crate::boot::finish_net_init(
                    rux_drivers::virtio::net::mac(),
                    |f| rux_drivers::virtio::net::send(f),
                    |b| rux_drivers::virtio::net::recv(b),
                    "virtio-net", log,
                );
            }
        }
    }
}
