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
pub mod rtc;

// Include boot assembly: multiboot1 header + 32→64 bit transition
core::arch::global_asm!(include_str!("boot.S"), options(att_syntax));
// AP trampoline: 16-bit → long mode startup code, copied to 0x8000 at runtime
core::arch::global_asm!(include_str!("ap_trampoline.S"), options(att_syntax));

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
        let base: u64;
        core::arch::asm!("rdgsbase {}", out(reg) base, options(nostack));
        base as *mut u8
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
    const O_DIRECTORY: usize = 0x10000;
    const O_NOFOLLOW: usize = 0x20000;
    const SMP_FORK: bool = true;
    const AT_HWCAP: u64 = 0;
    // x86_64: unified I/D cache, no sync needed
}

impl rux_arch::MemoryLayout for X86_64 {
    const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000; // 128 TiB
    const INTERP_BASE: u64 = 0x40000000; // 1 GiB (above identity map)
    const PIE_BASE: u64 = 0x8000000;
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
        use rux_klib::{PhysAddr, VirtAddr};
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
        // Higher-half kernel window: every per-task user PT needs
        // the kernel text/rodata/data/bss visible at 0xffffffff80...
        // or we crash on the next kernel instruction fetch after
        // the CR3 switch into the user PT.
        const KERNEL_VMA: usize = 0xffffffff80000000;
        const HH_SIZE: usize = 128 * 1024 * 1024;
        let mut off = 0usize;
        while off < HH_SIZE {
            pt.map_2m(
                VirtAddr::new(KERNEL_VMA + off),
                PhysAddr::new(off),
                kflags,
                alloc,
            )
            .expect("high-half map");
            off += 2 * 1024 * 1024;
        }
    }
}

/// Static storage for the PCI virtio-blk driver (needs 'static for ext2 ref).
static mut VIRTIO_BLK_PCI: core::mem::MaybeUninit<rux_drivers::virtio::blk_pci::VirtioBlkPci> = core::mem::MaybeUninit::uninit();

/// Probe and initialize virtio-blk via PCI. Returns (device_ptr, capacity_sectors).
pub unsafe fn probe_blk(vq_addr: usize, log: fn(&str)) -> Option<(*const dyn rux_drivers::BlockDevice, u64)> {
    log("rux: probing PCI for virtio-blk...\n");
    match rux_drivers::virtio::blk_pci::VirtioBlkPci::probe(vq_addr) {
        Ok(blk) => {
            let cap = blk.capacity_sectors();
            (*(&raw mut VIRTIO_BLK_PCI)).write(blk);
            Some(((*(&raw const VIRTIO_BLK_PCI)).assume_init_ref() as *const _, cap))
        }
        Err(_) => { log("rux: no virtio-blk-pci device found\n"); None }
    }
}

/// Probe and initialize virtio-net via PCI. Called from boot.rs.
#[cfg(feature = "net")]
pub unsafe fn probe_and_init_net(alloc: &mut rux_mm::frame::BuddyAllocator, log: fn(&str)) {
    if rux_drivers::pci::find_device(rux_drivers::pci::VIRTIO_VENDOR, 0x1000).is_none() {
        return;
    }
    let rx_pg = alloc.alloc_order(2).ok();
    let tx_pg = alloc.alloc_order(2).ok();
    if let (Some(rx), Some(tx)) = (rx_pg, tx_pg) {
        core::ptr::write_bytes(rx.as_usize() as *mut u8, 0, 16384);
        core::ptr::write_bytes(tx.as_usize() as *mut u8, 0, 16384);
        if rux_drivers::virtio::net_pci::init(rx.as_usize(), tx.as_usize()) {
            crate::boot::finish_net_init(
                rux_drivers::virtio::net_pci::mac(),
                |f| rux_drivers::virtio::net_pci::send(f),
                |b| rux_drivers::virtio::net_pci::recv(b),
                "virtio-net-pci", log,
            );
        }
    }
}
