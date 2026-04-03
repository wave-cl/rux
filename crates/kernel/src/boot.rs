/// Generic boot sequence: create ramfs, unpack initramfs, mount procfs, exec /sbin/init.
///
/// Called from arch-specific init after hardware setup is complete.
/// The arch provides memory addresses, initrd location, and procfs callbacks.
///
/// For native (test harness) mode, use `init_native()` instead.

use rux_arch::ConsoleOps;

/// Parameters for the generic boot sequence.
pub struct BootParams {
    /// Physical address of the frame allocator.
    pub alloc_ptr: *mut rux_mm::frame::BuddyAllocator,
    /// Physical address for the RamFs.
    pub ramfs_ptr: *mut rux_fs::ramfs::RamFs,
    /// Initrd location: (start_addr, size), or None.
    pub initrd: Option<(usize, usize)>,
    /// Procfs callbacks.
    pub procfs: &'static mut rux_fs::procfs::ProcFs,
    /// Console write function for log messages.
    pub log: fn(&str),
    /// Kernel command line (from multiboot or device tree), or empty.
    pub cmdline: &'static [u8],
    /// virtio-mmio base address for block device probe, or 0.
    pub virtio_mmio_base: usize,
}

/// Boot the kernel: init ramfs, unpack cpio, mount procfs, exec /sbin/init.
///
/// # Safety
/// All pointers must be valid. Called once during boot.
#[inline(never)]
pub unsafe fn boot(params: BootParams) -> ! {
    let log = params.log;
    log("rux: init ramfs...\n");

    let ramfs_ptr = params.ramfs_ptr;
    let alloc_ptr = params.alloc_ptr;

    // Zero and init RamFs
    let fs_bytes = core::mem::size_of::<rux_fs::ramfs::RamFs>();
    core::ptr::write_bytes(ramfs_ptr as *mut u8, 0, fs_bytes);
    log("rux: zeroing done\n");

    let alloc_dyn: *mut dyn rux_mm::FrameAllocator =
        &mut *alloc_ptr as &mut dyn rux_mm::FrameAllocator;
    rux_fs::ramfs::RamFs::init_at(ramfs_ptr, alloc_dyn);
    log("rux: ramfs init done\n");

    // Unpack initramfs into ramfs
    if let Some((initrd_start, initrd_size)) = params.initrd {
        log("rux: initrd at ");
        { let mut hb = [0u8; 16]; log("0x"); crate::arch::Arch::write_bytes(rux_klib::fmt::usize_to_hex(&mut hb, initrd_start)); }
        log(" (");
        let mut buf = [0u8; 10];
        log(rux_klib::fmt::u32_to_str(&mut buf, initrd_size as u32));
        log(" bytes)\n");
        let data = core::slice::from_raw_parts(initrd_start as *const u8, initrd_size);
        rux_fs::cpio::unpack_cpio(&mut *ramfs_ptr, data, Some(log));
    } else {
        log("rux: no initrd found!\n");
    }

    // Parse kernel command line
    let cmdparams = crate::cmdline::parse(params.cmdline);

    // Wrap ramfs in VFS (ramfs is always slot 0 initially)
    let vfs_addr = (ramfs_ptr as usize + fs_bytes + 0xFFF) & !0xFFF;
    let vfs_ptr = vfs_addr as *mut rux_fs::vfs::Vfs;
    core::ptr::write_bytes(vfs_ptr as *mut u8, 0, core::mem::size_of::<rux_fs::vfs::Vfs>());
    rux_fs::vfs::Vfs::init_at(vfs_ptr, ramfs_ptr);

    // Probe for ext2 root disk if cmdline says root= or a virtio device exists
    let has_disk_root = try_mount_ext2_root(
        vfs_ptr, alloc_ptr, &cmdparams, params.virtio_mmio_base, log,
    );

    // Probe for virtio-net device (aarch64 only for now)
    #[cfg(target_arch = "aarch64")]
    {
        use rux_mm::FrameAllocator;
        let alloc = &mut *alloc_ptr;
        if let Some(net_base) = rux_drivers::virtio::net::probe_mmio() {
            let rx_pg = alloc.alloc_order(1).ok(); // 2 pages = 8KB
            let tx_pg = alloc.alloc_order(1).ok();
            if let (Some(rx), Some(tx)) = (rx_pg, tx_pg) {
                core::ptr::write_bytes(rx.as_usize() as *mut u8, 0, 8192);
                core::ptr::write_bytes(tx.as_usize() as *mut u8, 0, 8192);
                if rux_drivers::virtio::net::init_mmio(net_base, rx.as_usize(), tx.as_usize()) {
                    let mac = rux_drivers::virtio::net::mac();
                    rux_net::stack::configure(
                        [10, 0, 2, 15],   // default QEMU user-mode IP
                        [10, 0, 2, 2],    // QEMU gateway
                        [255, 255, 255, 0],
                        mac,
                    );
                    rux_net::stack::set_callbacks(
                        |src_ip, src_port, dst_port, data| {
                            crate::syscall::socket::deliver_udp(src_ip, src_port, dst_port, data);
                        },
                        |src_ip, data| {
                            crate::syscall::socket::deliver_icmp(src_ip, data);
                        },
                    );
                    log("rux: virtio-net: MAC=");
                    let mut hb = [0u8; 3];
                    for i in 0..6 {
                        let hi = mac[i] >> 4;
                        let lo = mac[i] & 0xF;
                        hb[0] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                        hb[1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                        hb[2] = if i < 5 { b':' } else { b'\n' };
                        crate::arch::Arch::write_bytes(&hb);
                    }
                }
            }
        }
    }

    // Mount procfs at /proc and devfs at /dev
    {
        use rux_fs::FileSystem;
        let vfs = &mut *vfs_ptr;
        let root = vfs.root_inode();
        let _ = vfs.mount(root, b"proc", rux_fs::vfs::MountedFs::Proc(params.procfs));
        log("rux: procfs mounted at /proc\n");

        static mut DEVFS: rux_fs::devfs::DevFs = rux_fs::devfs::DevFs::new();
        let _ = vfs.mount(root, b"dev", rux_fs::vfs::MountedFs::Dev(&raw mut DEVFS));
        log("rux: devfs mounted at /dev\n");
    }

    // Init kernel state
    crate::kstate::init(vfs_ptr, alloc_ptr);
    crate::task_table::init_pid1();
    { use rux_mm::FrameAllocator; crate::cow::init((*alloc_ptr).alloc_base()); }
    log("rux: kernel state initialized\n");

    // Exec /sbin/init (or custom init= from cmdline)
    let vfs = &mut *vfs_ptr;
    let init_path: &[u8] = if cmdparams.init_len > 0 {
        &cmdparams.init[..cmdparams.init_len]
    } else {
        b"/sbin/init"
    };
    log("rux: exec ");
    crate::arch::Arch::write_bytes(init_path);
    log("\n");
    rux_proc::execargs::set(b"/bin/sh", b"");
    let init_ino = match rux_fs::path::resolve_path(vfs, init_path) {
        Ok(ino) => ino,
        Err(e) => {
            log("rux: resolve_path(");
            crate::arch::Arch::write_bytes(init_path);
            log(") failed: ");
            log(match e {
                rux_fs::VfsError::NotFound => "not found",
                rux_fs::VfsError::NotADirectory => "not a dir",
                rux_fs::VfsError::IoError => "io error",
                rux_fs::VfsError::NotSupported => "not supported",
                _ => "other",
            });
            log("\n");
            // Try /bin/sh as fallback
            match rux_fs::path::resolve_path(vfs, b"/bin/sh") {
                Ok(ino) => { log("rux: fallback to /bin/sh\n"); ino }
                Err(_) => { log("rux: /bin/sh also failed!\n"); loop { core::hint::spin_loop(); } }
            }
        }
    };
    let alloc = &mut *alloc_ptr;
    crate::elf::load_elf_from_inode(init_ino as u64, alloc);
}

// ── ext2 root mount ──────────────────────────────────────────────────────

/// Static storage for the ext2 filesystem and virtio-blk drivers.
static mut EXT2_FS: core::mem::MaybeUninit<rux_fs::ext2::Ext2Fs> = core::mem::MaybeUninit::uninit();
static mut VIRTIO_BLK_MMIO: core::mem::MaybeUninit<rux_drivers::virtio::blk::VirtioBlk> = core::mem::MaybeUninit::uninit();
#[cfg(target_arch = "x86_64")]
static mut VIRTIO_BLK_PCI: core::mem::MaybeUninit<rux_drivers::virtio::blk_pci::VirtioBlkPci> = core::mem::MaybeUninit::uninit();

/// Try to probe a virtio-blk device and mount ext2 as root.
/// Tries PCI on x86_64, MMIO on aarch64. Falls back gracefully.
unsafe fn try_mount_ext2_root(
    vfs_ptr: *mut rux_fs::vfs::Vfs,
    alloc_ptr: *mut rux_mm::frame::BuddyAllocator,
    _cmdparams: &crate::cmdline::CmdlineParams,
    virtio_mmio_base: usize,
    log: fn(&str),
) -> bool {
    use rux_mm::FrameAllocator;
    let alloc = &mut *alloc_ptr;

    // Allocate contiguous 32KB (order 3 = 8 pages) for virtqueue.
    // Must be contiguous: the device calculates used ring offset from PFN.
    let vq_page = match alloc.alloc_order(3) {
        Ok(p) => p,
        Err(_) => { log("rux: virtio-blk: no memory for virtqueue\n"); return false; }
    };
    core::ptr::write_bytes(vq_page.as_usize() as *mut u8, 0, 32768);

    // ── Platform-specific probe ────────────────────────────────────
    let blk_dev: *const dyn rux_drivers::BlockDevice;
    let capacity: u64;

    #[cfg(target_arch = "x86_64")]
    {
        log("rux: probing PCI for virtio-blk...\n");
        match rux_drivers::virtio::blk_pci::VirtioBlkPci::probe(vq_page.as_usize()) {
            Ok(blk) => {
                capacity = blk.capacity_sectors();
                VIRTIO_BLK_PCI.write(blk);
                blk_dev = VIRTIO_BLK_PCI.assume_init_ref() as *const rux_drivers::virtio::blk_pci::VirtioBlkPci;
            }
            Err(_) => {
                log("rux: no virtio-blk-pci device found\n");
                return false;
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if virtio_mmio_base == 0 { return false; }
        let base = match rux_drivers::virtio::blk::probe_virtio_blk() {
            Some(b) => b,
            None => { log("rux: no virtio-blk device found\n"); return false; }
        };
        log("rux: virtio-blk: probing at 0x");
        { let mut hb = [0u8; 16]; crate::arch::Arch::write_bytes(rux_klib::fmt::usize_to_hex(&mut hb, base)); }
        log("\n");
        match rux_drivers::virtio::blk::VirtioBlk::new(base, vq_page.as_usize()) {
            Ok(blk) => {
                capacity = blk.capacity_sectors();
                VIRTIO_BLK_MMIO.write(blk);
                blk_dev = VIRTIO_BLK_MMIO.assume_init_ref() as *const rux_drivers::virtio::blk::VirtioBlk;
            }
            Err(_) => { log("rux: virtio-blk: init failed\n"); return false; }
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { return false; }

    log("rux: virtio-blk: ");
    { let mut buf = [0u8; 10]; log(rux_klib::fmt::u32_to_str(&mut buf, (capacity / 2048) as u32)); }
    log(" MB disk\n");

    // Mount ext2
    let ext2 = match rux_fs::ext2::Ext2Fs::mount(blk_dev) {
        Ok(fs) => fs,
        Err(_) => { log("rux: ext2: mount failed (bad superblock?)\n"); return false; }
    };
    log("rux: ext2: mounted as root (block_size=");
    { let mut buf = [0u8; 10]; log(rux_klib::fmt::u32_to_str(&mut buf, ext2.block_size)); }
    log(")\n");


    EXT2_FS.write(ext2);
    let ext2_ptr = EXT2_FS.assume_init_mut() as *mut rux_fs::ext2::Ext2Fs;
    let vfs = &mut *vfs_ptr;
    vfs.set_root(rux_fs::vfs::MountedFs::Ext2(ext2_ptr));
    true
}

// ── Native test harness init ──────────────────────────────────────────

/// Initialize kernel state for native (non-QEMU) testing.
///
/// Allocates a heap-backed frame pool, unpacks the given cpio archive into
/// a RamFs, wraps it in a VFS, and sets up the global kernel state.
/// After this call, `syscall::dispatch()` can be called directly from tests.
///
/// # Arguments
/// * `cpio_data` — raw bytes of a newc-format cpio archive (e.g. the initramfs)
///
/// # Safety
/// Must be called at most once. Single-threaded use only.
#[cfg(feature = "native")]
pub unsafe fn init_native(cpio_data: &[u8]) {
    use rux_mm::frame::BuddyAllocator;
    use rux_fs::{ramfs::RamFs, vfs::Vfs};

    // ── Frame allocator backed by heap memory ────────────────────────────
    // Allocate 32MB of heap memory as our "physical frame pool".
    let phys_size: usize = 32 * 1024 * 1024;
    let phys_mem: Box<[u8]> = vec![0u8; phys_size].into_boxed_slice();
    let phys_base = Box::into_raw(phys_mem) as *mut u8 as usize; // cast fat→thin→usize
    let phys_frames = (phys_size / 4096) as u32;

    let alloc_ptr: *mut BuddyAllocator = {
        let b: Box<[u8]> = vec![0u8; core::mem::size_of::<BuddyAllocator>()]
            .into_boxed_slice();
        let raw = Box::into_raw(b) as *mut BuddyAllocator;
        // BuddyAllocator is already zeroed; call init() to register the pool
        (*raw).init(rux_klib::PhysAddr::new(phys_base), phys_frames);
        raw
    };

    // ── RamFs ────────────────────────────────────────────────────────────
    let ramfs_size = core::mem::size_of::<RamFs>();
    let ramfs_ptr: *mut RamFs = {
        let b: Box<[u8]> = vec![0u8; ramfs_size].into_boxed_slice();
        Box::into_raw(b) as *mut RamFs
    };
    let alloc_dyn: *mut dyn rux_mm::FrameAllocator = alloc_ptr;
    RamFs::init_at(ramfs_ptr, alloc_dyn);

    // ── Unpack initramfs cpio into RamFs ─────────────────────────────────
    rux_fs::cpio::unpack_cpio(&mut *ramfs_ptr, cpio_data, None);

    // ── VFS ──────────────────────────────────────────────────────────────
    let vfs_ptr: *mut Vfs = {
        let b: Box<[u8]> = vec![0u8; core::mem::size_of::<Vfs>()].into_boxed_slice();
        Box::into_raw(b) as *mut Vfs
    };
    Vfs::init_at(vfs_ptr, ramfs_ptr);

    // ── Kernel state ──────────────────────────────────────────────────────
    crate::kstate::init(vfs_ptr, alloc_ptr);

    // ── Task table (PID 1) ────────────────────────────────────────────────
    crate::task_table::init_pid1();
    { use rux_mm::FrameAllocator; crate::cow::init((*alloc_ptr).alloc_base()); }

    // FD table console setup is done by init_pid1() which writes to
    // TASK_TABLE[0].fds and points FD_TABLE at it.

    // ── Scheduler ─────────────────────────────────────────────────────────
    crate::scheduler::init_context_fns();
}
