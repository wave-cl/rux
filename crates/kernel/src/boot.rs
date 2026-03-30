/// Generic boot sequence: create ramfs, unpack initramfs, mount procfs, exec /sbin/init.
///
/// Called from arch-specific init after hardware setup is complete.
/// The arch provides memory addresses, initrd location, and procfs callbacks.

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
    let fs_qwords = (fs_bytes + 7) / 8;
    for i in 0..fs_qwords {
        core::ptr::write_volatile((ramfs_ptr as *mut u64).add(i), 0u64);
    }
    log("rux: zeroing done\n");

    let alloc_dyn: *mut dyn rux_mm::FrameAllocator =
        &mut *alloc_ptr as &mut dyn rux_mm::FrameAllocator;
    rux_fs::ramfs::RamFs::init_at(ramfs_ptr, alloc_dyn);

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

    // Wrap ramfs in VFS
    let vfs_addr = (ramfs_ptr as usize + fs_bytes + 0xFFF) & !0xFFF;
    let vfs_ptr = vfs_addr as *mut rux_fs::vfs::Vfs;
    core::ptr::write_bytes(vfs_ptr as *mut u8, 0, core::mem::size_of::<rux_fs::vfs::Vfs>());
    rux_fs::vfs::Vfs::init_at(vfs_ptr, ramfs_ptr);

    // Mount procfs at /proc
    {
        use rux_fs::FileSystem;
        let vfs = &mut *vfs_ptr;
        let root = vfs.root_inode();
        let _ = vfs.mount(root, b"proc", rux_fs::vfs::MountedFs::Proc(params.procfs));
        log("rux: procfs mounted at /proc\n");
    }

    // Init kernel state
    crate::kstate::init(vfs_ptr, alloc_ptr);
    log("rux: kernel state initialized\n");

    // Exec /sbin/init
    let vfs = &mut *vfs_ptr;
    log("rux: exec /sbin/init\n");
    rux_proc::execargs::set(b"/bin/sh", b"");
    let init_ino = rux_fs::path::resolve_path(vfs, b"/sbin/init").expect("/sbin/init not found");
    let alloc = &mut *alloc_ptr;
    crate::elf::load_elf_from_inode(init_ino as u64, alloc);
}
