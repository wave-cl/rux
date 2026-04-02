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

    // Exec /sbin/init
    let vfs = &mut *vfs_ptr;
    log("rux: exec /sbin/init\n");
    rux_proc::execargs::set(b"/bin/sh", b"");
    let init_ino = rux_fs::path::resolve_path(vfs, b"/sbin/init").expect("/sbin/init not found");
    let alloc = &mut *alloc_ptr;
    crate::elf::load_elf_from_inode(init_ino as u64, alloc);
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
