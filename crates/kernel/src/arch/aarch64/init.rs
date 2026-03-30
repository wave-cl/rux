/// aarch64 boot initialization: hardware setup and shell launch.

use super::console;
use super::exit;
use crate::{scheduler, elf, pgtrack};

pub fn aarch64_init(dtb_addr: usize) {
    console::write_str("rux: aarch64 running in EL1\n");

    unsafe { super::exception::init(); }
    console::write_str("rux: exception vectors installed\n");

    unsafe { super::gic::init(); }
    console::write_str("rux: GIC initialized\n");

    unsafe { super::timer::init(1000); }
    console::write_str("rux: timer initialized (1000 Hz)\n");

    unsafe { super::gic::enable_irqs(); }
    console::write_str("rux: interrupts enabled\n");

    // ── Frame allocator (hardcoded for QEMU virt -m 128M) ────────────
    console::write_str("rux: init frame allocator...\n");
    unsafe {
        let alloc_ptr = 0x43000000 as *mut u8;
        let alloc_qwords = core::mem::size_of::<rux_mm::frame::BuddyAllocator>() / 8;
        for i in 0..alloc_qwords {
            core::ptr::write_volatile((alloc_ptr as *mut u64).add(i), 0u64);
        }
        let alloc = &mut *(alloc_ptr as *mut rux_mm::frame::BuddyAllocator);
        alloc.init(rux_klib::PhysAddr::new(0x44000000), 16384);
        console::write_str("rux: frame allocator ready\n");

        // ── Kernel page tables + enable MMU ────────────────────────────
        console::write_str("rux: building kernel page tables...\n");
        let rwx = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::EXECUTE);
        let mut kpt = super::paging::PageTable4Level::new(alloc).expect("kpt");
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x40000000), 128 * 1024 * 1024, rwx, alloc,
        ).expect("identity map");
        let dev_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::NO_CACHE);
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x08000000), 0x20000, dev_flags, alloc,
        ).expect("gic map");
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x09000000), 0x1000, dev_flags, alloc,
        ).expect("uart map");

        super::paging::activate(&kpt);
        pgtrack::set_kernel_pt(kpt.root_phys().as_usize() as u64);
        console::write_str("rux: MMU enabled, kernel page tables active!\n");
    }

    // ── Init scheduler (needed for vfork/exec) ──────────────────────
    unsafe { scheduler::init_context_fns(); }

    // ── RamFs + initramfs + exec /sbin/init ──────────────────────
    unsafe { init_ramfs_and_exec(dtb_addr); }
}

#[inline(never)]
unsafe fn init_ramfs_and_exec(dtb_addr: usize) -> ! {
    use rux_fs::FileSystem;

    console::write_str("rux: init ramfs...\n");
    let alloc_ptr = 0x43000000 as *mut rux_mm::frame::BuddyAllocator;
    let alloc_size = core::mem::size_of::<rux_mm::frame::BuddyAllocator>();
    let ramfs_addr = (0x43000000 + alloc_size + 0xFFF) & !0xFFF;
    let ramfs_ptr = ramfs_addr as *mut rux_fs::ramfs::RamFs;

    let fs_bytes = core::mem::size_of::<rux_fs::ramfs::RamFs>();
    let fs_qwords = (fs_bytes + 7) / 8;
    for i in 0..fs_qwords {
        core::ptr::write_volatile((ramfs_ptr as *mut u64).add(i), 0u64);
    }
    console::write_str("rux: zeroing done\n");

    let alloc_dyn: *mut dyn rux_mm::FrameAllocator =
        &mut *alloc_ptr as &mut dyn rux_mm::FrameAllocator;
    rux_fs::ramfs::RamFs::init_at(ramfs_ptr, alloc_dyn);

    // Find and unpack initramfs into ramfs (before VFS wrapping)
    let initrd = if dtb_addr != 0 {
        super::devicetree::get_initrd(dtb_addr)
    } else {
        None
    }.or_else(|| find_cpio_in_ram(0x44100000, 0x47F00000));
    if let Some((initrd_start, initrd_size)) = initrd {
        console::write_str("rux: initrd at ");
        { let mut hb = [0u8; 16]; console::write_str("0x"); console::write_bytes(rux_klib::fmt::usize_to_hex(&mut hb, initrd_start)); }
        console::write_str(" (");
        let mut buf = [0u8; 10];
        console::write_str(rux_klib::fmt::u32_to_str(&mut buf, initrd_size as u32));
        console::write_str(" bytes)\n");
        let data = core::slice::from_raw_parts(initrd_start as *const u8, initrd_size);
        rux_fs::cpio::unpack_cpio(&mut *ramfs_ptr, data, Some(console::write_str));
    } else {
        console::write_str("rux: no initrd found!\n");
    }

    // Wrap ramfs in VFS dispatch layer
    let vfs_addr = (ramfs_addr + fs_bytes + 0xFFF) & !0xFFF;
    let vfs_ptr = vfs_addr as *mut rux_fs::vfs::Vfs;
    core::ptr::write_bytes(vfs_ptr as *mut u8, 0, core::mem::size_of::<rux_fs::vfs::Vfs>());
    rux_fs::vfs::Vfs::init_at(vfs_ptr, ramfs_ptr);

    crate::kstate::init(vfs_ptr, alloc_ptr);
    console::write_str("rux: kernel state initialized\n");

    let vfs = &mut *vfs_ptr;
    console::write_str("rux: exec /sbin/init\n");
    crate::execargs::set(b"/bin/sh", b"");
    let init_ino = rux_fs::path::resolve_path(vfs, b"/sbin/init").expect("/sbin/init not found");
    let alloc = &mut *alloc_ptr;
    elf::load_elf_from_inode(init_ino as u64, alloc);
}

/// Scan RAM for a cpio newc archive (magic "070701").
unsafe fn find_cpio_in_ram(start: usize, end: usize) -> Option<(usize, usize)> {
    let magic = *b"070701";
    let mut addr = start;
    while addr + 6 < end {
        let p = addr as *const [u8; 6];
        if *p == magic {
            let size = end - addr;
            console::write_str("rux: initrd found at ");
            { let mut hb = [0u8; 16]; console::write_str("0x"); console::write_bytes(rux_klib::fmt::usize_to_hex(&mut hb, addr)); }
            console::write_str(" (");
            let mut buf = [0u8; 10];
            console::write_str(rux_klib::fmt::u32_to_str(&mut buf, size as u32));
            console::write_str(" bytes)\n");
            return Some((addr, size));
        }
        addr += 4096;
    }
    None
}
