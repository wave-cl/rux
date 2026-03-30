/// aarch64 boot initialization: hardware setup, tests, and shell launch.

use super::serial;
use super::exit;
use crate::{scheduler, elf, pgtrack, COUNTER_A, COUNTER_B};

pub fn aarch64_init(dtb_addr: usize) {
    serial::write_str("rux: aarch64 running in EL1\n");

    unsafe { super::exception::init(); }
    serial::write_str("rux: exception vectors installed\n");

    unsafe { super::gic::init(); }
    serial::write_str("rux: GIC initialized\n");

    unsafe { super::timer::init(1000); }
    serial::write_str("rux: timer initialized (1000 Hz)\n");

    unsafe { super::gic::enable_irqs(); }
    serial::write_str("rux: interrupts enabled\n");

    let start = super::timer::ticks();
    while super::timer::ticks() < start + 10 {
        core::hint::spin_loop();
    }
    serial::write_str("rux: timer OK\n");

    // ── Frame allocator (hardcoded for QEMU virt -m 128M) ────────────
    serial::write_str("rux: init frame allocator...\n");
    unsafe {
        let alloc_ptr = 0x43000000 as *mut u8;
        let alloc_qwords = core::mem::size_of::<rux_mm::frame::BuddyAllocator>() / 8;
        for i in 0..alloc_qwords {
            core::ptr::write_volatile((alloc_ptr as *mut u64).add(i), 0u64);
        }
        let alloc = &mut *(alloc_ptr as *mut rux_mm::frame::BuddyAllocator);
        alloc.init(rux_klib::PhysAddr::new(0x44000000), 16384);
        serial::write_str("rux: frame allocator ready (16384 frames)\n");

        use rux_mm::FrameAllocator;
        let page = alloc.alloc(rux_mm::PageSize::FourK).expect("alloc");
        alloc.dealloc(page, rux_mm::PageSize::FourK);
        serial::write_str("rux: alloc/dealloc OK\n");

        // Slab test
        let mut task_slab = rux_mm::Slab::new(1024);
        let a = task_slab.alloc(alloc).expect("slab A");
        let b = task_slab.alloc(alloc).expect("slab B");
        task_slab.dealloc(b);
        let c = task_slab.alloc(alloc).expect("slab C");
        if c != b {
            serial::write_str("FAIL: slab\n");
            exit::exit_qemu(exit::EXIT_FAILURE);
        }
        task_slab.dealloc(a);
        task_slab.dealloc(c);
        serial::write_str("rux: slab OK\n");

        // Page table map/translate/unmap
        let mut pt = super::paging::PageTable4Level::new(alloc).expect("pt");
        let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("frame");
        let virt = rux_klib::VirtAddr::new(0xA000_0000);
        let flags = rux_mm::MappingFlags::READ.or(rux_mm::MappingFlags::WRITE);
        pt.map_4k(virt, frame, flags, alloc).expect("map");
        let t = pt.translate(virt).expect("translate");
        if t.as_usize() != frame.as_usize() {
            serial::write_str("FAIL: translate\n");
            exit::exit_qemu(exit::EXIT_FAILURE);
        }
        pt.unmap_4k(virt).expect("unmap");
        if pt.translate(virt).is_ok() {
            serial::write_str("FAIL: unmap\n");
            exit::exit_qemu(exit::EXIT_FAILURE);
        }
        alloc.dealloc(frame, rux_mm::PageSize::FourK);
        serial::write_str("rux: page table OK\n");

        // Build kernel page tables and enable MMU
        serial::write_str("rux: building kernel page tables...\n");
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
        serial::write_str("rux: MMU enabled, kernel page tables active!\n");

        // Process lifecycle
        let p = task_slab.alloc(alloc).expect("p") as *mut rux_proc::task::Task;
        core::ptr::write(p, rux_proc::task::Task::new(
            rux_proc::id::Pid::new(1), rux_proc::id::Tgid::new(1)));
        let ch = task_slab.alloc(alloc).expect("ch") as *mut rux_proc::task::Task;
        core::ptr::write(ch, rux_proc::task::Task::new(
            rux_proc::id::Pid::new(2), rux_proc::id::Tgid::new(2)));
        (*ch).ppid = (*p).pid;
        (*ch).exit_code = (42 & 0xFF) << 8;
        (*ch).sched.state = rux_sched::TaskState::Zombie;
        let code = ((*ch).exit_code >> 8) & 0xFF;
        if code != 42 {
            serial::write_str("FAIL: exit code\n");
            exit::exit_qemu(exit::EXIT_FAILURE);
        }
        task_slab.dealloc(p as *mut u8);
        task_slab.dealloc(ch as *mut u8);
        serial::write_str("rux: process lifecycle OK\n");
    }

    // ── Context switch test ─────────────────────────────────────────
    serial::write_str("rux: context switch test...\n");
    unsafe {
        static mut STACK_B: [u8; 65536] = [0; 65536];
        let stack_top = STACK_B.as_ptr() as usize + 65536;
        let task_b_rsp = super::context::init_task_stack(stack_top, aarch64_task_b as usize, 0);
        super::context::context_switch(&raw mut MAIN_RSP_AA64, task_b_rsp);
        serial::write_str("rux: back in main task\n");
    }

    // ── Preemptive scheduling test ──────────────────────────────────
    serial::write_str("rux: preemptive scheduler test...\n");
    unsafe {
        scheduler::init_context_fns();
        use rux_sched::SchedClassOps;
        let sched = scheduler::get();
        static mut SCHED_STACK_A: [u8; 65536] = [0; 65536];
        static mut SCHED_STACK_B: [u8; 65536] = [0; 65536];
        sched.create_task(
            aarch64_counter_a, SCHED_STACK_A.as_ptr() as usize + 65536, 0,
        );
        sched.create_task(
            aarch64_counter_b, SCHED_STACK_B.as_ptr() as usize + 65536, 5,
        );
        serial::write_str("rux: created tasks A and B\n");
        sched.need_resched = true;
        sched.schedule();
    }

    let a_count = COUNTER_A.load(core::sync::atomic::Ordering::Relaxed);
    let b_count = COUNTER_B.load(core::sync::atomic::Ordering::Relaxed);
    let mut buf = [0u8; 10];
    serial::write_str("rux: task A count: ");
    serial::write_str(rux_klib::fmt::u32_to_str(&mut buf, a_count));
    serial::write_str(", task B count: ");
    serial::write_str(rux_klib::fmt::u32_to_str(&mut buf, b_count));
    serial::write_str("\n");
    if a_count > 0 && b_count > 0 {
        serial::write_str("rux: preemptive scheduling OK!\n");
    } else {
        serial::write_str("FAIL: preemptive scheduling\n");
        exit::exit_qemu(exit::EXIT_FAILURE);
    }

    // ── RamFs + initramfs + exec /sbin/init ──────────────────────
    unsafe { init_ramfs_and_exec(dtb_addr); }
}

#[inline(never)]
unsafe fn init_ramfs_and_exec(dtb_addr: usize) -> ! {
    use rux_vfs::FileSystem;

    serial::write_str("rux: init ramfs...\n");
    let alloc_ptr = 0x43000000 as *mut rux_mm::frame::BuddyAllocator;
    let alloc_size = core::mem::size_of::<rux_mm::frame::BuddyAllocator>();
    let fs_addr = (0x43000000 + alloc_size + 0xFFF) & !0xFFF;
    let fs_ptr = fs_addr as *mut rux_vfs::ramfs::RamFs;

    let fs_bytes = core::mem::size_of::<rux_vfs::ramfs::RamFs>();
    let fs_qwords = (fs_bytes + 7) / 8;
    for i in 0..fs_qwords {
        core::ptr::write_volatile((fs_ptr as *mut u64).add(i), 0u64);
    }
    serial::write_str("rux: zeroing done\n");

    let alloc_dyn: *mut dyn rux_mm::FrameAllocator =
        &mut *alloc_ptr as &mut dyn rux_mm::FrameAllocator;
    rux_vfs::ramfs::RamFs::init_at(fs_ptr, alloc_dyn);
    let fs = &mut *fs_ptr;

    // Unpack initramfs from DTB /chosen node (passed via -initrd)
    // Find initramfs: try DTB first, then scan RAM for cpio magic.
    let initrd = if dtb_addr != 0 {
        super::devicetree::get_initrd(dtb_addr)
    } else {
        None
    }.or_else(|| find_cpio_in_ram(0x44100000, 0x47F00000));
    if let Some((initrd_start, initrd_size)) = initrd {
        serial::write_str("rux: initrd at ");
        { let mut __hb = [0u8; 16]; serial::write_str("0x"); serial::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, initrd_start)); }
        serial::write_str(" (");
        let mut buf = [0u8; 10];
        serial::write_str(rux_klib::fmt::u32_to_str(&mut buf, initrd_size as u32));
        serial::write_str(" bytes)\n");
        let data = core::slice::from_raw_parts(initrd_start as *const u8, initrd_size);
        rux_vfs::cpio::unpack_cpio(fs, data, Some(serial::write_str));
    } else {
        serial::write_str("rux: no initrd found!\n");
    }

    crate::kstate::init(fs_ptr, alloc_ptr);
    serial::write_str("rux: kernel state initialized\n");

    serial::write_str("rux: exec /sbin/init\n");
    crate::execargs::set(b"/bin/sh", b"");
    let init_ino = rux_vfs::path::resolve_path(fs, b"/sbin/init").expect("/sbin/init not found");
    let alloc = &mut *alloc_ptr;
    elf::load_elf_from_inode(init_ino as u64, alloc);
}

/// Scan RAM for a cpio newc archive (magic "070701").
/// Returns (start_addr, size) if found. Uses all remaining mapped RAM
/// as the size since scanning for TRAILER is unreliable (binary data
/// may contain that string).
unsafe fn find_cpio_in_ram(start: usize, end: usize) -> Option<(usize, usize)> {
    let magic = *b"070701";
    let mut addr = start;
    while addr + 6 < end {
        let p = addr as *const [u8; 6];
        if *p == magic {
            let size = end - addr;
            serial::write_str("rux: initrd found at ");
            { let mut __hb = [0u8; 16]; serial::write_str("0x"); serial::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, addr)); }
            serial::write_str(" (");
            let mut buf = [0u8; 10];
            serial::write_str(rux_klib::fmt::u32_to_str(&mut buf, size as u32));
            serial::write_str(" bytes)\n");
            return Some((addr, size));
        }
        addr += 4096;
    }
    None
}

static mut MAIN_RSP_AA64: usize = 0;

extern "C" fn aarch64_task_b() {
    serial::write_str("rux: task B running!\n");
    unsafe {
        static mut TASK_B_RSP: usize = 0;
        super::context::context_switch(&raw mut TASK_B_RSP, MAIN_RSP_AA64);
    }
    loop { core::hint::spin_loop(); }
}

fn aarch64_maybe_yield() {
    unsafe {
        let sched = scheduler::get();
        if sched.need_resched {
            sched.schedule();
        }
    }
}

fn aarch64_task_exit() -> ! {
    unsafe {
        use rux_sched::SchedClassOps;
        let sched = scheduler::get();
        let idx = sched.current;
        sched.tasks[idx].active = false;
        sched.tasks[idx].entity.state = rux_sched::TaskState::Dead;
        sched.cfs.dequeue(0, &mut sched.tasks[idx].entity, 0);
        sched.need_resched = true;
        sched.schedule();
    }
    loop { core::hint::spin_loop(); }
}

extern "C" fn aarch64_counter_a() {
    for _ in 0..100_000 {
        COUNTER_A.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        aarch64_maybe_yield();
    }
    serial::write_str("rux: task A done\n");
    aarch64_task_exit();
}

extern "C" fn aarch64_counter_b() {
    for _ in 0..100_000 {
        COUNTER_B.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        aarch64_maybe_yield();
    }
    serial::write_str("rux: task B done\n");
    aarch64_task_exit();
}
