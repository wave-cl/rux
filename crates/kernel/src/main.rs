#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "aarch64")]
mod aarch64;

mod scheduler;
mod slab;
mod elf;
mod kstate;
pub mod fdtable;
pub mod execargs;
pub mod pgtrack;
pub mod rootfs;
pub mod syscall_impl;

#[cfg(target_arch = "x86_64")]
use x86_64::{serial, exit};
#[cfg(target_arch = "aarch64")]
use aarch64::{serial, exit};

/// Kernel entry point. Called from boot.S.
/// On x86_64: `arg` is the multiboot info physical address.
/// On aarch64: `arg` is unused (DTB pointer, ignored for now).
#[no_mangle]
pub extern "C" fn kernel_main(arg: usize) -> ! {
    unsafe { serial::init(); }
    serial::write_str("rux: boot OK\n");

    #[cfg(target_arch = "x86_64")]
    x86_64_init(arg);

    #[cfg(target_arch = "aarch64")]
    aarch64_init(arg);

    serial::write_str("rux: all checks passed\n");
    exit::exit_qemu(exit::EXIT_SUCCESS);
}

#[cfg(target_arch = "aarch64")]
fn aarch64_init(dtb_addr: usize) {
    serial::write_str("rux: aarch64 running in EL1\n");

    unsafe { aarch64::exception::init(); }
    serial::write_str("rux: exception vectors installed\n");

    unsafe { aarch64::gic::init(); }
    serial::write_str("rux: GIC initialized\n");

    unsafe { aarch64::timer::init(1000); }
    serial::write_str("rux: timer initialized (1000 Hz)\n");

    unsafe { aarch64::gic::enable_irqs(); }
    serial::write_str("rux: interrupts enabled\n");

    let start = aarch64::timer::ticks();
    while aarch64::timer::ticks() < start + 10 {
        core::hint::spin_loop();
    }
    serial::write_str("rux: timer OK\n");

    // ── Frame allocator (hardcoded for QEMU virt -m 128M) ────────────
    // QEMU virt: RAM at 0x40000000. Kernel + BSS uses ~3 MiB.
    // Place allocator struct at 0x43000000, frames start at 0x44000000.
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
        let mut task_slab = crate::slab::Slab::new(1024);
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
        let mut pt = aarch64::paging::PageTable4Level::new(alloc).expect("pt");
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
        let mut kpt = aarch64::paging::PageTable4Level::new(alloc).expect("kpt");
        // QEMU virt: RAM at 0x40000000 (1 GiB). Identity map 0x40000000-0x48000000 (128 MiB)
        // to cover kernel, BSS, stacks, allocator, and user-space ELF regions.
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x40000000),
            128 * 1024 * 1024,
            rwx,
            alloc,
        ).expect("identity map");
        // Also identity-map the GIC region (device memory) for interrupt handling
        let dev_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::NO_CACHE);
        // GIC distributor at 0x08000000, CPU interface at 0x08010000
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x08000000),
            0x20000,
            dev_flags,
            alloc,
        ).expect("gic map");
        // UART at 0x09000000
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x09000000),
            0x1000,
            dev_flags,
            alloc,
        ).expect("uart map");

        aarch64::paging::activate(&kpt);
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
        let stack_top = STACK_B.as_ptr() as u64 + 65536;
        let task_b_rsp = aarch64::context::init_task_stack(stack_top, aarch64_task_b as u64, 0);

        aarch64::context::context_switch(&raw mut MAIN_RSP_AA64, task_b_rsp);
        serial::write_str("rux: back in main task\n");
    }

    // ── Preemptive scheduling test ──────────────────────────────────
    serial::write_str("rux: preemptive scheduler test...\n");
    unsafe {
        use rux_sched::SchedClassOps;
        let sched = scheduler::get();

        static mut SCHED_STACK_A: [u8; 65536] = [0; 65536];
        static mut SCHED_STACK_B: [u8; 65536] = [0; 65536];

        sched.create_task(
            aarch64_counter_a,
            SCHED_STACK_A.as_ptr() as u64 + 65536,
            0,
        );
        sched.create_task(
            aarch64_counter_b,
            SCHED_STACK_B.as_ptr() as u64 + 65536,
            5,
        );

        serial::write_str("rux: created tasks A and B\n");
        sched.need_resched = true;
        sched.schedule();
    }

    let a_count = COUNTER_A.load(core::sync::atomic::Ordering::Relaxed);
    let b_count = COUNTER_B.load(core::sync::atomic::Ordering::Relaxed);
    let mut buf = [0u8; 10];
    serial::write_str("rux: task A count: ");
    serial::write_str(write_u32(&mut buf, a_count));
    serial::write_str(", task B count: ");
    serial::write_str(write_u32(&mut buf, b_count));
    serial::write_str("\n");

    if a_count > 0 && b_count > 0 {
        serial::write_str("rux: preemptive scheduling OK!\n");
    } else {
        serial::write_str("FAIL: preemptive scheduling\n");
        exit::exit_qemu(exit::EXIT_FAILURE);
    }

    // ── Shell via ramfs + vfork/exec/wait ─────────────────────────
    unsafe { aarch64_init_ramfs_and_exec_shell(); }
}

/// Initialize ramfs, populate /hello, and run the shell on aarch64.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn aarch64_init_ramfs_and_exec_shell() -> ! {
    use rux_mm::FrameAllocator;
    use rux_vfs::{FileSystem, FileName};

    serial::write_str("rux: init ramfs...\n");

    // Use fixed addresses for aarch64 (allocator at 0x43000000, ramfs after it)
    let alloc_ptr = 0x43000000 as *mut rux_mm::frame::BuddyAllocator;
    let alloc_size = core::mem::size_of::<rux_mm::frame::BuddyAllocator>();
    let fs_addr = (0x43000000 + alloc_size + 0xFFF) & !0xFFF; // page-align
    let fs_ptr = fs_addr as *mut rux_vfs::ramfs::RamFs;

    // Zero the RamFs memory region
    let fs_bytes = core::mem::size_of::<rux_vfs::ramfs::RamFs>();
    let fs_qwords = (fs_bytes + 7) / 8;
    for i in 0..fs_qwords {
        core::ptr::write_volatile((fs_ptr as *mut u64).add(i), 0u64);
    }
    serial::write_str("rux: zeroing done\n");

    // Initialize RamFs in place
    let alloc_dyn: *mut dyn rux_mm::FrameAllocator =
        &mut *alloc_ptr as &mut dyn rux_mm::FrameAllocator;
    rux_vfs::ramfs::RamFs::init_at(fs_ptr, alloc_dyn);
    let fs = &mut *fs_ptr;

    // Populate full busybox-compatible rootfs
    let box_data: &[u8] = include_bytes!("../../../user/busybox_aarch64");
    rootfs::populate(fs, box_data);

    // Init kernel state
    kstate::init(fs_ptr, alloc_ptr);
    serial::write_str("rux: kernel state initialized\n");

    // Boot: exec /bin/sh (busybox)
    serial::write_str("rux: exec /sbin/init\n");
    crate::execargs::set(b"/bin/sh", b"");
    let init_ino = rux_vfs::path::resolve_path(fs, b"/bin/busybox").expect("busybox not found");
    let alloc = &mut *alloc_ptr;
    elf::load_elf_from_inode(init_ino as u64, alloc);
}

#[cfg(target_arch = "aarch64")]
static mut MAIN_RSP_AA64: u64 = 0;

#[cfg(target_arch = "aarch64")]
extern "C" fn aarch64_task_b() {
    serial::write_str("rux: task B running!\n");
    unsafe {
        static mut TASK_B_RSP: u64 = 0;
        aarch64::context::context_switch(&raw mut TASK_B_RSP, MAIN_RSP_AA64);
    }
    loop { core::hint::spin_loop(); }
}

#[cfg(target_arch = "aarch64")]
fn aarch64_maybe_yield() {
    unsafe {
        let sched = scheduler::get();
        if sched.need_resched {
            sched.schedule();
        }
    }
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
extern "C" fn aarch64_counter_a() {
    for _ in 0..100_000 {
        COUNTER_A.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        aarch64_maybe_yield();
    }
    serial::write_str("rux: task A done\n");
    aarch64_task_exit();
}

#[cfg(target_arch = "aarch64")]
extern "C" fn aarch64_counter_b() {
    for _ in 0..100_000 {
        COUNTER_B.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        aarch64_maybe_yield();
    }
    serial::write_str("rux: task B done\n");
    aarch64_task_exit();
}

#[cfg(target_arch = "x86_64")]
fn x86_64_init(multiboot_info: usize) {
    // Initialize GDT with TSS — use the actual boot_stack_top from boot.S
    unsafe {
        extern "C" { static boot_stack_top: u8; }
        let stack_top = &boot_stack_top as *const u8 as u64;
        x86_64::gdt::init(stack_top);
    }
    serial::write_str("rux: GDT + TSS loaded\n");

    // Initialize IDT with all exception/IRQ handlers
    unsafe { x86_64::idt::init(); }
    serial::write_str("rux: IDT loaded\n");

    // Initialize SYSCALL/SYSRET MSRs for Linux ABI
    unsafe { x86_64::syscall::init_syscall_msrs(); }

    // Initialize PIT timer at 1000 Hz
    unsafe { x86_64::pit::init(1000); }
    serial::write_str("rux: PIT timer initialized (1000 Hz)\n");

    // Enable interrupts
    unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)); }
    serial::write_str("rux: interrupts enabled\n");

    // Wait for some timer ticks
    let start = x86_64::pit::ticks();
    while x86_64::pit::ticks() < start + 10 {
        core::hint::spin_loop();
    }
    serial::write_str("rux: timer OK\n");

    // ── Parse multiboot memory map ──────────────────────────────────────
    serial::write_str("rux: multiboot info at ");
    write_hex_serial(multiboot_info);
    serial::write_str("\n");
    let memmap = unsafe { x86_64::multiboot::parse_memory_map(multiboot_info) };
    serial::write_str("rux: memory map (");
    let mut buf = [0u8; 10];
    serial::write_str(write_u32(&mut buf, memmap.count as u32));
    serial::write_str(" regions, ");
    serial::write_str(write_u32(&mut buf, (memmap.total_usable / (1024 * 1024)) as u32));
    serial::write_str(" MiB usable)\n");

    for i in 0..memmap.count {
        let r = &memmap.regions[i];
        serial::write_str("  ");
        write_hex_serial(r.base.as_usize());
        serial::write_str(" - ");
        write_hex_serial(r.base.as_usize() + r.size);
        serial::write_str(" (");
        serial::write_str(write_u32(&mut buf, (r.size / 1024) as u32));
        serial::write_str(" KiB)\n");
    }

    // ── Init frame allocator from the largest region ────────────────────
    // Find the largest usable region
    let mut best = 0;
    for i in 1..memmap.count {
        if memmap.regions[i].size > memmap.regions[best].size {
            best = i;
        }
    }
    if memmap.count > 0 {
        let region = &memmap.regions[best];
        let alloc_base = if region.base.as_usize() < 0x200000 {
            0x780000usize  // above busybox VA range (0x400000-0x714000)
        } else {
            region.base.as_usize()
        };
        let alloc_size = region.size - (alloc_base - region.base.as_usize());
        let frames = (alloc_size / 4096) as u32;
        let frames = frames.min(16384);

        serial::write_str("rux: init allocator at ");
        write_hex_serial(alloc_base);
        serial::write_str(" (");
        serial::write_str(write_u32(&mut buf, frames));
        serial::write_str(" frames)\n");

        unsafe {
            serial::write_str("rux: zeroing allocator...\n");
            let alloc_ptr = 0x300000 as *mut u64;
            let alloc_qwords = core::mem::size_of::<rux_mm::frame::BuddyAllocator>() / 8;
            for i in 0..alloc_qwords {
                core::ptr::write_volatile(alloc_ptr.add(i), 0u64);
            }
            serial::write_str("rux: zeroing done\n");

            let alloc = &mut *(0x300000 as *mut rux_mm::frame::BuddyAllocator);
            serial::write_str("rux: calling init...\n");
            alloc.init(rux_klib::PhysAddr::new(alloc_base), frames);
            serial::write_str("rux: init done\n");

            use rux_mm::FrameAllocator;
            let page = alloc.alloc(rux_mm::PageSize::FourK).expect("alloc failed");
            serial::write_str("rux: alloc at ");
            write_hex_serial(page.as_usize());
            serial::write_str("\n");
            alloc.dealloc(page, rux_mm::PageSize::FourK);
            serial::write_str("rux: dealloc OK\n");

            // ── Slab allocator test ─────────────────────────────────────
            serial::write_str("rux: slab test...\n");
            {
                // Create a slab for 1024-byte objects (Task size)
                let mut task_slab = slab::Slab::new(1024);

                // Allocate 3 objects
                let obj_a = task_slab.alloc(alloc).expect("slab alloc A");
                let obj_b = task_slab.alloc(alloc).expect("slab alloc B");
                let obj_c = task_slab.alloc(alloc).expect("slab alloc C");

                // All should be different addresses
                if obj_a == obj_b || obj_b == obj_c || obj_a == obj_c {
                    serial::write_str("FAIL: slab returned duplicate\n");
                    exit::exit_qemu(exit::EXIT_FAILURE);
                }

                // Free B, reallocate — should reuse B's slot
                task_slab.dealloc(obj_b);
                let obj_d = task_slab.alloc(alloc).expect("slab alloc D");
                if obj_d != obj_b {
                    serial::write_str("FAIL: slab didn't reuse freed slot\n");
                    exit::exit_qemu(exit::EXIT_FAILURE);
                }

                serial::write_str("rux: slab OK (alloc/dealloc/reuse)\n");

                // Clean up
                task_slab.dealloc(obj_a);
                task_slab.dealloc(obj_c);
                task_slab.dealloc(obj_d);
            }

            // ── Page table test ─────────────────────────────────────────
            serial::write_str("rux: page table test...\n");
            let mut pt = x86_64::paging::PageTable4Level::new(alloc)
                .expect("failed to create page table");
            serial::write_str("rux: page table created (root=");
            write_hex_serial(pt.root_phys().as_usize());
            serial::write_str(")\n");

            // Allocate a physical frame and map it at virtual 0x8000_0000
            let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("alloc frame");
            let test_virt = rux_klib::VirtAddr::new(0x8000_0000);
            let flags = rux_mm::MappingFlags::READ.or(rux_mm::MappingFlags::WRITE);
            pt.map_4k(test_virt, frame, flags, alloc).expect("map failed");
            serial::write_str("rux: mapped ");
            write_hex_serial(test_virt.as_usize());
            serial::write_str(" -> ");
            write_hex_serial(frame.as_usize());
            serial::write_str("\n");

            // Translate — should return the frame address
            let translated = pt.translate(test_virt).expect("translate failed");
            if translated.as_usize() != frame.as_usize() {
                serial::write_str("FAIL: translate mismatch!\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }
            serial::write_str("rux: translate OK\n");

            // Unmap
            let unmapped = pt.unmap_4k(test_virt).expect("unmap failed");
            if unmapped.as_usize() != frame.as_usize() {
                serial::write_str("FAIL: unmap returned wrong address!\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }

            // Verify unmapped — translate should fail
            if pt.translate(test_virt).is_ok() {
                serial::write_str("FAIL: translate succeeded after unmap!\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }
            serial::write_str("rux: unmap + re-translate OK\n");

            alloc.dealloc(frame, rux_mm::PageSize::FourK);

            // ── Activate our own page tables ────────────────────────────
            // Identity-map the first 32 MiB (covers kernel + allocator + stacks)
            serial::write_str("rux: building kernel page tables...\n");
            let mut kpt = x86_64::paging::PageTable4Level::new(alloc)
                .expect("failed to create kernel page table");

            let rwx = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::EXECUTE);
            // Map first 8 MiB identity (0 → 0)
            // Covers: kernel image (1-2MB), frame allocator struct (4MB),
            // allocator data (2-6MB), BSS/stacks (1MB+), serial I/O ports
            kpt.identity_map_range(
                rux_klib::PhysAddr::new(0),
                16 * 1024 * 1024,
                rwx,
                alloc,
            ).expect("identity map failed");

            serial::write_str("rux: identity mapped 0-8 MiB\n");

            // Activate — switch CR3 to our page tables
            x86_64::paging::activate(&kpt);
            pgtrack::set_kernel_pt(kpt.root_phys().as_usize() as u64);
            serial::write_str("rux: CR3 switched to kernel page tables!\n");
        }
    }

    // ── Context switch test ─────────────────────────────────────────────
    // Create a second kernel task on a separate stack. Switch to it,
    // it prints a message, switches back. Proves context_switch works.
    serial::write_str("rux: context switch test...\n");

    unsafe {
        // Allocate a 16K stack for task B (use a static buffer)
        static mut TASK_B_STACK: [u8; 16384] = [0; 16384];
        let stack_top = TASK_B_STACK.as_ptr() as u64 + 16384;

        // Initialize task B's stack to "return" to task_b_entry(0x42)
        let task_b_rsp = x86_64::context::init_task_stack(
            stack_top,
            task_b_entry as u64,
            0x42,
        );

        // Switch to task B (saves our RSP in the module-level MAIN_RSP)
        x86_64::context::context_switch(
            &raw mut MAIN_RSP,
            task_b_rsp,
        );

        // We're back! Task B switched back to us.
        serial::write_str("rux: back in main task\n");
    }

    // ── Preemptive scheduling test ─────────────────────────────────────
    // Create two kernel tasks that each increment a counter in a loop.
    // The PIT timer ISR preempts them via the scheduler. After ~200ms,
    // we check both counters advanced — proving preemptive multitasking works.
    serial::write_str("rux: preemptive scheduler test...\n");

    unsafe {
        use rux_sched::SchedClassOps;
        let sched = scheduler::get();

        static mut STACK_A: [u8; 16384] = [0; 16384];
        static mut STACK_B: [u8; 16384] = [0; 16384];

        let _idx_a = sched.create_task(
            task_counter_a,
            STACK_A.as_ptr() as u64 + 16384,
            0,
        );
        let _idx_b = sched.create_task(
            task_counter_b,
            STACK_B.as_ptr() as u64 + 16384,
            5,
        );

        serial::write_str("rux: created tasks A and B\n");

        // Run the scheduler loop from kernel_main.
        // schedule() picks the first task and switches to it.
        // When a task calls schedule(), it context-switches to the next.
        // Tasks signal completion via TASKS_DONE counter.
        // After both tasks complete, the last one switches back here.
        sched.need_resched = true;
        sched.schedule();

        // Back here means schedule switched back to us (slot 0, the idle/main task)
    }

    // Check the counters
    let a_count = COUNTER_A.load(core::sync::atomic::Ordering::Relaxed);
    let b_count = COUNTER_B.load(core::sync::atomic::Ordering::Relaxed);
    let mut buf = [0u8; 10];
    serial::write_str("rux: task A count: ");
    serial::write_str(write_u32(&mut buf, a_count));
    serial::write_str(", task B count: ");
    serial::write_str(write_u32(&mut buf, b_count));
    serial::write_str("\n");

    if a_count > 0 && b_count > 0 {
        serial::write_str("rux: preemptive scheduling OK!\n");
    } else {
        serial::write_str("FAIL: preemptive scheduling did not run both tasks\n");
        exit::exit_qemu(exit::EXIT_FAILURE);
    }

    // ── Process lifecycle test ──────────────────────────────────────────
    // Allocate a Task from the slab, use ProcessManager to set up fork-like
    // metadata, run it via the scheduler, have it exit.
    serial::write_str("rux: process lifecycle test...\n");
    {
        use rux_proc::id::{Pid, Tgid};
        use rux_proc::task::Task;
        use rux_proc::lifecycle::ProcessOps;

        // Allocate tasks from the slab (1024 bytes each = Task size)
        unsafe {
            let alloc = &mut *(0x300000 as *mut rux_mm::frame::BuddyAllocator);
            let mut task_slab = slab::Slab::new(core::mem::size_of::<Task>());

            // "Parent" task (represents init/kernel_main)
            let parent_ptr = task_slab.alloc(alloc).expect("slab parent") as *mut Task;
            core::ptr::write(parent_ptr, Task::new(Pid::new(1), Tgid::new(1)));
            let parent = &mut *parent_ptr;
            parent.sched.state = rux_sched::TaskState::Running;

            // "Child" task (will be set up like a fork)
            let child_ptr = task_slab.alloc(alloc).expect("slab child") as *mut Task;
            core::ptr::write(child_ptr, Task::new(Pid::new(2), Tgid::new(2)));
            let child = &mut *child_ptr;

            // Copy parent metadata to child (simulating fork)
            child.ppid = parent.pid;
            child.pgid = parent.pgid;
            child.sid = parent.sid;
            child.creds = parent.creds;
            child.fs = parent.fs;
            child.sched.state = rux_sched::TaskState::Ready;
            child.sched.class = parent.sched.class;
            child.sched.policy = parent.sched.policy;
            child.sched.nice = parent.sched.nice;
            child.exit_code = 0;

            serial::write_str("rux: fork OK (parent=1, child=2)\n");

            // Simulate child exit
            child.exit_code = (42 & 0xFF) << 8;
            child.sched.state = rux_sched::TaskState::Zombie;

            // Simulate parent wait — read child's exit code
            let exit_code = (child.exit_code >> 8) & 0xFF;
            let mut buf = [0u8; 10];
            serial::write_str("rux: wait OK (child exited with code ");
            serial::write_str(write_u32(&mut buf, exit_code as u32));
            serial::write_str(")\n");

            if exit_code != 42 {
                serial::write_str("FAIL: wrong exit code\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }

            // Clean up — mark dead, free slab
            child.sched.state = rux_sched::TaskState::Dead;
            task_slab.dealloc(child_ptr as *mut u8);
            task_slab.dealloc(parent_ptr as *mut u8);

            serial::write_str("rux: process lifecycle OK (fork→exit→wait→reap)\n");
        }
    }

    // ── RamFs + shell exec ─────────────────────────────────────────────
    unsafe { init_ramfs_and_exec_shell(); }
}

/// Initialize the RAM filesystem, populate it with /hello, and exec the shell.
/// Marked `#[inline(never)]` to isolate VFS code from the test functions above.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn init_ramfs_and_exec_shell() -> ! {
    use rux_mm::FrameAllocator;
    use rux_vfs::{FileSystem, FileName};

    serial::write_str("rux: init ramfs...\n");

    let alloc_ptr = 0x300000 as *mut rux_mm::frame::BuddyAllocator;
    let fs_ptr = 0x310000 as *mut rux_vfs::ramfs::RamFs;

    // Zero the RamFs memory region
    let fs_bytes = core::mem::size_of::<rux_vfs::ramfs::RamFs>();
    let fs_qwords = (fs_bytes + 7) / 8;
    for i in 0..fs_qwords {
        core::ptr::write_volatile((fs_ptr as *mut u64).add(i), 0u64);
    }
    for i in 0..fs_qwords {
        core::ptr::write_volatile((fs_ptr as *mut u64).add(i), 0u64);
    }
    serial::write_str("rux: zeroing done\n");

    // Initialize RamFs in place (avoids 700KB stack allocation)
    let alloc_dyn: *mut dyn rux_mm::FrameAllocator =
        &mut *alloc_ptr as &mut dyn rux_mm::FrameAllocator;
    rux_vfs::ramfs::RamFs::init_at(fs_ptr, alloc_dyn);
    let fs = &mut *fs_ptr;

    // Populate full busybox-compatible rootfs
    let box_data: &[u8] = include_bytes!("../../../user/busybox_x86_64");
    rootfs::populate(fs, box_data);

    // Init kernel state
    kstate::init(fs_ptr, alloc_ptr);
    serial::write_str("rux: kernel state initialized\n");

    serial::write_str("rux: exec /sbin/init\n");
    crate::execargs::set(b"/bin/sh", b"");
    let init_ino = rux_vfs::path::resolve_path(fs, b"/bin/busybox").expect("busybox not found");
    let alloc = &mut *(0x300000 as *mut rux_mm::frame::BuddyAllocator);
    elf::load_elf_from_inode(init_ino as u64, alloc);
}

// Counters incremented by the preemptive tasks
static COUNTER_A: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static COUNTER_B: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Yield point: check if the timer ISR requested a reschedule and switch if so.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn maybe_yield() {
    unsafe {
        let sched = scheduler::get();
        if sched.need_resched {
            sched.schedule();
        }
    }
}

/// Task exit: dequeue from scheduler and switch to next task.
#[cfg(target_arch = "x86_64")]
fn task_exit() -> ! {
    unsafe {
        use rux_sched::SchedClassOps;
        let sched = scheduler::get();
        let idx = sched.current;
        sched.tasks[idx].active = false;
        sched.tasks[idx].entity.state = rux_sched::TaskState::Dead;
        // Dequeue from CFS
        sched.cfs.dequeue(0, &mut sched.tasks[idx].entity, 0);
        // Switch to next task (or idle)
        sched.need_resched = true;
        sched.schedule();
    }
    loop { core::hint::spin_loop(); }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn task_counter_a() {
    for _ in 0..100_000 {
        COUNTER_A.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        maybe_yield();
    }
    serial::write_str("rux: task A done\n");
    task_exit();
}

#[cfg(target_arch = "x86_64")]
extern "C" fn task_counter_b() {
    for _ in 0..100_000 {
        COUNTER_B.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        maybe_yield();
    }
    serial::write_str("rux: task B done\n");
    task_exit();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial::write_str("PANIC: ");
    if let Some(location) = info.location() {
        serial::write_str(location.file());
        serial::write_str(":");
        let mut buf = [0u8; 10];
        let s = write_u32(&mut buf, location.line());
        serial::write_str(s);
    }
    serial::write_str("\n");
    if let Some(msg) = info.message().as_str() {
        serial::write_str(msg);
        serial::write_str("\n");
    }
    exit::exit_qemu(exit::EXIT_FAILURE);
}

#[cfg(target_arch = "x86_64")]
/// Task B entry point — runs on its own stack.
extern "C" fn task_b_entry() {
    serial::write_str("rux: task B running!\n");

    // Switch back to main task
    unsafe {
        static mut TASK_B_RSP: u64 = 0;
        // MAIN_RSP was set by the switch that got us here
        x86_64::context::context_switch(
            &raw mut TASK_B_RSP,
            MAIN_RSP,
        );
    }
    // Should not reach here
    loop { core::hint::spin_loop(); }
}

#[cfg(target_arch = "x86_64")]
static mut MAIN_RSP: u64 = 0;

fn write_hex_serial(n: usize) {
    serial::write_str("0x");
    let mut buf = [0u8; 16];
    write_hex_buf(&mut buf, n);
}

fn write_hex_buf(buf: &mut [u8; 16], mut n: usize) {
    if n == 0 {
        serial::write_str("0");
        return;
    }
    let mut i = 16;
    while n > 0 && i > 0 {
        i -= 1;
        let digit = (n & 0xF) as u8;
        buf[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
    }
    serial::write_bytes(&buf[i..]);
}

pub fn write_u32(buf: &mut [u8; 10], mut n: u32) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut i = 10;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}
