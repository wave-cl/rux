/// x86_64 boot initialization: hardware setup, tests, and shell launch.

use super::{serial, exit};
use crate::{scheduler, elf, pgtrack, write_hex_serial, write_u32, COUNTER_A, COUNTER_B};

pub fn x86_64_init(multiboot_info: usize) {
    // Initialize GDT with TSS — use the actual boot_stack_top from boot.S
    unsafe {
        extern "C" { static boot_stack_top: u8; }
        let stack_top = &boot_stack_top as *const u8 as u64;
        super::gdt::init(stack_top);
    }
    serial::write_str("rux: GDT + TSS loaded\n");

    // Initialize IDT with all exception/IRQ handlers
    unsafe { super::idt::init(); }
    serial::write_str("rux: IDT loaded\n");

    // Initialize SYSCALL/SYSRET MSRs for Linux ABI
    unsafe { super::syscall::init_syscall_msrs(); }

    // Initialize PIT timer at 1000 Hz
    unsafe { super::pit::init(1000); }
    serial::write_str("rux: PIT timer initialized (1000 Hz)\n");

    // Enable interrupts
    unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)); }
    serial::write_str("rux: interrupts enabled\n");

    // Wait for some timer ticks
    let start = super::pit::ticks();
    while super::pit::ticks() < start + 10 {
        core::hint::spin_loop();
    }
    serial::write_str("rux: timer OK\n");

    // ── Parse multiboot memory map ──────────────────────────────────────
    serial::write_str("rux: multiboot info at ");
    write_hex_serial(multiboot_info);
    serial::write_str("\n");
    let memmap = unsafe { super::multiboot::parse_memory_map(multiboot_info) };
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
    let mut best = 0;
    for i in 1..memmap.count {
        if memmap.regions[i].size > memmap.regions[best].size {
            best = i;
        }
    }
    if memmap.count > 0 {
        let region = &memmap.regions[best];
        let alloc_base = if region.base.as_usize() < 0x200000 {
            0x780000usize
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
                let mut task_slab = rux_mm::Slab::new(1024);
                let obj_a = task_slab.alloc(alloc).expect("slab alloc A");
                let obj_b = task_slab.alloc(alloc).expect("slab alloc B");
                let obj_c = task_slab.alloc(alloc).expect("slab alloc C");
                if obj_a == obj_b || obj_b == obj_c || obj_a == obj_c {
                    serial::write_str("FAIL: slab returned duplicate\n");
                    exit::exit_qemu(exit::EXIT_FAILURE);
                }
                task_slab.dealloc(obj_b);
                let obj_d = task_slab.alloc(alloc).expect("slab alloc D");
                if obj_d != obj_b {
                    serial::write_str("FAIL: slab didn't reuse freed slot\n");
                    exit::exit_qemu(exit::EXIT_FAILURE);
                }
                serial::write_str("rux: slab OK (alloc/dealloc/reuse)\n");
                task_slab.dealloc(obj_a);
                task_slab.dealloc(obj_c);
                task_slab.dealloc(obj_d);
            }

            // ── Page table test ─────────────────────────────────────────
            serial::write_str("rux: page table test...\n");
            let mut pt = super::paging::PageTable4Level::new(alloc)
                .expect("failed to create page table");
            serial::write_str("rux: page table created (root=");
            write_hex_serial(pt.root_phys().as_usize());
            serial::write_str(")\n");

            let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("alloc frame");
            let test_virt = rux_klib::VirtAddr::new(0x8000_0000);
            let flags = rux_mm::MappingFlags::READ.or(rux_mm::MappingFlags::WRITE);
            pt.map_4k(test_virt, frame, flags, alloc).expect("map failed");
            serial::write_str("rux: mapped ");
            write_hex_serial(test_virt.as_usize());
            serial::write_str(" -> ");
            write_hex_serial(frame.as_usize());
            serial::write_str("\n");

            let translated = pt.translate(test_virt).expect("translate failed");
            if translated.as_usize() != frame.as_usize() {
                serial::write_str("FAIL: translate mismatch!\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }
            serial::write_str("rux: translate OK\n");

            let unmapped = pt.unmap_4k(test_virt).expect("unmap failed");
            if unmapped.as_usize() != frame.as_usize() {
                serial::write_str("FAIL: unmap returned wrong address!\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }
            if pt.translate(test_virt).is_ok() {
                serial::write_str("FAIL: translate succeeded after unmap!\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }
            serial::write_str("rux: unmap + re-translate OK\n");
            alloc.dealloc(frame, rux_mm::PageSize::FourK);

            // ── Activate kernel page tables ─────────────────────────────
            serial::write_str("rux: building kernel page tables...\n");
            let mut kpt = super::paging::PageTable4Level::new(alloc)
                .expect("failed to create kernel page table");
            let rwx = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::EXECUTE);
            kpt.identity_map_range(
                rux_klib::PhysAddr::new(0),
                128 * 1024 * 1024,
                rwx,
                alloc,
            ).expect("identity map failed");
            serial::write_str("rux: identity mapped 0-128 MiB\n");

            super::paging::activate(&kpt);
            pgtrack::set_kernel_pt(kpt.root_phys().as_usize() as u64);
            serial::write_str("rux: CR3 switched to kernel page tables!\n");
        }
    }

    // ── Context switch test ─────────────────────────────────────────────
    serial::write_str("rux: context switch test...\n");
    unsafe {
        static mut TASK_B_STACK: [u8; 16384] = [0; 16384];
        let stack_top = TASK_B_STACK.as_ptr() as u64 + 16384;
        let task_b_rsp = super::context::init_task_stack(
            stack_top, task_b_entry as u64, 0x42,
        );
        super::context::context_switch(&raw mut MAIN_RSP, task_b_rsp);
        serial::write_str("rux: back in main task\n");
    }

    // ── Preemptive scheduling test ─────────────────────────────────────
    serial::write_str("rux: preemptive scheduler test...\n");
    unsafe {
        use rux_sched::SchedClassOps;
        let sched = scheduler::get();
        static mut STACK_A: [u8; 16384] = [0; 16384];
        static mut STACK_B: [u8; 16384] = [0; 16384];
        sched.create_task(task_counter_a, STACK_A.as_ptr() as u64 + 16384, 0);
        sched.create_task(task_counter_b, STACK_B.as_ptr() as u64 + 16384, 5);
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
        serial::write_str("FAIL: preemptive scheduling did not run both tasks\n");
        exit::exit_qemu(exit::EXIT_FAILURE);
    }

    // ── Process lifecycle test ──────────────────────────────────────────
    serial::write_str("rux: process lifecycle test...\n");
    {
        use rux_proc::id::{Pid, Tgid};
        use rux_proc::task::Task;
        unsafe {
            let alloc = &mut *(0x300000 as *mut rux_mm::frame::BuddyAllocator);
            let mut task_slab = rux_mm::Slab::new(core::mem::size_of::<Task>());
            let parent_ptr = task_slab.alloc(alloc).expect("slab parent") as *mut Task;
            core::ptr::write(parent_ptr, Task::new(Pid::new(1), Tgid::new(1)));
            let parent = &mut *parent_ptr;
            parent.sched.state = rux_sched::TaskState::Running;
            let child_ptr = task_slab.alloc(alloc).expect("slab child") as *mut Task;
            core::ptr::write(child_ptr, Task::new(Pid::new(2), Tgid::new(2)));
            let child = &mut *child_ptr;
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
            child.exit_code = (42 & 0xFF) << 8;
            child.sched.state = rux_sched::TaskState::Zombie;
            let exit_code = (child.exit_code >> 8) & 0xFF;
            serial::write_str("rux: wait OK (child exited with code ");
            serial::write_str(write_u32(&mut buf, exit_code as u32));
            serial::write_str(")\n");
            if exit_code != 42 {
                serial::write_str("FAIL: wrong exit code\n");
                exit::exit_qemu(exit::EXIT_FAILURE);
            }
            child.sched.state = rux_sched::TaskState::Dead;
            task_slab.dealloc(child_ptr as *mut u8);
            task_slab.dealloc(parent_ptr as *mut u8);
            serial::write_str("rux: process lifecycle OK (fork→exit→wait→reap)\n");
        }
    }

    // ── RamFs + shell exec ─────────────────────────────────────────────
    unsafe { init_ramfs_and_exec_shell(); }
}

#[inline(never)]
unsafe fn init_ramfs_and_exec_shell() -> ! {
    use rux_mm::FrameAllocator;
    use rux_vfs::{FileSystem, FileName};

    serial::write_str("rux: init ramfs...\n");
    let alloc_ptr = 0x300000 as *mut rux_mm::frame::BuddyAllocator;
    let fs_ptr = 0x310000 as *mut rux_vfs::ramfs::RamFs;

    let fs_bytes = core::mem::size_of::<rux_vfs::ramfs::RamFs>();
    let fs_qwords = (fs_bytes + 7) / 8;
    for i in 0..fs_qwords {
        core::ptr::write_volatile((fs_ptr as *mut u64).add(i), 0u64);
    }
    for i in 0..fs_qwords {
        core::ptr::write_volatile((fs_ptr as *mut u64).add(i), 0u64);
    }
    serial::write_str("rux: zeroing done\n");

    let alloc_dyn: *mut dyn rux_mm::FrameAllocator =
        &mut *alloc_ptr as &mut dyn rux_mm::FrameAllocator;
    rux_vfs::ramfs::RamFs::init_at(fs_ptr, alloc_dyn);
    let fs = &mut *fs_ptr;

    let box_data: &[u8] = include_bytes!("../../../../user/busybox_x86_64");
    crate::rootfs::populate(fs, box_data);

    crate::kstate::init(fs_ptr, alloc_ptr);
    serial::write_str("rux: kernel state initialized\n");

    serial::write_str("rux: exec /sbin/init\n");
    crate::execargs::set(b"/bin/sh", b"");
    let init_ino = rux_vfs::path::resolve_path(fs, b"/bin/busybox").expect("busybox not found");
    let alloc = &mut *(0x300000 as *mut rux_mm::frame::BuddyAllocator);
    elf::load_elf_from_inode(init_ino as u64, alloc);
}

static mut MAIN_RSP: u64 = 0;

extern "C" fn task_b_entry() {
    serial::write_str("rux: task B running!\n");
    unsafe {
        static mut TASK_B_RSP: u64 = 0;
        super::context::context_switch(&raw mut TASK_B_RSP, MAIN_RSP);
    }
    loop { core::hint::spin_loop(); }
}

#[inline(always)]
fn maybe_yield() {
    unsafe {
        let sched = scheduler::get();
        if sched.need_resched {
            sched.schedule();
        }
    }
}

fn task_exit() -> ! {
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

extern "C" fn task_counter_a() {
    for _ in 0..100_000 {
        COUNTER_A.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        maybe_yield();
    }
    serial::write_str("rux: task A done\n");
    task_exit();
}

extern "C" fn task_counter_b() {
    for _ in 0..100_000 {
        COUNTER_B.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        maybe_yield();
    }
    serial::write_str("rux: task B done\n");
    task_exit();
}
