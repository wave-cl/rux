#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
use x86_64::{serial, exit};

/// Kernel entry point. Called from boot.S after long mode is set up.
#[no_mangle]
pub extern "C" fn kernel_main(_multiboot_info: usize) -> ! {
    unsafe { serial::init(); }
    serial::write_str("rux: boot OK\n");

    // Initialize GDT with TSS
    // The boot stack top is defined in boot.S. We use 0x104000 + 16384 = 0x108000
    // (bss starts at ~0x104000, boot_stack is 16K after page tables)
    unsafe { x86_64::gdt::init(0x108000); }
    serial::write_str("rux: GDT + TSS loaded\n");

    // Initialize IDT with all exception/IRQ handlers
    unsafe { x86_64::idt::init(); }
    serial::write_str("rux: IDT loaded\n");

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
    write_hex_serial(_multiboot_info);
    serial::write_str("\n");
    let memmap = unsafe { x86_64::multiboot::parse_memory_map(_multiboot_info) };
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
            0x200000usize
        } else {
            region.base.as_usize()
        };
        let alloc_size = region.size - (alloc_base - region.base.as_usize());
        let frames = (alloc_size / 4096) as u32;
        let frames = frames.min(4096); // limit for initial testing

        serial::write_str("rux: init allocator at ");
        write_hex_serial(alloc_base);
        serial::write_str(" (");
        serial::write_str(write_u32(&mut buf, frames));
        serial::write_str(" frames)\n");

        unsafe {
            serial::write_str("rux: zeroing allocator...\n");
            let alloc_ptr = 0x400000 as *mut u64;
            let alloc_qwords = core::mem::size_of::<rux_mm::frame::BuddyAllocator>() / 8;
            for i in 0..alloc_qwords {
                core::ptr::write_volatile(alloc_ptr.add(i), 0u64);
            }
            serial::write_str("rux: zeroing done\n");

            let alloc = &mut *(0x400000 as *mut rux_mm::frame::BuddyAllocator);
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
                8 * 1024 * 1024,
                rwx,
                alloc,
            ).expect("identity map failed");

            serial::write_str("rux: identity mapped 0-8 MiB\n");

            // Activate — switch CR3 to our page tables
            kpt.activate();
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

    // ── CFS scheduler test ────────────────────────────────────────────
    serial::write_str("rux: CFS scheduler test...\n");
    {
        use rux_sched::entity::SchedEntity;
        use rux_sched::fair::cfs::CfsClass;
        use rux_sched::fair::constants::WF_FORK;
        use rux_sched::SchedClassOps;
        use rux_sched::TaskState;

        let mut cfs = CfsClass::new();
        cfs.set_clock(0, 0);

        // Create two entities with different nice values
        let mut task_a = SchedEntity::new(1);
        task_a.nice = 0;    // weight 1024
        task_a.cpu = 0;

        let mut task_b = SchedEntity::new(2);
        task_b.nice = 5;    // weight 423 (lower priority)
        task_b.cpu = 0;

        // Enqueue both
        cfs.enqueue(0, &mut task_a, WF_FORK);
        cfs.enqueue(0, &mut task_b, WF_FORK);

        // Run a proper scheduling loop: pick → set_next → tick → put_prev → repeat
        let mut prev = SchedEntity::new(99);
        prev.state = TaskState::Interruptible;
        let mut clock: u64 = 0;
        let mut a_ticks: u32 = 0;
        let mut b_ticks: u32 = 0;

        for _ in 0..20 {
            clock += 3_000_000; // 3ms per tick (matches BASE_SLICE_NS)
            cfs.set_clock(0, clock);

            if let Some(picked) = cfs.pick_next(0, &mut prev) {
                unsafe {
                    let curr = &mut *picked;
                    cfs.set_next(0, curr);

                    // Advance clock for the tick duration
                    clock += 1_000_000;
                    cfs.set_clock(0, clock);
                    let resched = cfs.task_tick(0, curr);

                    if curr.id == 1 { a_ticks += 1; }
                    else if curr.id == 2 { b_ticks += 1; }

                    // Put prev back on the runqueue
                    cfs.put_prev(0, curr);
                }
            }
        }

        let mut buf = [0u8; 10];
        serial::write_str("rux: task A (nice 0): ");
        serial::write_str(write_u32(&mut buf, a_ticks));
        serial::write_str(" ticks, task B (nice 5): ");
        serial::write_str(write_u32(&mut buf, b_ticks));
        serial::write_str(" ticks\n");

        if a_ticks == 0 || b_ticks == 0 {
            serial::write_str("FAIL: one task got zero ticks\n");
            exit::exit_qemu(exit::EXIT_FAILURE);
        }
        if a_ticks < b_ticks {
            serial::write_str("FAIL: lower-weight task got more ticks\n");
            exit::exit_qemu(exit::EXIT_FAILURE);
        }
        serial::write_str("rux: CFS scheduler OK (weighted fair)\n");
    }

    serial::write_str("rux: all checks passed\n");
    exit::exit_qemu(exit::EXIT_SUCCESS);
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

/// Reference to main task's saved RSP (set during context switch).
/// Task B reads this to switch back.
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
