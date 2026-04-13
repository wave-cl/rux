/// aarch64 boot initialization: hardware setup and shell launch.

use super::console;
use crate::{scheduler, pgtrack};

/// AP (Application Processor) Rust entry point. Called from ap_entry.S
/// after the AP has configured MMU, FP/NEON, and stack.
#[no_mangle]
pub extern "C" fn ap_entry_rust(cpu_id: u64) -> ! {
    unsafe {
        // Set TPIDR_EL1 for this CPU (must be first — this_cpu() depends on it)
        crate::percpu::init_this_cpu(cpu_id as usize);
        let pc = crate::percpu::cpu(cpu_id as usize);
        pc.cpu_id = cpu_id as u32;
        pc.online = true;
        pc.idle = true;
        pc.current_task_idx = 0; // idle task (slot 0)
        pc.irq_stack_top = crate::task_table::IRQ_STACKS.0[cpu_id as usize].as_ptr() as u64
            + crate::task_table::IRQ_STACK_SIZE as u64;

        // Initialize GIC CPU interface for this AP
        super::gic::init_cpu();

        // Start per-CPU timer (aarch64 generic timer is per-CPU)
        super::timer::init(1000);

        // AP is online — BSP prints status after all APs check in
        // (avoids interleaved console output from concurrent CPUs)

        // Enable interrupts and enter scheduler loop
        core::arch::asm!("msr daifclr, #0xF", options(nostack));
        loop {
            core::arch::asm!("wfi", options(nostack, nomem));
            if crate::task_table::current_needs_resched() {
                crate::task_table::clear_current_need_resched();
                crate::arch::preempt_disable();
                crate::scheduler::get().schedule();
                crate::arch::preempt_enable();
            }
        }
    }
}

pub fn aarch64_init(dtb_addr: usize) {
    // Initialize BSP per-CPU data + set TPIDR_EL1
    unsafe {
        crate::percpu::init_bsp();
        crate::percpu::init_this_cpu(0); // TPIDR_EL1 → &PERCPU[0]
        // Set up per-CPU IRQ stack for BSP
        crate::percpu::this_cpu().irq_stack_top =
            crate::task_table::IRQ_STACKS.0[0].as_ptr() as u64
            + crate::task_table::IRQ_STACK_SIZE as u64;
    }

    console::write_str("rux: aarch64 running in EL1\n");

    // Detect CPU features from ID registers
    unsafe {
        use rux_arch::aarch64::cpu::*;
        let isar0: u64;
        let pfr0: u64;
        let mmfr1: u64;
        core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nostack));
        core::arch::asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0, options(nostack));
        core::arch::asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1, options(nostack));
        let features = parse_isar0(isar0).or(parse_pfr0(pfr0)).or(parse_mmfr1(mmfr1));
        rux_arch::cpu::set_cpu_features(features);
        if features.has(ATOMICS) { console::write_str("rux: LSE atomics detected\n"); }
        if features.has(PAN) {
            // PAN detected — disable enforcement by ensuring SPAN=1
            // (PAN is NOT set on exception entry from EL0).
            // Also explicitly clear PAN bit in PSTATE.
            let mut sctlr: u64;
            core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));
            sctlr |= 1 << 23; // SPAN=1: do NOT set PAN on exception entry
            core::arch::asm!("msr sctlr_el1, {}", in(reg) sctlr, options(nostack));
            core::arch::asm!("isb", options(nostack));
            // Clear PAN in current PSTATE
            core::arch::asm!(".inst 0xd500409f", options(nostack)); // MSR PAN, #0
            console::write_str("rux: PAN detected (disabled via SPAN=1)\n");
        }
    }

    unsafe { super::exception::init(); }
    console::write_str("rux: exception vectors installed\n");

    unsafe { super::gic::init(); }
    console::write_str("rux: GIC initialized\n");

    unsafe { super::timer::init(1000); }
    console::write_str("rux: timer initialized (1000 Hz)\n");

    // Read PL031 RTC for wall-clock time
    unsafe {
        let rtc_epoch = super::rtc::read_rtc();
        crate::syscall::process::set_boot_epoch(rtc_epoch);
    }
    console::write_str("rux: PL031 RTC read\n");

    unsafe { super::gic::enable_irqs(); }
    console::write_str("rux: interrupts enabled\n");

    // ── Frame allocator (placed dynamically after kernel _end) ────────
    extern "C" { static _end: u8; }
    let kernel_end = unsafe { (&_end as *const u8 as usize + 0xFFF) & !0xFFF };
    let alloc_size = core::mem::size_of::<rux_mm::frame::BuddyAllocator>();
    let ramfs_size = core::mem::size_of::<rux_fs::ramfs::RamFs>();
    let ramfs_start = (kernel_end + alloc_size + 0xFFF) & !0xFFF;
    // Keep 0x44000000 as minimum floor for compatibility, but auto-adjust
    // upward if _end extends past it (e.g., large MAX_PROCS).
    let frame_base = ((ramfs_start + ramfs_size + 0xFFF) & !0xFFF).max(0x44000000);
    let id_map_end: usize = 0x40000000 + 128 * 1024 * 1024; // 0x48000000
    let max_frames = (id_map_end.saturating_sub(frame_base)) / 4096;
    let frame_count = max_frames.min(16384) as u32;

    {
        let mut hx = [0u8; 16];
        console::write_str("rux: _end=0x");
        console::write_bytes(rux_klib::fmt::usize_to_hex(&mut hx, kernel_end));
        console::write_str(" frames@0x");
        console::write_bytes(rux_klib::fmt::usize_to_hex(&mut hx, frame_base));
        console::write_str("\n");
    }

    if frame_base >= id_map_end {
        console::write_str("PANIC: kernel too large for 128MB identity map\n");
        loop { core::hint::spin_loop(); }
    }

    console::write_str("rux: init frame allocator...\n");
    unsafe {
        let alloc_ptr = kernel_end as *mut u8;
        let alloc_qwords = alloc_size / 8;
        for i in 0..alloc_qwords {
            core::ptr::write_volatile((alloc_ptr as *mut u64).add(i), 0u64);
        }
        let alloc = &mut *(alloc_ptr as *mut rux_mm::frame::BuddyAllocator);
        alloc.init(rux_klib::PhysAddr::new(frame_base), frame_count);
        console::write_str("rux: frame allocator ready\n");

        // ── Kernel page tables + enable MMU ────────────────────────────
        console::write_str("rux: building kernel page tables...\n");
        let rwx = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::EXECUTE);
        let mut kpt = super::paging::PageTable4Level::new(alloc).expect("kpt");
        kpt.identity_map_range_huge(
            rux_klib::PhysAddr::new(0x40000000), 128 * 1024 * 1024, rwx, alloc,
        ).expect("identity map");
        let dev_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::NO_CACHE);
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x08000000), 0x20000, dev_flags, alloc,
        ).expect("gic map");
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x09000000), 0x11000, dev_flags, alloc,
        ).expect("uart+rtc map");
        // virtio-mmio region: 32 devices × 0x200 bytes each at 0x0a000000
        // Map full 64KB to ensure all device slots are covered
        kpt.identity_map_range(
            rux_klib::PhysAddr::new(0x0a000000), 0x10000, dev_flags, alloc,
        ).expect("virtio-mmio map");

        super::paging::activate(&kpt);
        pgtrack::set_kernel_pt(kpt.root_phys().as_usize() as u64);
        console::write_str("rux: MMU enabled, kernel page tables active!\n");

        // Split 2MB pages containing KSTACKS, then unmap guard pages
        for i in 0..crate::task_table::MAX_PROCS {
            let stack_bottom = crate::task_table::KSTACKS.0[i].as_ptr() as usize;
            let guard_page = stack_bottom & !0xFFF;
            let huge_base = guard_page & !0x1FFFFF;
            // split_huge_page is idempotent if already split
            let _ = kpt.split_huge_page(
                rux_klib::VirtAddr::new(huge_base),
                rux_mm::PageLevel::L1,
                alloc,
            );
            let _ = kpt.unmap_4k(rux_klib::VirtAddr::new(guard_page));
        }
        console::write_str("rux: kernel stack guard pages active\n");
    }

    // ── Init scheduler (needed for vfork/exec) ──────────────────────
    unsafe { scheduler::init_context_fns(); }

    // ── Start APs via PSCI ──────────────────────────────────────────
    unsafe {
        // Read BSP system registers to pass to AP
        let ttbr0: u64;
        let tcr: u64;
        let mair: u64;
        let vbar: u64;
        let sctlr: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nostack));
        core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr, options(nostack));
        core::arch::asm!("mrs {}, mair_el1", out(reg) mair, options(nostack));
        core::arch::asm!("mrs {}, vbar_el1", out(reg) vbar, options(nostack));
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nostack));

        // Start APs via PSCI: try CPUs 1..MAX_CPUS, stop on first failure
        extern "C" { static mut AP_BOOT_DATA: [u64; 7]; fn ap_entry_asm(); }

        let max_aps = 4usize.min(crate::percpu::MAX_CPUS);
        for ap_id in 1..max_aps {
            AP_BOOT_DATA[0] = ttbr0;
            AP_BOOT_DATA[1] = tcr;
            AP_BOOT_DATA[2] = mair;
            AP_BOOT_DATA[3] = vbar;
            AP_BOOT_DATA[4] = sctlr;
            AP_BOOT_DATA[5] = crate::task_table::KSTACKS.0[ap_id].as_ptr() as u64
                + crate::task_table::KSTACK_SIZE as u64;
            AP_BOOT_DATA[6] = ap_entry_rust as *const () as u64;

            let ret = super::psci::cpu_on(ap_id as u64, ap_entry_asm as *const () as u64, ap_id as u64);
            if ret != 0 { break; } // no more CPUs

            let mut waited = 0u64;
            while waited < 10_000_000 {
                if crate::percpu::cpu(ap_id).online { break; }
                core::hint::spin_loop();
                waited += 1;
            }
            if !crate::percpu::cpu(ap_id).online { break; }

            console::write_str("rux: AP ");
            let mut idbuf = [0u8; 10];
            console::write_str(rux_klib::fmt::u32_to_str(&mut idbuf, ap_id as u32));
            console::write_str(" online\n");
        }

        let total = crate::percpu::online_cpus();
        console::write_str("rux: SMP: ");
        let mut nbuf = [0u8; 10];
        console::write_str(rux_klib::fmt::u32_to_str(&mut nbuf, total as u32));
        console::write_str(" CPUs online\n");
    }

    // ── Boot: ramfs + initramfs + procfs + exec /sbin/init ────────────
    // Store kernel_end in a static for the procfs closure.
    static mut ALLOC_ADDR: usize = 0;
    unsafe { ALLOC_ADDR = kernel_end; }

    unsafe {
        let alloc_ptr = kernel_end as *mut rux_mm::frame::BuddyAllocator;

        // Find initrd: try DTB, then scan RAM (scan after frame pool)
        let scan_start = frame_base + frame_count as usize * 4096;
        let initrd = if dtb_addr != 0 {
            super::devicetree::get_initrd(dtb_addr)
        } else {
            None
        }.or_else(|| find_cpio_in_ram(scan_start, id_map_end));

        static mut PROCFS: rux_fs::procfs::ProcFs = crate::procfs_callbacks::new_procfs(
            || super::timer::ticks(),
            || 16384,
            || unsafe {
                use rux_mm::FrameAllocator;
                (*(ALLOC_ADDR as *const rux_mm::frame::BuddyAllocator))
                    .available_frames(rux_mm::PageSize::FourK)
            },
        );
        crate::boot::boot(crate::boot::BootParams {
            alloc_ptr,
            ramfs_ptr: ramfs_start as *mut rux_fs::ramfs::RamFs,
            initrd,
            procfs: {
                (&raw mut PROCFS).as_mut().unwrap().num_cpus = crate::percpu::online_cpus() as u32;
                &mut *(&raw mut PROCFS)
            },
            log: console::write_str,
            cmdline: b"",      // TODO: parse DTB bootargs
            virtio_mmio_base: 0x0a000000, // QEMU virt machine virtio-mmio base
        });
    }
}

/// Parse an 8-digit hex field from a cpio header at the given address.
unsafe fn cpio_hex8(addr: usize) -> usize {
    let mut val = 0usize;
    for i in 0..8 {
        let b = *(addr as *const u8).add(i);
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => 0,
        };
        val = (val << 4) | digit;
    }
    val
}

/// Scan RAM for a cpio newc archive (magic "070701").
/// Walks cpio entries to compute the actual archive size instead of
/// using the scan range end (which gave wildly wrong sizes).
unsafe fn find_cpio_in_ram(start: usize, end: usize) -> Option<(usize, usize)> {
    let magic = *b"070701";
    let mut addr = start;
    while addr + 6 < end {
        let p = addr as *const [u8; 6];
        if *p == magic {
            // Found cpio start — walk entries to compute actual size
            let mut pos = addr;
            loop {
                if pos + 110 > end { break; }
                let hdr = pos as *const [u8; 6];
                if *hdr != magic { break; }
                let filesize = cpio_hex8(pos + 54);
                let namesize = cpio_hex8(pos + 94);
                let name_start = pos + 110;
                let data_start = (name_start + namesize + 3) & !3;
                let data_end = data_start + filesize;
                pos = (data_end + 3) & !3;
            }
            let size = pos - addr;

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
