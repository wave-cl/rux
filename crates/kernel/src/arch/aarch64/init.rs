/// aarch64 boot initialization: hardware setup and shell launch.

use super::console;
use super::exit;
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
        pc.current_task_idx = usize::MAX;

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
            // After timer interrupt, check if scheduler wants to reschedule
            let sched = crate::scheduler::get();
            if sched.need_resched {
                sched.schedule();
            }
        }
    }
}

pub fn aarch64_init(dtb_addr: usize) {
    // Initialize BSP per-CPU data + set TPIDR_EL1
    unsafe {
        crate::percpu::init_bsp();
        crate::percpu::init_this_cpu(0); // TPIDR_EL1 → &PERCPU[0]
    }

    console::write_str("rux: aarch64 running in EL1\n");

    // Detect CPU features from ID registers
    unsafe {
        use rux_arch::aarch64::cpu::*;
        let isar0: u64;
        let pfr0: u64;
        core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nostack));
        core::arch::asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0, options(nostack));
        let features = parse_isar0(isar0).or(parse_pfr0(pfr0));
        rux_arch::cpu::set_cpu_features(features);
        if features.has(ATOMICS) { console::write_str("rux: LSE atomics detected\n"); }
    }

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
            rux_klib::PhysAddr::new(0x09000000), 0x1000, dev_flags, alloc,
        ).expect("uart map");

        super::paging::activate(&kpt);
        pgtrack::set_kernel_pt(kpt.root_phys().as_usize() as u64);
        console::write_str("rux: MMU enabled, kernel page tables active!\n");
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
            AP_BOOT_DATA[5] = crate::task_table::KSTACKS[ap_id].as_ptr() as u64
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
    unsafe {
        let alloc_ptr = 0x43000000 as *mut rux_mm::frame::BuddyAllocator;
        let alloc_size = core::mem::size_of::<rux_mm::frame::BuddyAllocator>();
        let ramfs_addr = (0x43000000 + alloc_size + 0xFFF) & !0xFFF;

        // Find initrd: try DTB, then scan RAM
        let initrd = if dtb_addr != 0 {
            super::devicetree::get_initrd(dtb_addr)
        } else {
            None
        }.or_else(|| find_cpio_in_ram(0x44100000, 0x47F00000));

        static mut PROCFS: rux_fs::procfs::ProcFs = rux_fs::procfs::ProcFs::new(
            || super::timer::ticks(),
            || 16384,
            || unsafe {
                use rux_mm::FrameAllocator;
                (*(0x43000000 as *const rux_mm::frame::BuddyAllocator))
                    .available_frames(rux_mm::PageSize::FourK)
            },
        );
        crate::boot::boot(crate::boot::BootParams {
            alloc_ptr,
            ramfs_ptr: ramfs_addr as *mut rux_fs::ramfs::RamFs,
            initrd,
            procfs: &mut *(&raw mut PROCFS),
            log: console::write_str,
        });
    }
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
