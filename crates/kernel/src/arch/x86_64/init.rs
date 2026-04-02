/// x86_64 boot initialization: hardware setup and shell launch.

use super::{console, exit};
use crate::{scheduler, pgtrack};

/// AP (Application Processor) entry point. Called by the AP trampoline
/// after transitioning to 64-bit long mode with a per-CPU stack.
///
/// # Safety
/// Called exactly once per AP, with a valid stack and identity-mapped memory.
#[no_mangle]
pub extern "C" fn ap_entry(cpu_id: u32) -> ! {
    unsafe {
        // 1. Per-CPU GDT + TSS
        let kstack_top = crate::task_table::KSTACKS[cpu_id as usize].as_ptr() as usize
            + crate::task_table::KSTACK_SIZE;
        super::gdt::init_ap(cpu_id as usize, kstack_top as u64);

        // 2. SYSCALL MSRs
        super::syscall::init_syscall_msrs();

        // 3. IDT (shared with BSP — IDT is the same for all CPUs)
        super::idt::load();

        // 4. Set GS-base + per-CPU state
        crate::percpu::init_this_cpu(cpu_id as usize);
        let pc = crate::percpu::cpu(cpu_id as usize);
        pc.cpu_id = cpu_id;
        pc.syscall_kstack_top = kstack_top as u64;
        pc.online = true;
        pc.idle = true;
        pc.current_task_idx = usize::MAX;

        console::write_str("rux: AP ");
        let mut buf = [0u8; 10];
        console::write_str(rux_klib::fmt::u32_to_str(&mut buf, cpu_id));
        console::write_str(" online\n");

        // 5. Start LAPIC timer on AP (vector 48, ~1000 Hz)
        super::apic::init_timer(48, 100_000);

        // 6. Enable interrupts and enter scheduler loop
        // After each timer interrupt (vector 48), check if the scheduler
        // wants to reschedule. If so, pick up a runnable task.
        core::arch::asm!("sti", options(nostack, preserves_flags));
        loop {
            core::arch::asm!("hlt", options(nostack, nomem));
            // After waking from hlt (timer fired), check reschedule
            let sched = crate::scheduler::get();
            if sched.need_resched {
                sched.schedule();
            }
        }
    }
}

/// Detect CPU features by querying all CPUID leaves.
unsafe fn detect_x86_features() -> rux_arch::cpu::CpuFeatures {
    use rux_arch::x86_64::cpu::*;

    // Leaf 1: basic features
    let (ecx1, edx1): (u32, u32);
    core::arch::asm!(
        "push rbx", "cpuid", "pop rbx",
        inout("eax") 1u32 => _, lateout("ecx") ecx1, lateout("edx") edx1,
        options(nostack)
    );
    let f1 = parse_cpuid_01(ecx1, edx1);

    // Leaf 7 subleaf 0: extended features
    let ebx7: u64;
    core::arch::asm!(
        "push rbx", "cpuid", "mov {out}, rbx", "pop rbx",
        out = out(reg) ebx7,
        inout("eax") 7u32 => _, inout("ecx") 0u32 => _, lateout("edx") _,
        options(nostack)
    );
    let ebx7 = ebx7 as u32;
    let f7 = parse_cpuid_07(ebx7);

    // Extended leaf 0x80000001: NX, GBPAGES
    let edx_ext1: u32;
    core::arch::asm!(
        "push rbx", "cpuid", "pop rbx",
        inout("eax") 0x80000001u32 => _, lateout("ecx") _, lateout("edx") edx_ext1,
        options(nostack)
    );
    let fe1 = parse_cpuid_ext_01(edx_ext1);

    // Extended leaf 0x80000007: invariant TSC
    let edx_ext7: u32;
    core::arch::asm!(
        "push rbx", "cpuid", "pop rbx",
        inout("eax") 0x80000007u32 => _, lateout("ecx") _, lateout("edx") edx_ext7,
        options(nostack)
    );
    let fe7 = parse_cpuid_ext_07(edx_ext7);

    f1.or(f7).or(fe1).or(fe7)
}

pub fn x86_64_init(multiboot_info: usize) {
    // Initialize BSP per-CPU data
    unsafe { crate::percpu::init_bsp(); }

    // Initialize GDT with TSS — use the actual boot_stack_top from boot.S
    unsafe {
        extern "C" { static boot_stack_top: u8; }
        let stack_top = &boot_stack_top as *const u8 as u64;
        super::gdt::init(stack_top);
    }
    console::write_str("rux: GDT + TSS loaded\n");

    // Set GS-base AFTER GDT init (GDT init zeros GS segment, clearing hidden base)
    unsafe { crate::percpu::init_this_cpu(0); }

    // Detect and enable CPU features
    unsafe {
        use rux_arch::x86_64::cpu::*;
        let features = detect_x86_features();
        rux_arch::cpu::set_cpu_features(features);

        // Enable features via CR4
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
        cr4 |= 1 << 7; // PGE: Page Global Enable (required for GLOBAL bit in huge pages)
        if features.has(PCID)     { cr4 |= 1 << 17; console::write_str("rux: PCID enabled\n"); }
        if features.has(SMEP)     { cr4 |= 1 << 20; console::write_str("rux: SMEP enabled\n"); }
        if features.has(FSGSBASE) { cr4 |= 1 << 16; console::write_str("rux: FSGSBASE enabled\n"); }
        if features.has(SMAP) {
            // SMAP requires hardware support for stac/clac instructions.
            // QEMU TCG (software emulation) does not support SMAP — stac/clac
            // cause #UD. Only enable on real hardware or KVM.
            // cr4 |= 1 << 21;
            // console::write_str("rux: SMAP enabled\n");
            console::write_str("rux: SMAP detected (not enabled on TCG)\n");
        }
        // Must set CR4 before enabling stac/clac guards

        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));

        // Activate stac/clac runtime guards now that CR4 is set
        if features.has(SMAP) {
            crate::uaccess::enable_smap_guards();
        }
    }

    // Initialize IDT with all exception/IRQ handlers
    unsafe { super::idt::init(); }
    console::write_str("rux: IDT loaded\n");

    // Initialize SYSCALL/SYSRET MSRs for Linux ABI
    unsafe { super::syscall::init_syscall_msrs(); }

    // Initialize PIT timer at 1000 Hz
    unsafe { super::pit::init(1000); }
    console::write_str("rux: PIT timer initialized (1000 Hz)\n");

    // Enable interrupts
    unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)); }
    console::write_str("rux: interrupts enabled\n");

    // Wait for some timer ticks
    let start = super::pit::ticks();
    while super::pit::ticks() < start + 10 {
        core::hint::spin_loop();
    }
    console::write_str("rux: timer OK\n");

    // ── Parse multiboot memory map ──────────────────────────────────────
    console::write_str("rux: multiboot info at ");
    { let mut __hb = [0u8; 16]; console::write_str("0x"); console::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, multiboot_info)); }
    console::write_str("\n");
    let memmap = unsafe { super::multiboot::parse_memory_map(multiboot_info) };
    console::write_str("rux: memory map (");
    let mut buf = [0u8; 10];
    console::write_str(rux_klib::fmt::u32_to_str(&mut buf, memmap.count as u32));
    console::write_str(" regions, ");
    console::write_str(rux_klib::fmt::u32_to_str(&mut buf, (memmap.total_usable / (1024 * 1024)) as u32));
    console::write_str(" MiB usable)\n");

    for i in 0..memmap.count {
        let r = &memmap.regions[i];
        console::write_str("  ");
        { let mut __hb = [0u8; 16]; console::write_str("0x"); console::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, r.base.as_usize())); }
        console::write_str(" - ");
        { let mut __hb = [0u8; 16]; console::write_str("0x"); console::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, r.base.as_usize() + r.size)); }
        console::write_str(" (");
        console::write_str(rux_klib::fmt::u32_to_str(&mut buf, (r.size / 1024) as u32));
        console::write_str(" KiB)\n");
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

        console::write_str("rux: init allocator at ");
        { let mut __hb = [0u8; 16]; console::write_str("0x"); console::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, alloc_base)); }
        console::write_str(" (");
        console::write_str(rux_klib::fmt::u32_to_str(&mut buf, frames));
        console::write_str(" frames)\n");

        unsafe {
            console::write_str("rux: zeroing allocator...\n");
            let alloc_ptr = 0x300000 as *mut u64;
            let alloc_qwords = core::mem::size_of::<rux_mm::frame::BuddyAllocator>() / 8;
            for i in 0..alloc_qwords {
                core::ptr::write_volatile(alloc_ptr.add(i), 0u64);
            }
            console::write_str("rux: zeroing done\n");

            let alloc = &mut *(0x300000 as *mut rux_mm::frame::BuddyAllocator);
            console::write_str("rux: calling init...\n");
            alloc.init(rux_klib::PhysAddr::new(alloc_base), frames);
            console::write_str("rux: init done\n");

            // ── Activate kernel page tables ─────────────────────────────
            console::write_str("rux: building kernel page tables...\n");
            let mut kpt = super::paging::PageTable4Level::new(alloc)
                .expect("failed to create kernel page table");
            let rwx = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::EXECUTE);
            kpt.identity_map_range_huge(
                rux_klib::PhysAddr::new(0),
                128 * 1024 * 1024,
                rwx,
                alloc,
            ).expect("identity map failed");
            // Map LAPIC MMIO for SMP
            let dev_flags = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::NO_CACHE);
            kpt.identity_map_range(
                rux_klib::PhysAddr::new(0xFEE00000), 4096, dev_flags, alloc,
            ).expect("lapic map");
            console::write_str("rux: identity mapped 0-128 MiB + LAPIC\n");

            super::paging::activate(&kpt);
            pgtrack::set_kernel_pt(kpt.root_phys().as_usize() as u64);
            console::write_str("rux: CR3 switched to kernel page tables!\n");
        }
    }

    // ── ACPI / NUMA topology ─────────────────────────────────────────────
    // Identity map is active (0-128MB + LAPIC). RSDP at 0xE0000 is accessible.
    unsafe {
        if let Some(rsdp) = super::acpi::find_rsdp() {
            console::write_str("rux: ACPI RSDP found\n");
            if let Some(srat) = super::acpi::find_srat(rsdp) {
                let topo = super::acpi::parse_srat(srat);
                if topo.count > 0 {
                    console::write_str("rux: NUMA: ");
                    let mut buf3 = [0u8; 10];
                    console::write_str(rux_klib::fmt::u32_to_str(&mut buf3, topo.count as u32));
                    console::write_str(" memory regions\n");
                } else {
                    console::write_str("rux: UMA system (no SRAT entries)\n");
                }
            } else {
                console::write_str("rux: no SRAT (UMA)\n");
            }
        } else {
            console::write_str("rux: no ACPI RSDP\n");
        }
    }

    // ── Init scheduler (needed for vfork/exec) ──────────────────────────
    unsafe { scheduler::init_context_fns(); }

    // ── SMP: LAPIC init + AP startup ────────────────────────────────────
    // LAPIC MMIO is now mapped (identity_map_range in kpt setup above).
    // PIT timer is running (initialized above). Safe to init LAPIC and start APs.
    unsafe {
        super::apic::init_bsp();
        // GS-base already set for BSP at boot (init_this_cpu(0) above)
        let bsp_id = super::apic::bsp_id();
        console::write_str("rux: BSP LAPIC ID=");
        let mut buf2 = [0u8; 10];
        console::write_str(rux_klib::fmt::u32_to_str(&mut buf2, bsp_id));
        console::write_str("\n");

        // Copy AP trampoline to physical 0x8000
        extern "C" {
            static ap_trampoline_start: u8;
            static ap_trampoline_end: u8;
        }
        let src = &ap_trampoline_start as *const u8;
        let end = &ap_trampoline_end as *const u8;
        let size = end as usize - src as usize;
        core::ptr::copy_nonoverlapping(src, 0x8000 as *mut u8, size);

        // Start APs: try CPUs 1..MAX_CPUS, skip if SIPI times out
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        let data = 0x8F00 as *mut u64;

        // Try up to 4 APs (QEMU -smp N, max N=4 for reasonable boot time).
        // Each failed SIPI costs ~50ms timeout. Larger N needs MADT detection.
        let max_aps = 4usize.min(crate::percpu::MAX_CPUS);
        for ap_id in 1..max_aps {
            *data.add(0) = cr3;
            *data.add(1) = crate::task_table::KSTACKS[ap_id].as_ptr() as u64
                + crate::task_table::KSTACK_SIZE as u64;
            *data.add(2) = ap_entry as *const () as u64;
            *data.add(3) = ap_id as u64;

            super::apic::send_init(ap_id as u32);
            let t0 = super::pit::ticks();
            while super::pit::ticks() - t0 < 10 { core::hint::spin_loop(); }
            super::apic::send_sipi(ap_id as u32, 0x08);

            let t0 = super::pit::ticks();
            while super::pit::ticks() - t0 < 20 { // 20ms timeout
                if crate::percpu::cpu(ap_id).online { break; }
                core::hint::spin_loop();
            }
            if !crate::percpu::cpu(ap_id).online { break; } // no more APs

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
        static mut PROCFS: rux_fs::procfs::ProcFs = rux_fs::procfs::ProcFs::new(
            || super::pit::ticks(),
            || 16384,
            || unsafe {
                use rux_mm::FrameAllocator;
                (*(0x300000 as *const rux_mm::frame::BuddyAllocator))
                    .available_frames(rux_mm::PageSize::FourK)
            },
        );
        crate::boot::boot(crate::boot::BootParams {
            alloc_ptr: 0x300000 as *mut rux_mm::frame::BuddyAllocator,
            ramfs_ptr: 0x310000 as *mut rux_fs::ramfs::RamFs,
            initrd: super::multiboot::get_initrd(multiboot_info),
            procfs: &mut *(&raw mut PROCFS),
            log: console::write_str,
        });
    }
}

