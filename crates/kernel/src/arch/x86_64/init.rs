/// x86_64 boot initialization: hardware setup and shell launch.

use super::console;
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
        let kstack_top = crate::task_table::KSTACKS.0[cpu_id as usize].as_ptr() as usize
            + crate::task_table::KSTACK_SIZE;
        super::gdt::init_ap(cpu_id as usize, kstack_top as u64);

        // 2. SYSCALL MSRs
        super::syscall::init_syscall_msrs();

        // 3. IDT (shared with BSP — IDT is the same for all CPUs)
        super::idt::load();

        // 4. Enable FSGSBASE (required for rdgsbase in percpu_base)
        {
            let mut cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
            cr4 |= 1 << 16;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        }

        // 5. Set GS-base + per-CPU state
        crate::percpu::init_this_cpu(cpu_id as usize);
        let pc = crate::percpu::cpu(cpu_id as usize);
        pc.cpu_id = cpu_id;
        pc.syscall_kstack_top = kstack_top as u64;
        pc.online = true;
        pc.idle = true;
        pc.current_task_idx = 0; // idle task
        pc.irq_stack_top = crate::task_table::IRQ_STACKS.0[cpu_id as usize].as_ptr() as u64
            + crate::task_table::IRQ_STACK_SIZE as u64 - 8;

        // 6. Enable LAPIC. Timer only on KVM (TCG shared globals prevent AP scheduling).
        super::apic::enable_lapic();
        if super::syscall::GS_PERCPU_ACTIVE {
            super::apic::init_timer(48, 100_000);
        }

        // 6. Enable interrupts and enter scheduler loop
        // After each timer interrupt (vector 48), check if the scheduler
        // wants to reschedule. If so, pick up a runnable task.
        core::arch::asm!("sti", options(nostack, preserves_flags));
        loop {
            core::arch::asm!("hlt", options(nostack, nomem));
            // After waking from hlt (timer fired), check reschedule
            let sched = crate::scheduler::get();
            if sched.need_resched & (1u64 << crate::percpu::cpu_id() as u32) != 0 {
                crate::arch::preempt_disable();
                sched.schedule();
                crate::arch::preempt_enable();
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
    let ecx7_out: u32;
    let edx7_out: u32;
    core::arch::asm!(
        "push rbx", "cpuid", "mov {out}, rbx", "pop rbx",
        out = out(reg) ebx7,
        inout("eax") 7u32 => _, inout("ecx") 0u32 => ecx7_out, lateout("edx") edx7_out,
        options(nostack)
    );
    let ebx7 = ebx7 as u32;
    let f7 = parse_cpuid_07(ebx7, ecx7_out, edx7_out);

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

/// Detect if running on KVM via CPUID hypervisor leaf.
/// Returns true if CPUID(0x40000000) signature is "KVMKVMKVM\0\0\0".
unsafe fn detect_kvm() -> bool {
    let max_leaf: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // CPUID clobbers ebx which LLVM reserves; save/restore manually
    core::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {ebx:e}, ebx",
        "pop rbx",
        inout("eax") 0x40000000u32 => max_leaf,
        ebx = lateout(reg) ebx,
        lateout("ecx") ecx,
        lateout("edx") edx,
        options(nostack),
    );
    // KVM signature: EBX="KVMK", ECX="VMKV", EDX="M\0\0\0"
    if max_leaf >= 0x40000000 {
        ebx == 0x4b564d4b && ecx == 0x564b4d56 && edx == 0x0000004d
    } else {
        false
    }
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
    unsafe {
        crate::percpu::init_this_cpu(0);
        // Per-CPU IRQ stack for BSP (Linux call_on_irq_stack approach).
        // -8 to leave room for the saved RSP at the top (Linux convention).
        super::syscall::CURRENT_IRQ_STACK_TOP =
            crate::task_table::IRQ_STACKS.0[0].as_ptr() as u64
            + crate::task_table::IRQ_STACK_SIZE as u64 - 8;
    }

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
        if features.has(UMIP) { cr4 |= 1 << 11; console::write_str("rux: UMIP enabled\n"); }
        if features.has(SMAP) {
            // SMAP CR4 bit deferred until after KVM detection.
            // QEMU TCG's SMAP + stac/clac interaction is unreliable
            // from syscall paths — enable only on KVM/real hardware.
        }

        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));

        // Enable CR0.WP — enforce read-only pages in ring 0
        {
            let mut cr0: u64;
            core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack));
            cr0 |= 1 << 16;
            core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
        }
        console::write_str("rux: CR0.WP enabled\n");

        // Spectre mitigations: enable IBRS + STIBP if detected
        if features.has(IBRS) || features.has(STIBP) {
            let mut spec_ctrl: u64 = 0;
            if features.has(IBRS) { spec_ctrl |= 1; }   // bit 0 = IBRS
            if features.has(STIBP) { spec_ctrl |= 2; }  // bit 1 = STIBP
            core::arch::asm!(
                "wrmsr",
                in("ecx") 0x48u32,  // IA32_SPEC_CTRL
                in("eax") spec_ctrl as u32,
                in("edx") 0u32,
                options(nostack),
            );
            if features.has(IBRS) { console::write_str("rux: IBRS enabled\n"); }
            if features.has(STIBP) { console::write_str("rux: STIBP enabled\n"); }
        }

        // Activate stac/clac runtime guards (run as no-ops until CR4.SMAP is set)
        if features.has(SMAP) {
            crate::uaccess::enable_smap_guards();
        }
    }

    // Detect KVM and enable per-CPU GS-based syscall entry
    unsafe {
        if detect_kvm() {
            super::syscall::GS_PERCPU_ACTIVE = true;
            console::write_str("rux: KVM detected, using gs-based syscall entry\n");

            // Enable SMAP in CR4 on KVM (stac/clac work reliably)
            if rux_arch::cpu::cpu_features().has(rux_arch::x86_64::cpu::SMAP) {
                let mut cr4: u64;
                core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
                cr4 |= 1 << 21;
                core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
                console::write_str("rux: SMAP enforced (KVM)\n");
            }
        } else {
            console::write_str("rux: TCG mode, using RIP-relative syscall entry\n");
            if rux_arch::cpu::cpu_features().has(rux_arch::x86_64::cpu::SMAP) {
                console::write_str("rux: SMAP detected (TCG: CR4 deferred, guards active)\n");
            }
        }
    }

    // Initialize IDT with all exception/IRQ handlers
    unsafe { super::idt::init(); }
    console::write_str("rux: IDT loaded\n");

    // Initialize SYSCALL/SYSRET MSRs for Linux ABI
    // (selects syscall_entry vs syscall_entry_gs based on GS_PERCPU_ACTIVE)
    unsafe { super::syscall::init_syscall_msrs(); }

    // Read hardware RTC for wall-clock time
    unsafe {
        let rtc_epoch = super::rtc::read_rtc();
        crate::syscall::process::set_boot_epoch(rtc_epoch);
    }
    console::write_str("rux: CMOS RTC read\n");

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

    // ── Compute addresses for BuddyAllocator + RamFs ──────────────────
    // Place after the kernel image (_end from linker script). Use _end as a
    // floor so growing BSS (e.g., raising MAX_PROCS) never overlaps.
    // Keep a 0x600000 minimum for historical compatibility.
    extern "C" { static _end: u8; }
    let kernel_end = unsafe { &_end as *const u8 as usize };

    let initrd_info = unsafe { super::multiboot::get_initrd(multiboot_info) };
    let initrd_end = match initrd_info {
        Some((start, size)) => ((start + size) + 0xFFF) & !0xFFF,
        None => 0,
    };
    let alloc_size_bytes = core::mem::size_of::<rux_mm::frame::BuddyAllocator>();
    let alloc_addr = initrd_end.max(kernel_end).max(0x600000);
    let ramfs_addr = (alloc_addr + alloc_size_bytes + 0xFFF) & !0xFFF;
    let ramfs_end = (ramfs_addr + core::mem::size_of::<rux_fs::ramfs::RamFs>() + 0xFFF) & !0xFFF;

    // Log computed layout
    {
        let mut hx = [0u8; 16];
        console::write_str("rux: _end=0x");
        console::write_bytes(rux_klib::fmt::usize_to_hex(&mut hx, kernel_end));
        console::write_str(" alloc@0x");
        console::write_bytes(rux_klib::fmt::usize_to_hex(&mut hx, alloc_addr));
        console::write_str(" ramfs@0x");
        console::write_bytes(rux_klib::fmt::usize_to_hex(&mut hx, ramfs_addr));
        console::write_str("\n");
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
        // Frame allocation must be above kernel BSS (which includes
        // BUDDY_ALLOC and RAMFS statics) and the initrd.
        let initrd_end = match unsafe { super::multiboot::get_initrd(multiboot_info) } {
            Some((start, size)) => ((start + size) + 0xFFF) & !0xFFF,
            None => 0,
        };
        let min_alloc_base = kernel_end.max(0x780000).max(ramfs_end).max(initrd_end);
        let alloc_base = if region.base.as_usize() < min_alloc_base {
            min_alloc_base
        } else {
            region.base.as_usize()
        };
        let alloc_size = region.size - (alloc_base - region.base.as_usize());
        let frames = (alloc_size / 4096) as u32;
        // Cap at identity-map range (128MB) or MAX_FRAMES, whichever is smaller.
        let id_map_frames = ((0x8000000usize.saturating_sub(alloc_base)) / 4096) as u32;
        let frames = frames.min(id_map_frames).min(rux_mm::frame::MAX_FRAMES as u32);

        console::write_str("rux: init allocator at ");
        { let mut __hb = [0u8; 16]; console::write_str("0x"); console::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, alloc_base)); }
        console::write_str(" (");
        console::write_str(rux_klib::fmt::u32_to_str(&mut buf, frames));
        console::write_str(" frames)\n");

        unsafe {
            console::write_str("rux: zeroing allocator...\n");
            let alloc_ptr = alloc_addr as *mut u64;
            let alloc_qwords = alloc_size_bytes / 8;
            for i in 0..alloc_qwords {
                core::ptr::write_volatile(alloc_ptr.add(i), 0u64);
            }
            console::write_str("rux: zeroing done\n");

            let alloc = &mut *(alloc_addr as *mut rux_mm::frame::BuddyAllocator);
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

            // Split the first 2MB huge page into 4K pages so we can
            // unmap individual pages for null guard and stack guards.
            kpt.split_huge_page(
                rux_klib::VirtAddr::new(0), rux_mm::PageLevel::L1, alloc,
            ).expect("split first 2MB page");

            // Null pointer guard: unmap page 0
            let _ = kpt.unmap_4k(rux_klib::VirtAddr::new(0));
            console::write_str("rux: page 0 unmapped (null guard)\n");

            // Guard pages at bottom of each kernel stack (catches overflow).
            // KSTACKS is page-aligned; each 32KB stack starts on a page boundary.
            // Unmapping the bottom page gives 28KB usable per stack.
            for i in 0..crate::task_table::MAX_PROCS {
                let stack_bottom = crate::task_table::KSTACKS.0[i].as_ptr() as usize;
                let guard_page = stack_bottom & !0xFFF;
                // Split the 2MB page containing this guard if not already split
                let huge_base = guard_page & !0x1FFFFF;
                if huge_base != 0 { // page at 0 already split above
                    let _ = kpt.split_huge_page(
                        rux_klib::VirtAddr::new(huge_base),
                        rux_mm::PageLevel::L1, alloc,
                    );
                }
                let _ = kpt.unmap_4k(rux_klib::VirtAddr::new(guard_page));
            }
            console::write_str("rux: kernel stack guard pages active\n");

            // Make kernel .text read-only (READ+EXECUTE, no WRITE).
            // Section boundaries determined at build time. .text starts after
            // the multiboot header page (0x101000) and extends to the page
            // BEFORE .rodata. We protect conservatively using page-aligned
            // ranges — pages shared between sections keep the more permissive
            // flags (WRITE) to avoid faulting.
            //
            // Layout (from objdump, may shift with code changes):
            //   .text:   0x101000  (~128KB)
            //   .rodata: 0x121000  (~20KB)   (page after .text end)
            //   .data:   0x126000  (~140KB)
            //
            // We protect .text pages that are ENTIRELY within .text (not shared
            // with .rodata). Since .text end may not be page-aligned, the last
            // .text page might contain .rodata start — leave it writable.
            //
            // Use the .rodata section start as the conservative .text end.
            // The .data start is the conservative .rodata end.
            // These addresses are stable across builds (sections don't overlap).

            // Use linker-exported symbols for section boundaries.
            // These are defined in linker-x86_64.ld and update automatically.
            extern "C" {
                static __text_start: u8;
                static __text_end: u8;
                static __rodata_end: u8;
                static __data_start: u8;
            }
            let text_start = (&__text_start as *const u8 as usize) & !0xFFF;
            let text_end_page = ((&__text_end as *const u8 as usize) + 0xFFF) & !0xFFF;
            let rodata_end_page = (&__data_start as *const u8 as usize) & !0xFFF;

            // .text → RX
            {
                let rx = rux_mm::MappingFlags::READ.or(rux_mm::MappingFlags::EXECUTE);
                let mut addr = text_start;
                while addr < text_end_page {
                    let _ = kpt.protect_4k(rux_klib::VirtAddr::new(addr), rx);
                    addr += 4096;
                }
            }
            // .rodata → R (no WRITE, no EXECUTE)
            {
                let ro = rux_mm::MappingFlags::READ;
                let mut addr = text_end_page;
                while addr < rodata_end_page {
                    let _ = kpt.protect_4k(rux_klib::VirtAddr::new(addr), ro);
                    addr += 4096;
                }
            }
            console::write_str("rux: kernel .text/.rodata read-only\n");
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
            *data.add(1) = crate::task_table::KSTACKS.0[ap_id].as_ptr() as u64
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
        // Use computed addresses (above initrd) for allocator and ramfs
        static mut PROCFS: rux_fs::procfs::ProcFs = rux_fs::procfs::ProcFs::new(
            || super::pit::ticks(),
            || unsafe {
                use rux_mm::FrameAllocator;
                crate::kstate::alloc().total_frames()
            },
            || unsafe {
                use rux_mm::FrameAllocator;
                crate::kstate::alloc().available_frames(rux_mm::PageSize::FourK)
            },
            |buf| unsafe {
                use crate::task_table::*;
                let mut count = 0;
                for i in 0..MAX_PROCS {
                    if TASK_TABLE[i].active && TASK_TABLE[i].pid > 0 && TASK_TABLE[i].state != TaskState::Free && count < buf.len() {
                        buf[count] = TASK_TABLE[i].pid;
                        count += 1;
                    }
                }
                count
            },
            || crate::task_table::current_pid(),
            |pid, buf| unsafe {
                use crate::task_table::*;
                for i in 0..MAX_PROCS {
                    if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                        let len = (TASK_TABLE[i].cmdline_len as usize).min(buf.len());
                        buf[..len].copy_from_slice(&TASK_TABLE[i].cmdline[..len]);
                        return len;
                    }
                }
                0
            },
            |pid| unsafe {
                use crate::task_table::*;
                for i in 0..MAX_PROCS {
                    if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                        return rux_fs::procfs::TaskInfo {
                            pid: TASK_TABLE[i].pid,
                            ppid: TASK_TABLE[i].ppid,
                            pgid: TASK_TABLE[i].pgid,
                            sid: TASK_TABLE[i].sid,
                            uid: TASK_TABLE[i].uid,
                            gid: TASK_TABLE[i].gid,
                            state: TASK_TABLE[i].state as u8,
                            threads: 1,
                            rss_pages: TASK_TABLE[i].rss_pages,
                            brk_addr: TASK_TABLE[i].program_brk,
                        };
                    }
                }
                rux_fs::procfs::TaskInfo::default()
            },
            || crate::idle::idle_ticks(),
            |pid, buf| unsafe {
                use crate::task_table::*;
                for i in 0..MAX_PROCS {
                    if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                        let len = TASK_TABLE[i].fs_ctx.cwd_path_len.min(buf.len());
                        buf[..len].copy_from_slice(&TASK_TABLE[i].fs_ctx.cwd_path[..len]);
                        return len;
                    }
                }
                0
            },
            |pid, buf| unsafe {
                use crate::task_table::*;
                for i in 0..MAX_PROCS {
                    if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                        let len = (TASK_TABLE[i].environ_len as usize).min(buf.len());
                        buf[..len].copy_from_slice(&TASK_TABLE[i].environ[..len]);
                        return len;
                    }
                }
                0
            },
        );
        (&raw mut PROCFS).as_mut().unwrap().num_cpus = crate::percpu::online_cpus() as u32;
        crate::boot::boot(crate::boot::BootParams {
            alloc_ptr: alloc_addr as *mut rux_mm::frame::BuddyAllocator,
            ramfs_ptr: ramfs_addr as *mut rux_fs::ramfs::RamFs,
            initrd: initrd_info,
            procfs: &mut *(&raw mut PROCFS),
            log: console::write_str,
            cmdline: super::multiboot::get_cmdline(multiboot_info),
            virtio_mmio_base: 0, // x86_64 virtio-mmio not yet mapped
        });
    }
}

