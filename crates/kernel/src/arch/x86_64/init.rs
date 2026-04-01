/// x86_64 boot initialization: hardware setup and shell launch.

use super::{console, exit};
use crate::{scheduler, pgtrack};

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
    // Initialize GDT with TSS — use the actual boot_stack_top from boot.S
    unsafe {
        extern "C" { static boot_stack_top: u8; }
        let stack_top = &boot_stack_top as *const u8 as u64;
        super::gdt::init(stack_top);
    }
    console::write_str("rux: GDT + TSS loaded\n");

    // Detect and enable CPU features
    unsafe {
        use rux_arch::x86_64::cpu::*;
        let features = detect_x86_features();
        rux_arch::cpu::set_cpu_features(features);

        // Enable features via CR4
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
        if features.has(PCID)     { cr4 |= 1 << 17; console::write_str("rux: PCID enabled\n"); }
        if features.has(SMEP)     { cr4 |= 1 << 20; console::write_str("rux: SMEP enabled\n"); }
        if features.has(FSGSBASE) { cr4 |= 1 << 16; console::write_str("rux: FSGSBASE enabled\n"); }
        // SMAP (CR4 bit 21) deferred — requires stac/clac around user memory access
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
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
            kpt.identity_map_range(
                rux_klib::PhysAddr::new(0),
                128 * 1024 * 1024,
                rwx,
                alloc,
            ).expect("identity map failed");
            console::write_str("rux: identity mapped 0-128 MiB\n");

            super::paging::activate(&kpt);
            pgtrack::set_kernel_pt(kpt.root_phys().as_usize() as u64);
            console::write_str("rux: CR3 switched to kernel page tables!\n");
        }
    }

    // ── ACPI / NUMA topology (informational) ────────────────────────────
    // Scan for RSDP after identity map is active (0xE0000 region accessible).
    // Disabled on QEMU Multiboot1 — RSDP region may not be mapped correctly.
    // TODO: re-enable once RSDP scan is validated on real hardware.

    // ── Init scheduler (needed for vfork/exec) ──────────────────────────
    unsafe { scheduler::init_context_fns(); }

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

