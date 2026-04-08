/// Global Descriptor Table + Task State Segment for x86_64.
///
/// In long mode, segmentation is mostly disabled — the GDT exists only
/// for the CPU to find the TSS (which holds the kernel stack pointers
/// for privilege-level transitions) and to set CS/SS for ring 0/3.

/// GDT entry (8 bytes). In 64-bit mode, code/data descriptors are
/// mostly ignored except for L (long mode), DPL, and Present bits.
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct GdtEntry(u64);

/// TSS entry in the GDT is 16 bytes (two GDT slots).
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct TssEntry {
    low: u64,
    high: u64,
}

/// Task State Segment — holds kernel stack pointers for ring transitions.
#[repr(C, packed)]
pub struct Tss {
    reserved0: u32,
    /// Ring 0 stack pointer — loaded on interrupt from ring 3.
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    reserved1: u64,
    /// Interrupt Stack Table — alternative stacks for specific vectors.
    pub ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// Offset to I/O permission bitmap (set to size of TSS = no bitmap).
    pub iopb_offset: u16,
}

/// Our GDT: null + kernel code + kernel data + user code + user data + TSS.
#[repr(C, align(16))]
struct Gdt {
    null: GdtEntry,
    kernel_code: GdtEntry,   // selector 0x08
    kernel_data: GdtEntry,   // selector 0x10
    user_data: GdtEntry,     // selector 0x18 (user data before user code for sysret)
    user_code: GdtEntry,     // selector 0x20
    tss: TssEntry,           // selector 0x28 (16 bytes = 2 entries)
}

/// Segment selectors.
pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16   = 0x18 | 3; // RPL=3
pub const USER_CS: u16   = 0x20 | 3; // RPL=3
pub const TSS_SEL: u16   = 0x28;

static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iopb_offset: 104, // size of TSS struct
};

static mut GDT: Gdt = Gdt {
    null: GdtEntry(0),
    // Kernel code: L=1(long mode), D=0, P=1, DPL=0, type=execute/read
    kernel_code: GdtEntry(0x00AF_9A00_0000_FFFF),
    // Kernel data: P=1, DPL=0, type=read/write
    kernel_data: GdtEntry(0x00CF_9200_0000_FFFF),
    // User data: P=1, DPL=3, type=read/write
    user_data: GdtEntry(0x00CF_F200_0000_FFFF),
    // User code: L=1, D=0, P=1, DPL=3, type=execute/read
    user_code: GdtEntry(0x00AF_FA00_0000_FFFF),
    // TSS: filled in at init time
    tss: TssEntry { low: 0, high: 0 },
};

/// GDTR pointer structure.
#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

/// Initialize the GDT with a TSS pointing to the boot stack.
/// `kernel_stack_top` is the RSP0 value for ring 3 → ring 0 transitions.
pub unsafe fn init(kernel_stack_top: u64) {
    // Set up TSS
    TSS.rsp0 = kernel_stack_top;
    TSS.iopb_offset = core::mem::size_of::<Tss>() as u16;

    // Encode TSS descriptor into GDT
    let tss_addr = (&raw const TSS) as *const Tss as u64;
    let tss_size = (core::mem::size_of::<Tss>() - 1) as u64;

    let low: u64 = (tss_size & 0xFFFF)
        | ((tss_addr & 0xFFFF) << 16)
        | (((tss_addr >> 16) & 0xFF) << 32)
        | (0b1000_1001u64 << 40) // P=1, DPL=0, type=0x9 (64-bit TSS available)
        | (((tss_size >> 16) & 0xF) << 48)
        | (((tss_addr >> 24) & 0xFF) << 56);
    let high: u64 = tss_addr >> 32;

    GDT.tss = TssEntry { low, high };

    // Load GDT
    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of::<Gdt>() - 1) as u16,
        base: (&raw const GDT) as *const Gdt as u64,
    };

    core::arch::asm!(
        "lgdt [{}]",
        in(reg) &gdt_ptr,
        options(nostack)
    );

    // Reload CS via far return
    core::arch::asm!(
        "push {kcs}",
        "lea {tmp}, [rip + 2f]",
        "push {tmp}",
        "retfq",
        "2:",
        kcs = in(reg) KERNEL_CS as u64,
        tmp = lateout(reg) _,
        options(preserves_flags)
    );

    // Reload data segments
    core::arch::asm!(
        "mov ds, {0:x}",
        "mov es, {0:x}",
        "mov ss, {0:x}",
        "xor {1:e}, {1:e}",
        "mov fs, {1:x}",
        "mov gs, {1:x}",
        in(reg) KERNEL_DS,
        lateout(reg) _,
        options(nostack, preserves_flags)
    );

    // Load TSS
    core::arch::asm!(
        "ltr {0:x}",
        in(reg) TSS_SEL,
        options(nostack, preserves_flags)
    );
}

/// Update TSS.rsp0 for the current CPU. Called on context switch so that
/// interrupts from user mode land on the new task's kernel stack.
pub unsafe fn set_rsp0(rsp0: u64) {
    let id = crate::percpu::cpu_id();
    if id == 0 {
        TSS.rsp0 = rsp0;
    } else {
        TSS_PERCPU[id].rsp0 = rsp0;
    }
}

// ── Per-CPU GDT + TSS for AP startup ────────────────────────────────

use crate::percpu::MAX_CPUS;

static mut TSS_PERCPU: [Tss; MAX_CPUS] = {
    const EMPTY: Tss = Tss {
        reserved0: 0, rsp0: 0, rsp1: 0, rsp2: 0,
        reserved1: 0, ist: [0; 7], reserved2: 0, reserved3: 0, iopb_offset: 104,
    };
    [EMPTY; MAX_CPUS]
};

static mut GDT_PERCPU: [Gdt; MAX_CPUS] = {
    const EMPTY: Gdt = Gdt {
        null: GdtEntry(0),
        kernel_code: GdtEntry(0x00AF_9A00_0000_FFFF),
        kernel_data: GdtEntry(0x00CF_9200_0000_FFFF),
        user_data: GdtEntry(0x00CF_F200_0000_FFFF),
        user_code: GdtEntry(0x00AF_FA00_0000_FFFF),
        tss: TssEntry { low: 0, high: 0 },
    };
    [EMPTY; MAX_CPUS]
};

/// Initialize per-CPU GDT + TSS for an AP. Called from ap_entry().
pub unsafe fn init_ap(cpu_id: usize, kernel_stack_top: u64) {
    let tss = &mut TSS_PERCPU[cpu_id];
    tss.rsp0 = kernel_stack_top;
    tss.iopb_offset = core::mem::size_of::<Tss>() as u16;

    let tss_addr = tss as *const Tss as u64;
    let tss_size = (core::mem::size_of::<Tss>() - 1) as u64;

    let low: u64 = (tss_size & 0xFFFF)
        | ((tss_addr & 0xFFFF) << 16)
        | (((tss_addr >> 16) & 0xFF) << 32)
        | (0b1000_1001u64 << 40)
        | (((tss_size >> 16) & 0xF) << 48)
        | (((tss_addr >> 24) & 0xFF) << 56);
    let high: u64 = tss_addr >> 32;

    let gdt = &mut GDT_PERCPU[cpu_id];
    gdt.tss = TssEntry { low, high };

    let gdt_ptr = GdtPtr {
        limit: (core::mem::size_of::<Gdt>() - 1) as u16,
        base: gdt as *const Gdt as u64,
    };

    core::arch::asm!("lgdt [{}]", in(reg) &gdt_ptr, options(nostack));

    // Reload CS via far return
    core::arch::asm!(
        "push {kcs}", "lea {tmp}, [rip + 2f]", "push {tmp}", "retfq", "2:",
        kcs = in(reg) KERNEL_CS as u64, tmp = lateout(reg) _,
        options(preserves_flags)
    );

    // Reload data segments
    core::arch::asm!(
        "mov ds, {0:x}", "mov es, {0:x}", "mov ss, {0:x}",
        "xor {1:e}, {1:e}", "mov fs, {1:x}", "mov gs, {1:x}",
        in(reg) KERNEL_DS, lateout(reg) _,
        options(nostack, preserves_flags)
    );

    // Load TSS
    core::arch::asm!("ltr {0:x}", in(reg) TSS_SEL, options(nostack, preserves_flags));
}
