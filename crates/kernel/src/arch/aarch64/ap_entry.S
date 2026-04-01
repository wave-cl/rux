/*
 * AP (Application Processor) entry point for aarch64 SMP via PSCI.
 *
 * PSCI CPU_ON delivers the AP to this entry in EL1 with:
 *   x0 = context_id (we pass the CPU index)
 *
 * The AP must set up its own stack, enable FP/NEON, configure the MMU
 * (using BSP's page tables), then call the Rust ap_entry().
 *
 * Data passed via global AP_BOOT_DATA:
 *   +0x00: u64 ttbr0     (BSP's TTBR0_EL1 value for kernel page table)
 *   +0x08: u64 tcr       (BSP's TCR_EL1 value)
 *   +0x10: u64 mair      (BSP's MAIR_EL1 value)
 *   +0x18: u64 vbar      (BSP's VBAR_EL1 value)
 *   +0x20: u64 sctlr     (BSP's SCTLR_EL1 value, with MMU+cache enabled)
 *   +0x28: u64 stack_top (per-AP kernel stack top)
 *   +0x30: u64 entry_fn  (address of Rust ap_entry function)
 */

.section .text
.global ap_entry_asm

ap_entry_asm:
    /* x0 = cpu_index (context_id from PSCI CPU_ON) */
    mov     x19, x0                     /* save cpu_index */

    /* Disable interrupts */
    msr     daifset, #0xF

    /* Enable FP/NEON */
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    /* Load BSP's system register values from AP_BOOT_DATA */
    adrp    x1, AP_BOOT_DATA
    add     x1, x1, :lo12:AP_BOOT_DATA

    ldr     x2, [x1, #0x00]            /* TTBR0_EL1 */
    msr     ttbr0_el1, x2

    ldr     x2, [x1, #0x08]            /* TCR_EL1 */
    msr     tcr_el1, x2

    ldr     x2, [x1, #0x10]            /* MAIR_EL1 */
    msr     mair_el1, x2

    ldr     x2, [x1, #0x18]            /* VBAR_EL1 */
    msr     vbar_el1, x2

    isb
    tlbi    vmalle1is
    dsb     ish
    isb

    /* Enable MMU + caches */
    ldr     x2, [x1, #0x20]            /* SCTLR_EL1 */
    msr     sctlr_el1, x2
    isb

    /* Set up per-AP stack */
    ldr     x2, [x1, #0x28]            /* stack_top */
    mov     sp, x2

    /* Call Rust ap_entry(cpu_index) */
    mov     x0, x19                     /* cpu_index in first arg */
    ldr     x2, [x1, #0x30]            /* entry_fn */
    blr     x2

    /* Should never return */
1:  wfe
    b       1b

/* AP boot data — filled by BSP before calling PSCI CPU_ON */
.section .data
.global AP_BOOT_DATA
.align 8
AP_BOOT_DATA:
    .quad   0   /* ttbr0 */
    .quad   0   /* tcr */
    .quad   0   /* mair */
    .quad   0   /* vbar */
    .quad   0   /* sctlr */
    .quad   0   /* stack_top */
    .quad   0   /* entry_fn */
