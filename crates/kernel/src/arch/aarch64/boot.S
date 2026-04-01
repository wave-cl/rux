/*
 * aarch64 boot stub for QEMU virt machine.
 * QEMU loads at 0x40000000 and enters _start with:
 *   x0 = DTB (device tree blob) physical address
 */

.section .text._start
.global _start
_start:
    /* Save DTB pointer (x0) before we clobber it */
    mov     x19, x0

    /* Disable interrupts */
    msr     daifset, #0xF

    /* Enable FP/NEON (CPACR_EL1.FPEN = 0b11) */
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    /* Set up stack */
    adrp    x0, boot_stack_top
    add     x0, x0, :lo12:boot_stack_top
    mov     sp, x0

    /* Zero BSS — required for correct static initialization.
       Uses stp to zero 16 bytes per iteration for speed. */
    adrp    x1, __bss_start
    add     x1, x1, :lo12:__bss_start
    adrp    x2, __bss_end
    add     x2, x2, :lo12:__bss_end
1:  cmp     x1, x2
    b.ge    2f
    stp     xzr, xzr, [x1], #16
    b       1b
2:

    /* Pass DTB pointer as first argument to kernel_main */
    mov     x0, x19
    bl      kernel_main

1:  wfe
    b       1b

/* Boot stack: 64 KiB in BSS */
.section .bss
.align 16
boot_stack:
    .skip 65536
boot_stack_top:
