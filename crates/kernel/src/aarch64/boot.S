/*
 * aarch64 boot stub for QEMU virt machine.
 * QEMU loads at 0x40000000 and enters _start.
 */

.section .text._start
.global _start
_start:
    /* Disable interrupts */
    msr     daifset, #0xF

    /* Set up stack at the top of the boot_stack in BSS */
    adrp    x0, boot_stack_top
    add     x0, x0, :lo12:boot_stack_top
    mov     sp, x0

    /* Jump to Rust */
    bl      kernel_main

    /* Should not return */
1:  wfe
    b       1b

/* Boot stack: 64 KiB in BSS */
.section .bss
.align 16
boot_stack:
    .skip 65536
boot_stack_top:
