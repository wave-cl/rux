/* Multiboot1 boot stub for x86_64. QEMU -kernel loads this and drops us
 * in 32-bit protected mode with identity-mapped memory. We set up long mode
 * and jump to the 64-bit Rust entry point.
 */

.att_syntax prefix

/* Multiboot header — must be in first 8K of the binary */
.section .multiboot2, "a"
.align 4
multiboot_header:
    .long 0x1BADB002             /* magic */
    .long 0x00000003             /* flags: align + meminfo */
    .long 0xE4524FFB             /* checksum: -(magic + flags) */

/* PVH entry note — tells QEMU -kernel to load us in 64-bit mode directly.
 * QEMU reads this ELF note and enters at the specified address in long mode
 * with identity-mapped memory, bypassing the 32-bit multiboot path entirely. */
.section .note.rux, "a"
.align 4
    .long 4                      /* namesz: "Xen\0" */
    .long 8                      /* descsz: 8 bytes (64-bit entry addr) */
    .long 18                     /* type: XEN_ELFNOTE_PHYS32_ENTRY */
    .asciz "Xen"                 /* name (4 bytes including null) */
    .long _pvh_start             /* entry point (32-bit, but we handle it) */
    .long 0                      /* padding for 8-byte descsz */

/* Entry point — 32-bit protected mode, no paging */
.section .text
.code32
.global _start
_start:
    /* Save multiboot info pointer (ebx) */
    movl %ebx, %edi

    /* Disable interrupts */
    cli

    /* Set up temporary page tables for identity map of first 2GB
     * using 2MB huge pages (only need PML4 → PDPT → PD, no PT level)
     *
     * PML4[0] → pdpt
     * PDPT[0] → pd
     * PD[0..1023] → 2MB pages identity mapping 0-2GB
     */

    /* Zero the page table area */
    movl $pml4, %edi
    xorl %eax, %eax
    movl $(3 * 4096 / 4), %ecx  /* 3 pages worth of dwords */
    rep stosl

    /* PML4[0] = &pdpt | PRESENT | WRITABLE */
    movl $pml4, %edi
    movl $pdpt, %eax
    orl  $0x03, %eax             /* present + writable */
    movl %eax, (%edi)

    /* PDPT[0] = &pd | PRESENT | WRITABLE */
    movl $pdpt, %edi
    movl $pd, %eax
    orl  $0x03, %eax
    movl %eax, (%edi)

    /* PD[0..1023] = i*2MB | PRESENT | WRITABLE | HUGE */
    movl $pd, %edi
    movl $0x00000083, %eax       /* present + writable + huge(PS) */
    movl $1024, %ecx
1:
    movl %eax, (%edi)
    addl $0x200000, %eax         /* next 2MB */
    addl $8, %edi
    loop 1b

    /* Load PML4 into CR3 */
    movl $pml4, %eax
    movl %eax, %cr3

    /* Enable PAE (CR4.PAE = bit 5) */
    movl %cr4, %eax
    orl  $(1 << 5), %eax
    movl %eax, %cr4

    /* Enable long mode (EFER.LME = bit 8) */
    movl $0xC0000080, %ecx       /* IA32_EFER MSR */
    rdmsr
    orl  $(1 << 8), %eax
    wrmsr

    /* Enable paging (CR0.PG = bit 31) — this activates long mode */
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

    /* Load a 64-bit GDT and far jump to 64-bit code */
    lgdt gdt64_ptr
    ljmp $0x08, $long_mode_entry

/* 64-bit code */
.code64
long_mode_entry:
    /* Set up 64-bit data segments */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Set up stack (grows down from top of boot_stack) */
    movabs $boot_stack_top, %rsp

    /* Restore multiboot info pointer (was saved in edi, now in rdi for SysV ABI) */
    /* edi was set before paging — still valid since we identity-mapped */
    movl %edi, %edi              /* zero-extend edi to rdi */

    /* Call Rust entry point: kernel_main(multiboot_info: usize) */
    call kernel_main

    /* Should not return, but just in case: */
    cli
    hlt
    jmp .

/* Minimal 64-bit GDT */
.align 16
gdt64:
    .quad 0x0000000000000000     /* null descriptor */
    .quad 0x00AF9A000000FFFF     /* 64-bit code: L=1, D=0, P=1, DPL=0, type=execute/read */
    .quad 0x00CF92000000FFFF     /* 64-bit data: P=1, DPL=0, type=read/write */
gdt64_end:

gdt64_ptr:
    .word gdt64_end - gdt64 - 1
    .long gdt64

/* Page tables — must be page-aligned */
.section .bss
.align 4096
pml4:   .skip 4096
pdpt:   .skip 4096
pd:     .skip 4096

/* Boot stack — 16 KiB */
.align 16
boot_stack:
    .skip 16384
boot_stack_top:
