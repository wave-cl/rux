/*
 * AP (Application Processor) startup trampoline for x86_64 SMP.
 *
 * This code is copied to physical address 0x8000 by the BSP before
 * sending SIPI (Startup IPI). The AP enters at ap_trampoline_start
 * in 16-bit real mode and must:
 *   1. Enable protected mode
 *   2. Enable PAE + long mode
 *   3. Load BSP's page tables (CR3)
 *   4. Enable paging
 *   5. Jump to 64-bit code
 *   6. Set up stack and call Rust ap_entry()
 *
 * Data layout at 0x8000 + AP_TRAMPOLINE_DATA_OFFSET:
 *   +0x00: u64 cr3_value     (BSP's PML4 physical address)
 *   +0x08: u64 stack_top     (per-AP kernel stack top)
 *   +0x10: u64 entry_fn      (address of ap_entry Rust function)
 *   +0x18: u32 cpu_id        (AP's CPU ID)
 */

.section .text

/* Offsets into the trampoline data area */
.equ AP_DATA_CR3,     0x00
.equ AP_DATA_STACK,   0x08
.equ AP_DATA_ENTRY,   0x10
.equ AP_DATA_CPUID,   0x18

/* The trampoline code + data fits in one page (4KB). Data is at offset 0xF00. */
.equ AP_TRAMPOLINE_DATA_OFFSET, 0xF00
.equ AP_TRAMPOLINE_BASE, 0x8000

.global ap_trampoline_start
.global ap_trampoline_end

.code16
ap_trampoline_start:
    cli

    /* Set up segments for real mode */
    xorw    %ax, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss

    /* Load temp GDT for transition to protected mode */
    lgdt    (ap_gdt_ptr - ap_trampoline_start + AP_TRAMPOLINE_BASE)

    /* Enable protected mode (CR0.PE) */
    movl    %cr0, %eax
    orl     $1, %eax
    movl    %eax, %cr0

    /* Far jump to 32-bit protected mode */
    ljmpl   $0x08, $(ap_pm32 - ap_trampoline_start + AP_TRAMPOLINE_BASE)

.code32
ap_pm32:
    /* Set up 32-bit data segments */
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss

    /* Enable PAE (CR4.PAE = bit 5) */
    movl    %cr4, %eax
    orl     $(1 << 5), %eax
    movl    %eax, %cr4

    /* Load BSP's PML4 into CR3 */
    movl    (AP_TRAMPOLINE_BASE + AP_TRAMPOLINE_DATA_OFFSET + AP_DATA_CR3), %eax
    movl    %eax, %cr3

    /* Enable long mode: IA32_EFER.LME (bit 8) + NXE (bit 11) */
    movl    $0xC0000080, %ecx
    rdmsr
    orl     $((1 << 8) | (1 << 11)), %eax
    wrmsr

    /* Enable paging (CR0.PG = bit 31) — activates long mode */
    movl    %cr0, %eax
    orl     $(1 << 31), %eax
    movl    %eax, %cr0

    /* Far jump to 64-bit long mode */
    ljmpl   $0x18, $(ap_lm64 - ap_trampoline_start + AP_TRAMPOLINE_BASE)

.code64
ap_lm64:
    /* Set up 64-bit data segments */
    movw    $0x20, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    xorw    %ax, %ax
    movw    %ax, %fs
    movw    %ax, %gs

    /* Load per-AP stack */
    movq    (AP_TRAMPOLINE_BASE + AP_TRAMPOLINE_DATA_OFFSET + AP_DATA_STACK), %rsp

    /* Load CPU ID into first argument (rdi) */
    movl    (AP_TRAMPOLINE_BASE + AP_TRAMPOLINE_DATA_OFFSET + AP_DATA_CPUID), %edi

    /* Call Rust ap_entry(cpu_id) — never returns */
    movq    (AP_TRAMPOLINE_BASE + AP_TRAMPOLINE_DATA_OFFSET + AP_DATA_ENTRY), %rax
    callq   *%rax

    /* Should never reach here */
1:  hlt
    jmp     1b

/* Temporary GDT for AP transition (null, code32, data32, code64, data64) */
.align 8
ap_gdt:
    .quad   0                           /* null */
    .quad   0x00CF9A000000FFFF          /* 32-bit code: base=0, limit=4G, P=1, DPL=0, S=1, type=A(exec/read) */
    .quad   0x00CF92000000FFFF          /* 32-bit data: base=0, limit=4G, P=1, DPL=0, S=1, type=2(read/write) */
    .quad   0x00209A0000000000          /* 64-bit code: L=1, P=1, DPL=0, S=1 */
    .quad   0x0000920000000000          /* 64-bit data: P=1, DPL=0, S=1 */
ap_gdt_ptr:
    .word   (ap_gdt_ptr - ap_gdt - 1)  /* limit */
    .long   (ap_gdt - ap_trampoline_start + AP_TRAMPOLINE_BASE)  /* base (physical) */

ap_trampoline_end:
