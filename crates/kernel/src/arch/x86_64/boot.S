/* Higher-half x86_64 boot stub.
 *
 * QEMU -kernel loads this ELF64 at its LMAs and enters at _start
 * in 32-bit protected mode via the Xen PVH note below.
 *
 * Sequence:
 *   1. Build 4-level page tables with BOTH a low-half identity map
 *      (so the 32-bit code can keep executing after CR0.PG set) and
 *      a high-half map at KERNEL_VMA for the linked Rust kernel.
 *   2. Enable PAE + long mode + paging.
 *   3. Load 64-bit GDT, far-jump to a short low-VA 64-bit trampoline.
 *   4. Trampoline `movabs`-loads the high-VA entry and `jmp *%rax`.
 *   5. High-VA entry sets RSP from the high-VA boot_stack_top and
 *      calls kernel_main.
 *
 * The low-half identity map is retained during the rest of boot so
 * existing Rust code that still uses phys==virt on the low half
 * (device MMIO, frame allocator, etc) keeps working. */

/* --- Xen PVH ELF note --------------------------------------------- */

.section .note.rux, "a", @note
.balign 4
    .long 2f - 1f                /* namesz */
    .long 4f - 3f                /* descsz */
    .long 18                     /* type: XEN_ELFNOTE_PHYS32_ENTRY */
1:  .asciz "Xen"                 /* name */
2:  .balign 4
3:  .long _start                 /* 32-bit phys entry */
4:  .balign 4

/* --- Low-VA 32-bit entry ------------------------------------------ */

.section .boot.text, "ax"
.code32

.global _start
_start:
    cli

    /* Zero the 5 boot page-table pages laid out contiguously in
     * .boot.bss by the linker (pml4, pdpt_low, pd_low, pdpt_high,
     * pd_high). */
    movl $boot_pml4, %edi
    xorl %eax, %eax
    movl $(5 * 4096 / 4), %ecx
    rep stosl

    /* --- Low-half identity map -----------------------------------
     * PML4[0]           -> boot_pdpt_low
     * boot_pdpt_low[0]  -> boot_pd_low
     * boot_pd_low[0..511] -> 2 MiB huge pages PA[0..1 GiB]
     *
     * A PD page holds 512 entries (4096 / 8), so 1 GiB per PD. The
     * QEMU target has 256 MiB of RAM so 1 GiB is plenty. */
    movl $boot_pml4, %edi
    movl $boot_pdpt_low, %eax
    orl  $0x03, %eax
    movl %eax, (%edi)

    movl $boot_pdpt_low, %edi
    movl $boot_pd_low, %eax
    orl  $0x03, %eax
    movl %eax, (%edi)

    movl $boot_pd_low, %edi
    movl $0x00000083, %eax       /* present + writable + huge(PS) */
    movl $512, %ecx
1:
    movl %eax, (%edi)
    addl $0x200000, %eax
    addl $8, %edi
    loop 1b

    /* --- High-half map (KERNEL_VMA = 0xffffffff80000000) ---------
     * PML4[511] -> boot_pdpt_high
     * boot_pdpt_high[510] -> boot_pd_high
     * boot_pd_high[0..511] -> PA[0..1 GiB] as 2 MiB huge pages. */
    movl $boot_pml4, %edi
    addl $(511 * 8), %edi
    movl $boot_pdpt_high, %eax
    orl  $0x03, %eax
    movl %eax, (%edi)

    movl $boot_pdpt_high, %edi
    addl $(510 * 8), %edi
    movl $boot_pd_high, %eax
    orl  $0x03, %eax
    movl %eax, (%edi)

    movl $boot_pd_high, %edi
    movl $0x00000083, %eax
    movl $512, %ecx
2:
    movl %eax, (%edi)
    addl $0x200000, %eax
    addl $8, %edi
    loop 2b

    /* Load PML4 into CR3 */
    movl $boot_pml4, %eax
    movl %eax, %cr3

    /* Enable PAE + OSFXSR + OSXMMEXCPT */
    movl %cr4, %eax
    orl  $((1 << 5) | (1 << 9) | (1 << 10)), %eax
    movl %eax, %cr4

    /* Clear CR0.EM (bit 2), set CR0.MP (bit 1) */
    movl %cr0, %eax
    andl $~(1 << 2), %eax
    orl  $(1 << 1), %eax
    movl %eax, %cr0

    /* Enable long mode (EFER.LME=8) + NX (EFER.NXE=11) */
    movl $0xC0000080, %ecx
    rdmsr
    orl  $((1 << 8) | (1 << 11)), %eax
    wrmsr

    /* Enable paging */
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

    /* Long mode is now active. Load the 64-bit GDT (low VA) and
     * far-jump to the low-VA 64-bit trampoline. */
    lgdt boot_gdt64_ptr
    ljmp $0x08, $long_mode_low_trampoline

.code64
long_mode_low_trampoline:
    /* `movabs` is the only way to load a 64-bit immediate; the
     * linker fills in the high-VA entry at link time. */
    movabs $long_mode_high_entry, %rax
    jmpq *%rax

/* --- Low-VA boot rodata: GDT reachable from 32-bit mode ----------- */

.section .boot.rodata, "a"
.balign 16
boot_gdt64:
    .quad 0x0000000000000000     /* null */
    .quad 0x00AF9A000000FFFF     /* 64-bit code: L=1, D=0, P=1, DPL=0 */
    .quad 0x00CF92000000FFFF     /* 64-bit data: P=1, DPL=0 */
boot_gdt64_end:

boot_gdt64_ptr:
    .word boot_gdt64_end - boot_gdt64 - 1
    .long boot_gdt64             /* 32-bit abs — OK in 32-bit mode */
    .long 0                      /* pad */

/* --- High-VA 64-bit entry ----------------------------------------- */

.section .text, "ax"
.code64
.global long_mode_high_entry
long_mode_high_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Switch to the high-VA boot stack — placed AFTER __bss_rust_end
     * so kernel_main's BSS zero does not clobber its own return
     * address mid-memset. */
    movabs $boot_stack_top, %rsp

    /* SysV first arg: multiboot info pointer. PVH gives no info so
     * we pass 0; multiboot.rs checks for info_addr == 0. */
    xorl %edi, %edi

    call kernel_main

    cli
    hlt
    jmp .

/* --- Low-VA boot BSS: page tables --------------------------------- */

.section .boot.bss, "aw", @nobits
.balign 4096
.global boot_pml4
boot_pml4:      .skip 4096
boot_pdpt_low:  .skip 4096
boot_pd_low:    .skip 4096
boot_pdpt_high: .skip 4096
boot_pd_high:   .skip 4096

/* --- High-VA boot stack -------------------------------------------
 * Lives in `.boot_stack` so the linker script can place it AFTER
 * __bss_rust_end (out of kernel_main's BSS-zero range). */

.section .boot_stack, "aw", @nobits
.balign 16
boot_stack:
    .skip 131072
.global boot_stack_top
boot_stack_top:
