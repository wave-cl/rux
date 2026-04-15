/* Higher-half kernel linker script for x86_64.
 *
 * Physical layout: QEMU's Xen PVH loader drops this ELF at its
 * LMAs, starting at 0x100000. boot.S runs from low VAs until it
 * enables paging + jumps into the high half.
 *
 * Virtual layout: the .boot.* sections keep VA == PA (low) so the
 * 32-bit protected-mode entry can reach them via 32-bit absolutes.
 * Everything else is LINKED at KERNEL_VMA + offset (the top 2 GiB
 * of the canonical address space, which matches `-C code-model=kernel`).
 */

KERNEL_VMA = 0xffffffff80000000;

ENTRY(_start)

PHDRS {
    boot_text   PT_LOAD  FLAGS(5);   /* R-X low-VA 32-bit entry + trampoline */
    boot_note   PT_NOTE  FLAGS(4);
    boot_rodata PT_LOAD  FLAGS(4);
    boot_bss    PT_LOAD  FLAGS(6);
    text        PT_LOAD  FLAGS(5);   /* R-X high-VA kernel text */
    rodata      PT_LOAD  FLAGS(4);
    data        PT_LOAD  FLAGS(6);
}

SECTIONS {
    . = 0x100000;

    /* PVH note — QEMU walks the ELF program headers for PT_NOTE. */
    .note.rux : ALIGN(4) {
        KEEP(*(.note.rux))
    } :boot_text :boot_note

    .boot.text : ALIGN(4096) {
        __boot_text_start = .;
        *(.boot.text)
        __boot_text_end = .;
    } :boot_text

    .boot.rodata : ALIGN(16) {
        *(.boot.rodata)
    } :boot_rodata

    .boot.bss (NOLOAD) : ALIGN(4096) {
        __boot_bss_start = .;
        *(.boot.bss)
        __boot_bss_end = .;
    } :boot_bss

    /* Move into the high half. Subsequent sections are LINKED at
     * high VAs but LOADED at the current low phys (via AT(...)) so
     * the PVH loader places the bytes contiguously in RAM. */
    . += KERNEL_VMA;

    .text : AT(ADDR(.text) - KERNEL_VMA) ALIGN(4096) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    .rodata : AT(ADDR(.rodata) - KERNEL_VMA) ALIGN(4096) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.eh_frame_hdr)
        __rodata_end = .;
    } :rodata

    .data : AT(ADDR(.data) - KERNEL_VMA) ALIGN(4096) {
        __data_start = .;
        *(.got .got.*)
        *(.data .data.*)
    } :data

    .bss : AT(ADDR(.bss) - KERNEL_VMA) ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        /* Mark end of Rust statics — kernel_main zeroes up to here.
         * boot_stack lives in a dedicated .boot_stack section placed
         * AFTER __bss_rust_end so the memset doing the zero doesn't
         * clobber its own return address mid-rep-stosb. */
        . = ALIGN(4096);
        __bss_rust_end = .;
        *(.boot_stack)
        __bss_end = .;
    } :data

    . = ALIGN(4096);
    _end = .;
    _end_phys = _end - KERNEL_VMA;

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
        *(.note.GNU-stack)
        *(.note.gnu.*)
    }
}
