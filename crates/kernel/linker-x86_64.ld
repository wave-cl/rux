ENTRY(_start)

/* QEMU's PVH loader needs the XEN_ELFNOTE_PHYS32_ENTRY note to be in
 * a PT_NOTE program header, not just an SHT_NOTE section header.
 * ld only creates PT_NOTE automatically when NO explicit PHDRS block
 * is present; with SECTIONS alone it silently drops the note out of
 * the program-header table. We declare all the segments ourselves. */
PHDRS {
    text PT_LOAD FLAGS(5);    /* R-X */
    note PT_NOTE FLAGS(4);
    data PT_LOAD FLAGS(6);    /* RW- */
}

SECTIONS {
    /* Kernel loaded at 1M physical by QEMU -kernel via Xen PVH. */
    . = 0x100000;

    /* PVH note lives in the same file region as .text (both get
     * mapped by the `text` PT_LOAD) AND has its own PT_NOTE header
     * so the PVH loader can find it by program-header walk. */
    .note.rux : ALIGN(4) {
        KEEP(*(.note.rux))
    } :text :note

    .text : ALIGN(4096) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    .rodata : ALIGN(4096) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.eh_frame_hdr)
        __rodata_end = .;
    } :text

    .data : ALIGN(4096) {
        __data_start = .;
        *(.got .got.*)
        *(.data .data.*)
    } :data

    .bss : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        /* Mark end of Rust statics — kernel_main zeros up to here. */
        . = ALIGN(4096);
        __bss_rust_end = .;
        /* Boot page tables + stack: still in .bss (LOAD segment) but
         * kernel_main skips zeroing this region (page tables are live). */
        *(.boot_bss)
        __bss_end = .;
    } :data

    /* End of kernel image — page-aligned, above all code/data/BSS. */
    . = ALIGN(4096);
    _end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
        *(.note.GNU-stack)
        *(.note.gnu.*)
    }
}
