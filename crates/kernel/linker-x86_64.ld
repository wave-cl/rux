ENTRY(_start)

SECTIONS {
    /* Kernel loaded at 1M physical by multiboot/QEMU -kernel */
    . = 0x100000;

    .multiboot2 : ALIGN(8) {
        KEEP(*(.multiboot2))
    }

    /* PVH entry note — QEMU reads this to enter 64-bit kernel directly */
    .note : ALIGN(4) {
        KEEP(*(.note.rux))
    }

    .text : ALIGN(4096) {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata : ALIGN(4096) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.eh_frame_hdr)
        __rodata_end = .;
    }

    .data : ALIGN(4096) {
        __data_start = .;
        *(.got .got.*)
        *(.data .data.*)
    }

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
    }

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
