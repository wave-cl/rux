ENTRY(_start)

SECTIONS {
    /* Kernel loaded at 1M physical by multiboot/QEMU -kernel */
    . = 0x100000;

    .multiboot2 : ALIGN(8) {
        KEEP(*(.multiboot2))
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
        __bss_end = .;
    }

    /* End of kernel image — page-aligned, above all code/data/BSS.
     * Boot code uses this to place the frame allocator and ramfs
     * dynamically, preventing overlap when BSS grows (e.g., MAX_PROCS). */
    . = ALIGN(4096);
    _end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
        *(.note*)
    }
}
