use std::path::PathBuf;

fn main() {
    let kernel_path = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: rux-boot-image <path-to-kernel-elf>"),
    );

    let bios_path = kernel_path.with_extension("bios.img");

    bootloader_linker::bios::BiosLinker::new(&kernel_path)
        .create_disk_image(&bios_path)
        .expect("failed to create BIOS disk image");

    println!("Created: {}", bios_path.display());
}
