/// Root filesystem population — re-exports from rux-vfs.
///
/// The implementation lives in `rux_vfs::rootfs`. This wrapper supplies
/// the kernel's serial logging callback.

use rux_arch::SerialOps;

/// Populate the ramfs with the busybox-compatible rootfs layout.
pub fn populate(
    fs: &mut rux_vfs::ramfs::RamFs,
    elf_data: &[u8],
) {
    rux_vfs::rootfs::populate(fs, elf_data, Some(crate::arch::Arch::write_str));
}
