/// Exit QEMU via the isa-debug-exit device.
/// QEMU must be started with: -device isa-debug-exit,iobase=0xf4,iosize=0x04
///
/// QEMU's exit code = (value << 1) | 1:
///   0x10 → exit code 33 (success)
///   0x11 → exit code 35 (failure)
pub fn exit_qemu(code: u32) -> ! {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0xf4u16,
            in("al") code as u8,
            options(nostack, preserves_flags)
        );
    }
    loop { core::hint::spin_loop(); }
}

pub const EXIT_SUCCESS: u32 = 0x10;
pub const EXIT_FAILURE: u32 = 0x11;

impl rux_arch::ExitOps for super::X86_64 {
    const EXIT_SUCCESS: u32 = 0x10;
    const EXIT_FAILURE: u32 = 0x11;
    fn exit(code: u32) -> ! { exit_qemu(code) }
}
