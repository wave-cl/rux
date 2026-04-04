/// Exit QEMU on aarch64 via semihosting.
/// QEMU must be started with: -semihosting
pub fn exit_qemu(code: u32) -> ! {
    unsafe {
        // ADP_Stopped_ApplicationExit = 0x20026
        let block: [u64; 2] = [0x20026, code as u64];
        core::arch::asm!(
            "mov x1, {0}",
            "mov w0, 0x18",         // SYS_EXIT
            "hlt 0xF000",           // aarch64 semihosting trap
            in(reg) block.as_ptr(),
            options(noreturn)
        );
    }
}

#[allow(dead_code)]
pub const EXIT_SUCCESS: u32 = 0;
pub const EXIT_FAILURE: u32 = 1;

impl rux_arch::ExitOps for super::Aarch64 {
    const EXIT_SUCCESS: u32 = 0;
    const EXIT_FAILURE: u32 = 1;
    fn exit(code: u32) -> ! { exit_qemu(code) }
}
