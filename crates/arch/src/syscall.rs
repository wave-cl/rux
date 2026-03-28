/// Saved state from a syscall entry. The kernel reads syscall arguments
/// from this frame and writes the return value back.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallFrame {
    /// Syscall number (rax on x86_64, x8 on aarch64).
    pub number: usize,
    /// Syscall arguments (rdi,rsi,rdx,r10,r8,r9 on x86_64; x0-x5 on aarch64).
    pub args: [usize; 6],
    /// User-mode instruction pointer to return to.
    pub return_addr: usize,
    /// User-mode stack pointer at syscall entry.
    pub user_stack: usize,
    /// Saved flags (RFLAGS on x86_64, PSTATE on aarch64).
    pub flags: usize,
}

const _: () = assert!(core::mem::size_of::<SyscallFrame>() == 80);

impl SyscallFrame {
    pub const EMPTY: Self = Self {
        number: 0,
        args: [0; 6],
        return_addr: 0,
        user_stack: 0,
        flags: 0,
    };

    #[inline(always)]
    pub const fn arg0(&self) -> usize { self.args[0] }
    #[inline(always)]
    pub const fn arg1(&self) -> usize { self.args[1] }
    #[inline(always)]
    pub const fn arg2(&self) -> usize { self.args[2] }
    #[inline(always)]
    pub const fn arg3(&self) -> usize { self.args[3] }
    #[inline(always)]
    pub const fn arg4(&self) -> usize { self.args[4] }
    #[inline(always)]
    pub const fn arg5(&self) -> usize { self.args[5] }
}

/// Syscall entry/exit operations.
///
/// # Safety
/// `init` configures hardware registers (MSRs on x86_64, system registers on aarch64).
/// `return_to_user` transitions to user mode and never returns.
pub unsafe trait SyscallOps {
    /// One-time setup: configure LSTAR/SFMASK/STAR (x86_64) or VBAR_EL1 (aarch64).
    unsafe fn init();

    /// Return to user mode with `retval` as the syscall return value.
    /// Restores user stack, flags, and instruction pointer from `frame`.
    unsafe fn return_to_user(frame: &SyscallFrame, retval: usize) -> !;
}
