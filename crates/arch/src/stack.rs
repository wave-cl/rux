use rux_klib::VirtAddr;

/// Number of pages per kernel stack.
/// x86_64: 4 pages = 16 KiB. aarch64 with 16K pages: 4 pages = 64 KiB.
pub const KERNEL_STACK_PAGES: usize = 4;

/// A kernel stack descriptor.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct KernelStack {
    /// Base address (lowest address of the stack allocation).
    pub base: VirtAddr,
    /// Size in bytes.
    pub size: usize,
}

const _: () = assert!(core::mem::size_of::<KernelStack>() == 16);

impl KernelStack {
    /// The top of the stack (highest address). The stack pointer starts here
    /// and grows downward.
    #[inline(always)]
    pub const fn top(&self) -> VirtAddr {
        VirtAddr::new(self.base.as_usize() + self.size)
    }
}

/// Kernel stack allocation and initialization.
///
/// # Safety
/// `alloc_stack` and `dealloc_stack` manipulate kernel virtual memory.
/// `init_stack` writes a CpuContext frame onto the stack so that switching
/// to this stack returns to `entry_point` with `arg` as the first argument.
pub unsafe trait KernelStackOps {
    type Error;

    /// Allocate a new kernel stack.
    fn alloc_stack() -> Result<KernelStack, Self::Error>;

    /// Deallocate a kernel stack.
    fn dealloc_stack(stack: KernelStack);

    /// Initialize a kernel stack with a return-from-switch CpuContext.
    /// Returns the initial stack pointer (pointing to the saved CpuContext).
    unsafe fn init_stack(
        stack: &KernelStack,
        entry_point: usize,
        arg: usize,
    ) -> VirtAddr;
}
