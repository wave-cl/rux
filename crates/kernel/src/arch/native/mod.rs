//! Native architecture — used with `--features native` (cargo test, no QEMU).
//!
//! All hardware operations are stubbed out or delegated to the host OS.
//! This allows kernel logic (fs, pipe, process state) to be tested with
//! `cargo test -p rux-kernel --features native`.

use rux_klib::{PhysAddr, VirtAddr};
use rux_mm::{MappingFlags, FrameAllocator, MemoryError, PageSize};

/// Zero-sized marker type for the native "architecture".
pub struct NativeArch;

// ── ConsoleOps ────────────────────────────────────────────────────────

unsafe impl rux_arch::ConsoleOps for NativeArch {
    unsafe fn init() {}
    fn write_byte(b: u8) {
        use std::io::Write;
        let _ = std::io::stderr().lock().write_all(&[b]);
    }
    fn read_byte() -> u8 { 0 }
}

// ── ExitOps ───────────────────────────────────────────────────────────

impl rux_arch::ExitOps for NativeArch {
    const EXIT_SUCCESS: u32 = 0;
    const EXIT_FAILURE: u32 = 1;
    fn exit(code: u32) -> ! { std::process::exit(code as i32); }
}

// ── ContextOps ────────────────────────────────────────────────────────

unsafe impl rux_arch::ContextOps for NativeArch {
    unsafe fn context_switch(_old_sp: *mut usize, _new_sp: usize) {}
    unsafe fn init_task_stack(_stack_top: usize, _entry: usize, _arg: usize) -> usize { 0 }
}

// ── UserModeOps ───────────────────────────────────────────────────────

unsafe impl rux_arch::UserModeOps for NativeArch {
    unsafe fn enter_user_mode(_entry: usize, _user_stack: usize) -> ! {
        panic!("enter_user_mode not supported in native mode")
    }
}

// ── PageTableRootOps ──────────────────────────────────────────────────

unsafe impl rux_arch::PageTableRootOps for NativeArch {
    fn read() -> u64 { 0 }
    unsafe fn write(_root: u64) {}
}

// ── BootOps ───────────────────────────────────────────────────────────

impl rux_arch::BootOps for NativeArch {
    fn boot_init(_arg: usize) {}
}

// ── TimerOps ──────────────────────────────────────────────────────────

impl rux_arch::TimerOps for NativeArch {
    fn ticks() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ── HaltOps ───────────────────────────────────────────────────────────

unsafe impl rux_arch::HaltOps for NativeArch {
    unsafe fn halt_until_interrupt() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

// ── TimerControl ──────────────────────────────────────────────────────

unsafe impl rux_arch::TimerControl for NativeArch {
    unsafe fn stop_timer() {}
    unsafe fn start_timer() {}
}

// ── ArchInfo ──────────────────────────────────────────────────────────

impl rux_arch::ArchInfo for NativeArch {
    const MACHINE_NAME: &'static [u8] = b"native";
}

// ── ArchSpecificOps ───────────────────────────────────────────────────

impl rux_arch::ArchSpecificOps for NativeArch {
    fn arch_syscall(_nr: usize, _a0: usize, _a1: usize) -> Option<isize> { None }
}

// ── VforkContext ──────────────────────────────────────────────────────
// jmp_active() returns false — exit() won't attempt longjmp.
// All other methods are no-ops or panics (not needed for fs/pipe tests).

unsafe impl rux_arch::VforkContext for NativeArch {
    const CHILD_STACK_VA: usize = 0;
    unsafe fn save_regs() {}
    unsafe fn save_user_sp() -> usize { 0 }
    unsafe fn set_user_sp(_sp: usize) {}
    unsafe fn save_tls() -> u64 { 0 }
    unsafe fn restore_tls(_val: u64) {}
    unsafe fn read_pt_root() -> u64 { 0 }
    unsafe fn write_pt_root(_root: u64) {}
    unsafe fn clear_jmp() {}
    unsafe fn setjmp() -> isize { 0 }
    fn jmp_active() -> bool { false }
    unsafe fn longjmp(_child_pid: isize) -> ! {
        panic!("longjmp not supported in native mode")
    }
    unsafe fn restore_and_return_to_user(_return_val: isize, _user_sp: usize) -> ! {
        panic!("restore_and_return_to_user not supported in native mode")
    }
}

// ── SignalOps ─────────────────────────────────────────────────────────
// Stubs — signal delivery not tested in native mode.

unsafe impl rux_arch::SignalOps for NativeArch {
    const SIGNAL_FRAME_SIZE: usize = 32;
    unsafe fn sig_read_user_sp() -> usize { 0 }
    unsafe fn sig_write_user_sp(_sp: usize) {}
    unsafe fn sig_write_frame(
        _frame_addr: usize, _syscall_result: i64,
        _blocked_mask: u64, _restorer: usize, _signum: u8,
    ) {}
    unsafe fn sig_redirect_to_handler(_handler: usize, _signum: u8) {}
    unsafe fn sig_restore_frame(_frame_addr: usize) -> (i64, u64) { (0, 0) }
}

// ── StatLayout ────────────────────────────────────────────────────────
// Use the host architecture's layout so tests on aarch64 Mac and x86_64 Linux
// both produce valid stat buffers without needing a real userspace consumer.

impl rux_arch::StatLayout for NativeArch {
    const STAT_SIZE: usize = 128;
    const INO_OFF: usize = 8;
    #[cfg(target_arch = "x86_64")]
    const NLINK_OFF: usize = 16;
    #[cfg(not(target_arch = "x86_64"))]
    const NLINK_OFF: usize = 20;
    #[cfg(target_arch = "x86_64")]
    const NLINK_IS_U64: bool = true;
    #[cfg(not(target_arch = "x86_64"))]
    const NLINK_IS_U64: bool = false;
    #[cfg(target_arch = "x86_64")]
    const MODE_OFF: usize = 24;
    #[cfg(not(target_arch = "x86_64"))]
    const MODE_OFF: usize = 16;
    #[cfg(target_arch = "x86_64")]
    const UID_OFF: usize = 28;
    #[cfg(not(target_arch = "x86_64"))]
    const UID_OFF: usize = 24;
    #[cfg(target_arch = "x86_64")]
    const GID_OFF: usize = 32;
    #[cfg(not(target_arch = "x86_64"))]
    const GID_OFF: usize = 28;
    #[cfg(target_arch = "x86_64")]
    const RDEV_OFF: usize = 40;
    #[cfg(not(target_arch = "x86_64"))]
    const RDEV_OFF: usize = 32;
    const SIZE_OFF: usize = 48;
    const BLKSIZE_OFF: usize = 56;
    #[cfg(target_arch = "x86_64")]
    const BLKSIZE_IS_I64: bool = true;
    #[cfg(not(target_arch = "x86_64"))]
    const BLKSIZE_IS_I64: bool = false;
    const BLOCKS_OFF: usize = 64;
}

// ── SigactionLayout ───────────────────────────────────────────────────

impl rux_arch::SigactionLayout for NativeArch {
    #[cfg(target_arch = "x86_64")]
    const MASK_OFF: usize = 24;
    #[cfg(not(target_arch = "x86_64"))]
    const MASK_OFF: usize = 16;
    #[cfg(target_arch = "x86_64")]
    const HAS_RESTORER: bool = true;
    #[cfg(not(target_arch = "x86_64"))]
    const HAS_RESTORER: bool = false;
    #[cfg(target_arch = "x86_64")]
    const RESTORER_OFF: usize = 16;
    #[cfg(not(target_arch = "x86_64"))]
    const RESTORER_OFF: usize = 0;
}

// ── KernelMapOps ─────────────────────────────────────────────────────

unsafe impl crate::arch::KernelMapOps for NativeArch {
    unsafe fn map_kernel_pages(
        _pt: &mut crate::arch::PageTable,
        _alloc: &mut dyn rux_mm::FrameAllocator,
    ) {}
}

// ── FlatPageTable ─────────────────────────────────────────────────────
/// No-op page table for native mode. Frame allocations are real host memory
/// but no hardware page table walks are needed.

pub struct FlatPageTable;

impl FlatPageTable {
    pub fn new(_alloc: &mut dyn FrameAllocator) -> Option<Self> {
        Some(Self)
    }
    pub fn from_root(_pa: PhysAddr) -> Self {
        Self
    }
    pub fn map_4k(
        &mut self,
        _va: VirtAddr,
        _pa: PhysAddr,
        _flags: MappingFlags,
        _alloc: &mut dyn FrameAllocator,
    ) -> Result<(), MemoryError> {
        Ok(())
    }
    pub fn unmap_4k(&mut self, _va: VirtAddr) -> Result<PhysAddr, MemoryError> {
        Ok(PhysAddr::new(0))
    }
    /// Identity-map translation in native mode: VA == PA.
    pub fn translate(&self, va: VirtAddr) -> Result<PhysAddr, MemoryError> {
        Ok(PhysAddr::new(va.as_usize()))
    }
    pub fn walk_user_pages<F: FnMut(VirtAddr, PhysAddr, MappingFlags)>(&self, _f: F) {}
    pub fn root_phys(&self) -> PhysAddr { PhysAddr::new(0) }
    pub fn free_user_address_space(&self, _alloc: &mut dyn FrameAllocator) {}
}
