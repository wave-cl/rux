/// Shared syscall implementations — architecture-independent.
///
/// Split into POSIX-standardized syscalls and Linux-specific extensions.
/// Architecture-specific entry/exit asm stays in each arch module.

pub mod posix;
pub mod linux;

// ── Shared process state ────────────────────────────────────────────

/// Program break for brk().
pub static mut PROGRAM_BRK: u64 = 0;

/// Next anonymous mmap virtual address.
pub static mut MMAP_BASE: u64 = 0x10000000;

/// Current working directory inode (0 = root).
pub static mut CWD_INODE: u64 = 0;

/// Current working directory path (for getcwd). Null-terminated.
pub static mut CWD_PATH: [u8; 256] = {
    let mut buf = [0u8; 256];
    buf[0] = b'/';
    buf
};
pub static mut CWD_PATH_LEN: usize = 1;

/// Child exit status for wait4.
pub static mut LAST_CHILD_EXIT: i32 = 0;

/// Whether there's a child to collect.
pub static mut CHILD_AVAILABLE: bool = false;

/// Whether we're in a vfork child context (skip pipe ref counting in close).
pub static mut IN_VFORK_CHILD: bool = false;

// ── Page table helper (arch-dispatched) ─────────────────────────────

/// Map zeroed pages into the current user page table.
/// Used by brk() and mmap() to add pages to the user address space.
pub unsafe fn map_user_pages(
    start_va: u64,
    end_va: u64,
    flags: rux_mm::MappingFlags,
) {
    use rux_arch::PageTableRootOps;
    let alloc = crate::kstate::alloc();
    let cr3 = crate::arch::Arch::read();
    let mut upt = crate::arch::PageTable::from_cr3(
        rux_klib::PhysAddr::new(cr3 as usize));

    let upt_ptr = &mut upt as *mut crate::arch::PageTable;
    rux_mm::map_zeroed_pages(
        alloc, start_va, end_va, flags,
        &mut |va, phys, f, a| { let _ = (*upt_ptr).map_4k(va, phys, f, a); },
        &mut |va| { let _ = (*upt_ptr).unmap_4k(va); },
    );
}

// ── Path resolution helper (used by both POSIX and Linux) ───────────

/// Read a C string from user memory into a path slice.
pub unsafe fn read_user_path(path_ptr: u64) -> &'static [u8] {
    let cstr = path_ptr as *const u8;
    let mut len = 0usize;
    while *cstr.add(len) != 0 && len < 256 { len += 1; }
    core::slice::from_raw_parts(cstr, len)
}

/// Resolve a path using CWD for relative paths.
pub unsafe fn resolve_with_cwd(path: &[u8]) -> Result<rux_vfs::InodeId, i64> {
    let fs = crate::kstate::fs();
    rux_vfs::path::resolve_with_cwd(fs, CWD_INODE, path)
}

/// Resolve a path to (parent_inode, basename).
pub unsafe fn resolve_parent_and_name(path_ptr: u64) -> Result<(rux_vfs::InodeId, &'static [u8]), i64> {
    let path = read_user_path(path_ptr);
    let fs = crate::kstate::fs();
    rux_vfs::path::resolve_parent_and_name(fs, CWD_INODE, path)
}

/// Fill a Linux struct stat from VFS InodeStat.
///
/// Delegates to the architecture's `StatLayout::fill_stat` impl because
/// the struct stat layout differs between x86_64 and aarch64 (st_nlink
/// width, field order, st_blksize type).
pub unsafe fn fill_linux_stat(buf: u64, vfs_stat: &rux_vfs::InodeStat) {
    use crate::arch::StatLayout;
    crate::arch::Arch::fill_stat(buf, vfs_stat);
}
