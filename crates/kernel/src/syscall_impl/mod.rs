/// Shared syscall implementations — architecture-independent.
///
/// Split into POSIX-standardized syscalls and Linux-specific extensions.
/// Architecture-specific entry/exit asm stays in each arch module.

pub mod posix;
pub mod linux;

// ── Arch-specific helpers (zero-cost, cfg-dispatched) ───────────────

pub mod arch {
    /// Write a byte to the serial console.
    #[inline(always)]
    pub fn serial_write_byte(b: u8) {
        #[cfg(target_arch = "x86_64")]
        crate::x86_64::serial::write_byte(b);
        #[cfg(target_arch = "aarch64")]
        crate::aarch64::serial::write_byte(b);
    }

    /// Read a byte from the serial console (blocking).
    #[inline(always)]
    pub fn serial_read_byte() -> u8 {
        #[cfg(target_arch = "x86_64")]
        { crate::x86_64::serial::read_byte() }
        #[cfg(target_arch = "aarch64")]
        { crate::aarch64::serial::read_byte() }
    }

    /// Write a string to serial.
    pub fn serial_write_str(s: &str) {
        #[cfg(target_arch = "x86_64")]
        crate::x86_64::serial::write_str(s);
        #[cfg(target_arch = "aarch64")]
        crate::aarch64::serial::write_str(s);
    }

    /// Write bytes to serial.
    pub fn serial_write_bytes(b: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        crate::x86_64::serial::write_bytes(b);
        #[cfg(target_arch = "aarch64")]
        crate::aarch64::serial::write_bytes(b);
    }

    /// Get timer ticks.
    #[inline(always)]
    pub fn ticks() -> u64 {
        #[cfg(target_arch = "x86_64")]
        { crate::x86_64::pit::ticks() }
        #[cfg(target_arch = "aarch64")]
        { crate::aarch64::timer::ticks() }
    }

    /// Read the current page table root address (CR3 / TTBR0_EL1).
    #[inline(always)]
    pub fn page_table_root() -> u64 {
        let val: u64;
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) val, options(nostack)); }
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) val, options(nostack)); }
        val
    }
}

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
    rux_vfs::path::resolve_path_at(fs, CWD_INODE, path).map_err(|_| -2i64)
}

/// Resolve a path to (parent_inode, basename).
pub unsafe fn resolve_parent_and_name(path_ptr: u64) -> Result<(rux_vfs::InodeId, &'static [u8]), i64> {
    use rux_vfs::FileSystem;
    let path = read_user_path(path_ptr);

    let mut last_slash = None;
    for j in 0..path.len() {
        if path[j] == b'/' { last_slash = Some(j); }
    }

    let fs = crate::kstate::fs();
    match last_slash {
        Some(0) => {
            // "/foo" → parent is root, name is everything after '/'
            let name = &path[1..];
            Ok((fs.root_inode(), name))
        }
        Some(s) => {
            // "/a/b/foo" or "a/b/foo" → resolve parent, name is after last slash
            let parent_path = &path[..s];
            let name = &path[s + 1..];
            match rux_vfs::path::resolve_path_at(fs, CWD_INODE, parent_path) {
                Ok(parent_ino) => Ok((parent_ino, name)),
                Err(_) => Err(-2),
            }
        }
        None => {
            // "foo" (no slash) → parent is CWD
            Ok((CWD_INODE, path))
        }
    }
}

/// Fill a Linux struct stat from VFS InodeStat.
///
/// The struct stat layout differs between x86_64 and aarch64:
///
/// x86_64 (144 bytes):                    aarch64 (128 bytes):
///   0: st_dev      u64                     0: st_dev      u64
///   8: st_ino      u64                     8: st_ino      u64
///  16: st_nlink    u64  ← 8 bytes         16: st_mode     u32  ← 4 bytes
///  24: st_mode     u32                    20: st_nlink    u32  ← 4 bytes
///  28: st_uid      u32                    24: st_uid      u32
///  32: st_gid      u32                    28: st_gid      u32
///  48: st_size     i64                    32: st_rdev     u64
///  56: st_blksize  i64                    48: st_size     i64
///  64: st_blocks   i64                    56: st_blksize  i32
///                                         64: st_blocks   i64
pub unsafe fn fill_linux_stat(buf: u64, vfs_stat: &rux_vfs::InodeStat) {
    let p = buf as *mut u8;
    for i in 0..144 { *p.add(i) = 0; }

    #[cfg(target_arch = "x86_64")]
    {
        *(buf as *mut u64) = 0;                            // st_dev
        *((buf + 8) as *mut u64) = vfs_stat.ino;           // st_ino
        *((buf + 16) as *mut u64) = vfs_stat.nlink as u64; // st_nlink (u64!)
        *((buf + 24) as *mut u32) = vfs_stat.mode;         // st_mode
        *((buf + 28) as *mut u32) = vfs_stat.uid;          // st_uid
        *((buf + 32) as *mut u32) = vfs_stat.gid;          // st_gid
        *((buf + 48) as *mut i64) = vfs_stat.size as i64;  // st_size
        *((buf + 56) as *mut i64) = 4096;                  // st_blksize
        *((buf + 64) as *mut i64) = vfs_stat.blocks as i64; // st_blocks
    }

    #[cfg(target_arch = "aarch64")]
    {
        *(buf as *mut u64) = 0;                            // st_dev
        *((buf + 8) as *mut u64) = vfs_stat.ino;           // st_ino
        *((buf + 16) as *mut u32) = vfs_stat.mode;         // st_mode (u32)
        *((buf + 20) as *mut u32) = vfs_stat.nlink;        // st_nlink (u32)
        *((buf + 24) as *mut u32) = vfs_stat.uid;          // st_uid
        *((buf + 28) as *mut u32) = vfs_stat.gid;          // st_gid
        *((buf + 32) as *mut u64) = 0;                     // st_rdev
        *((buf + 40) as *mut u64) = 0;                     // __pad1
        *((buf + 48) as *mut i64) = vfs_stat.size as i64;  // st_size
        *((buf + 56) as *mut i32) = 4096;                  // st_blksize (i32)
        *((buf + 64) as *mut i64) = vfs_stat.blocks as i64; // st_blocks
    }
}
