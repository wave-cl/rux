//! Filesystem metadata and path operation syscalls.

use rux_fs::fdtable as fdt;
use crate::arch::StatLayout;
const STAT_MODE_OFF: usize = <crate::arch::Arch as StatLayout>::MODE_OFF;
const STAT_BLKSIZE_OFF: usize = <crate::arch::Arch as StatLayout>::BLKSIZE_OFF;
/// stat(pathname, statbuf) — POSIX.1 (follows symlinks)
pub fn stat(pathname: usize, buf: usize) -> isize {
    fstatat(0xffffff9c, pathname, buf, 0)
}

/// lstat(pathname, statbuf) — POSIX.1 (does NOT follow final symlink)
pub fn lstat(pathname: usize, buf: usize) -> isize {
    fstatat(0xffffff9c, pathname, buf, 0x100) // AT_SYMLINK_NOFOLLOW
}

/// Write a synthetic stat buffer for special fds (console, pipes).
/// Sets mode, blksize, nlink=1, ino=fd+1 (non-zero), dev=0.
unsafe fn synthetic_stat(buf: usize, mode: u32, fd: usize) {
    let p = buf as *mut u8;
    for i in 0..144 { *p.add(i) = 0; }
    *((buf + STAT_MODE_OFF) as *mut u32) = mode;
    *((buf + STAT_BLKSIZE_OFF) as *mut u32) = 4096;
    // st_ino: use fd+1 so it's non-zero (offset 0 on both x86_64 and aarch64)
    *(buf as *mut u64) = (fd + 1) as u64;
    // st_nlink: 1 (offset 16 on x86_64, varies — use StatLayout if available)
    // For simplicity, write at a known offset for both arches
    *((buf + 16) as *mut u32) = 1;
}

/// fstat(fd, statbuf) — POSIX.1
pub fn fstat(fd: usize, buf: usize) -> isize {
    if buf == 0 { return crate::errno::EFAULT; }
    if fd <= 2 && fdt::is_console_fd(fd) {
        unsafe { synthetic_stat(buf, 0o20666, fd); } // S_IFCHR | 0666
        return 0;
    }
    if fd <= 2 {
        unsafe {
            if (*fdt::FD_TABLE)[fd].is_pipe {
                synthetic_stat(buf, 0o10666, fd); // S_IFIFO | 0666
                return 0;
            }
        }
    }
    unsafe {
        use rux_fs::FileSystem;
        let f = &(*fdt::FD_TABLE)[fd];
        if !f.active { return crate::errno::EBADF; }
        let fs = crate::kstate::fs();
        let mut vfs_stat = core::mem::zeroed::<rux_fs::InodeStat>();
        if fs.stat(f.ino, &mut vfs_stat).is_err() {
            synthetic_stat(buf, 0o100644, fd); // S_IFREG | 0644
            return 0;
        }
        crate::arch::fill_linux_stat::<crate::arch::Arch>(buf, &vfs_stat);
    }
    0
}

/// fstatat(dirfd, pathname, statbuf, flags) — POSIX.1-2008
/// flags=0x100 (AT_SYMLINK_NOFOLLOW): stat the symlink itself, not its target.
pub fn fstatat(dirfd: usize, pathname: usize, buf: usize, flags: usize) -> isize {
    if buf == 0 { return crate::errno::EFAULT; }
    const AT_SYMLINK_NOFOLLOW: usize = 0x100;
    const AT_EMPTY_PATH: usize = 0x1000;
    unsafe {
        use rux_fs::FileSystem;
        let path = crate::uaccess::read_user_cstr(pathname);
        let fs = crate::kstate::fs();

        // AT_EMPTY_PATH: stat the FD itself
        if flags & AT_EMPTY_PATH != 0 && path.is_empty() && dirfd < rux_fs::fdtable::MAX_FDS {
            if let Some(ino) = rux_fs::fdtable::get_fd_inode(dirfd) {
                let mut vfs_stat = core::mem::zeroed::<rux_fs::InodeStat>();
                if fs.stat(ino, &mut vfs_stat).is_err() { return crate::errno::ENOENT; }
                crate::arch::fill_linux_stat::<crate::arch::Arch>(buf, &vfs_stat);
                return 0;
            }
        }

        let ino = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            match rux_fs::path::resolve_nofollow(fs, super::PROCESS.fs_ctx.cwd, path) {
                Ok(ino) => ino,
                Err(e) => return e,
            }
        } else {
            match super::resolve_at(dirfd, path) {
                Ok(ino) => ino,
                Err(e) => return e,
            }
        };
        let mut vfs_stat = core::mem::zeroed::<rux_fs::InodeStat>();
        if fs.stat(ino, &mut vfs_stat).is_err() { return crate::errno::ENOENT; }
        crate::arch::fill_linux_stat::<crate::arch::Arch>(buf, &vfs_stat);
        0
    }
}

/// statx(dirfd, pathname, flags, mask, statxbuf) — Linux 4.11+
/// Converts InodeStat to struct statx (256 bytes).
pub fn statx(dirfd: usize, pathname: usize, flags: usize, _mask: usize, buf: usize) -> isize {
    const AT_EMPTY_PATH: usize = 0x1000;
    const AT_SYMLINK_NOFOLLOW: usize = 0x100;
    if buf == 0 { return crate::errno::EFAULT; }
    if crate::uaccess::validate_user_ptr(buf, 256).is_err() { return crate::errno::EFAULT; }
    unsafe {
        use rux_fs::FileSystem;
        let path = crate::uaccess::read_user_cstr(pathname);
        let fs = crate::kstate::fs();

        let ino = if flags & AT_EMPTY_PATH != 0 && path.is_empty() && dirfd < rux_fs::fdtable::MAX_FDS {
            match rux_fs::fdtable::get_fd_inode(dirfd) {
                Some(ino) => ino,
                None => return crate::errno::EBADF,
            }
        } else if flags & AT_SYMLINK_NOFOLLOW != 0 {
            match rux_fs::path::resolve_nofollow(fs, super::PROCESS.fs_ctx.cwd, path) {
                Ok(ino) => ino,
                Err(e) => return e,
            }
        } else {
            match super::resolve_at(dirfd, path) {
                Ok(ino) => ino,
                Err(e) => return e,
            }
        };

        let mut vfs_stat = core::mem::zeroed::<rux_fs::InodeStat>();
        if fs.stat(ino, &mut vfs_stat).is_err() { return crate::errno::ENOENT; }

        // Zero the entire statx buffer first
        core::ptr::write_bytes(buf as *mut u8, 0, 256);

        // struct statx layout (all little-endian):
        //   0: u32 stx_mask       (STATX_BASIC_STATS = 0x07ff)
        //   4: u32 stx_blksize    (4096)
        //   8: u64 stx_attributes (0)
        //  16: u32 stx_nlink
        //  20: u32 stx_uid
        //  24: u32 stx_gid
        //  28: u16 stx_mode
        //  32: u64 stx_ino
        //  40: u64 stx_size
        //  48: u64 stx_blocks
        //  56: u64 stx_attributes_mask (0)
        //  64: struct statx_timestamp stx_atime {sec:i64, nsec:u32, pad:i32} = 16 bytes
        //  80: stx_btime (16 bytes)
        //  96: stx_ctime (16 bytes)
        // 112: stx_mtime (16 bytes)
        // 128: u32 stx_rdev_major, 132: u32 stx_rdev_minor
        // 136: u32 stx_dev_major,  140: u32 stx_dev_minor
        let p = buf as *mut u8;
        *(p.add(0) as *mut u32) = 0x07ff;  // STATX_BASIC_STATS
        *(p.add(4) as *mut u32) = 4096;     // blksize
        *(p.add(16) as *mut u32) = vfs_stat.nlink as u32;
        *(p.add(20) as *mut u32) = vfs_stat.uid;
        *(p.add(24) as *mut u32) = vfs_stat.gid;
        *(p.add(28) as *mut u16) = vfs_stat.mode as u16;
        *(p.add(32) as *mut u64) = vfs_stat.ino;
        *(p.add(40) as *mut u64) = vfs_stat.size;
        *(p.add(48) as *mut u64) = vfs_stat.blocks;
        // Timestamps (atime=64, btime=80, ctime=96, mtime=112)
        *(p.add(64) as *mut i64) = vfs_stat.atime as i64;
        *(p.add(96) as *mut i64) = vfs_stat.ctime as i64;
        *(p.add(112) as *mut i64) = vfs_stat.mtime as i64;
        // dev major/minor — ext2 on virtio-blk = 254:0
        *(p.add(136) as *mut u32) = 254;
        0
    }
}

// ── Directory operations (POSIX.1) ──────────────────────────────────

/// chdir(path) — POSIX.1
/// fchdir(fd) — change CWD to directory referenced by fd
pub fn fchdir(fd: usize) -> isize {
    unsafe {
        if fd >= rux_fs::fdtable::MAX_FDS { return crate::errno::EBADF; }
        match rux_fs::fdtable::get_fd_inode(fd) {
            Some(ino) => { super::PROCESS.fs_ctx.cwd = ino; 0 }
            None => crate::errno::EBADF,
        }
    }
}

pub fn chdir(path_ptr: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        let path = crate::uaccess::read_user_cstr(path_ptr);
        if path.is_empty() { return crate::errno::ENOENT; }

        let fs = crate::kstate::fs();
        let ino = match super::resolve_with_cwd(path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };

        let mut stat = core::mem::zeroed::<rux_fs::InodeStat>();
        if fs.stat(ino, &mut stat).is_err() { return crate::errno::ENOENT; }
        if stat.mode & rux_fs::S_IFMT != rux_fs::S_IFDIR {
            return crate::errno::ENOTDIR;
        }

        super::PROCESS.fs_ctx.cwd = ino;

        if path[0] == b'/' {
            let len = path.len().min(255);
            super::PROCESS.fs_ctx.cwd_path[..len].copy_from_slice(&path[..len]);
            super::PROCESS.fs_ctx.cwd_path[len] = 0;
            super::PROCESS.fs_ctx.cwd_path_len = len;
        } else {
            let cur_len = super::PROCESS.fs_ctx.cwd_path_len;
            let need_slash = cur_len > 0 && super::PROCESS.fs_ctx.cwd_path[cur_len - 1] != b'/';
            let mut pos = cur_len;
            if need_slash && pos < 255 { super::PROCESS.fs_ctx.cwd_path[pos] = b'/'; pos += 1; }
            for &b in path {
                if pos >= 255 { break; }
                super::PROCESS.fs_ctx.cwd_path[pos] = b;
                pos += 1;
            }
            super::PROCESS.fs_ctx.cwd_path[pos] = 0;
            super::PROCESS.fs_ctx.cwd_path_len = pos;
        }
        0
    }
}

/// mkdir(pathname, mode) — POSIX.1
pub fn mkdir(path_ptr: usize, mode: usize) -> isize {
    mkdir_at((-100isize) as usize, path_ptr, mode) // AT_FDCWD
}

/// unlink(pathname) — POSIX.1
pub fn unlink(path_ptr: usize) -> isize {
    unlink_at((-100isize) as usize, path_ptr) // AT_FDCWD
}

/// rmdir(pathname) — POSIX.1: remove empty directory.
pub fn rmdir(path_ptr: usize) -> isize {
    unsafe {
        let (dir_ino, fname) = match super::resolve_parent_fname(path_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_rmdir(dir_ino, fname, &cred) {
            Ok(()) => 0,
            Err(e) => -(e.as_errno() as isize),
        }
    }
}

/// creat(pathname, mode) — POSIX.1 (equivalent to open with O_CREAT|O_WRONLY|O_TRUNC)
pub fn creat(path_ptr: usize) -> isize {
    creat_at((-100isize) as usize, path_ptr) // AT_FDCWD
}

/// mkdir_at(dirfd, path) — mkdirat with dirfd support
pub fn mkdir_at(dirfd: usize, path_ptr: usize, mode: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        let (dir_ino, fname) = match super::resolve_parent_fname_at(dirfd, path_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let cred = super::current_cred();
        let fs = crate::kstate::fs();
        match fs.checked_mkdir(dir_ino, fname, (mode & 0o7777) as u32, &cred) {
            Ok(ino) => {
                let _ = fs.utimes(ino, super::current_time_secs(), super::current_time_secs());
                0
            }
            Err(e) => -(e.as_errno() as isize),
        }
    }
}

/// unlink_at(dirfd, path) — unlinkat with dirfd support
pub fn unlink_at(dirfd: usize, path_ptr: usize) -> isize {
    unsafe {
        let (dir_ino, fname) = match super::resolve_parent_fname_at(dirfd, path_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_unlink(dir_ino, fname, &cred) {
            Ok(()) => 0,
            Err(e) => -(e.as_errno() as isize),
        }
    }
}

/// creat_at(dirfd, path) — mknodat/openat O_CREAT with dirfd support
pub fn creat_at(dirfd: usize, path_ptr: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        let (dir_ino, fname) = match super::resolve_parent_fname_at(dirfd, path_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let cred = super::current_cred();
        let fs = crate::kstate::fs();
        match fs.checked_create(dir_ino, fname, 0o644, &cred) {
            Ok(ino) => {
                let _ = fs.utimes(ino, super::current_time_secs(), super::current_time_secs());
                fdt::sys_open_ino(ino, 0o02, crate::kstate::fs()) // O_RDWR
            }
            Err(e) => -(e.as_errno() as isize),
        }
    }
}

// ── Path operations ─────────────────────────────────────────────────

/// rename_at(olddirfd, old, newdirfd, new) — renameat with dirfd support
pub fn rename_at(old_dirfd: usize, old_ptr: usize, new_dirfd: usize, new_ptr: usize) -> isize {
    unsafe {
        use rux_fs::FileName;
        let (old_dir, old_name_ref) = match super::resolve_parent_at(old_dirfd, old_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let mut old_name_buf = [0u8; 256];
        let old_name_len = old_name_ref.len().min(255);
        old_name_buf[..old_name_len].copy_from_slice(&old_name_ref[..old_name_len]);

        let (new_dir, new_name) = match super::resolve_parent_at(new_dirfd, new_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let old_fname = match FileName::new(&old_name_buf[..old_name_len]) { Ok(f) => f, Err(_) => return crate::errno::EINVAL };
        let new_fname = match FileName::new(new_name) { Ok(f) => f, Err(_) => return crate::errno::EINVAL };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_rename(old_dir, old_fname, new_dir, new_fname, &cred) {
            Ok(()) => 0,
            Err(e) => -(e.as_errno() as isize),
        }
    }
}

/// rename(oldpath, newpath) — POSIX.1
pub fn rename(old_ptr: usize, new_ptr: usize) -> isize {
    let at_fdcwd = (-100isize) as usize;
    rename_at(at_fdcwd, old_ptr, at_fdcwd, new_ptr)
}

/// symlink(target, linkpath) — POSIX.1
pub fn symlink(target_ptr: usize, link_ptr: usize) -> isize {
    symlink_at(target_ptr, (-100isize) as usize, link_ptr) // AT_FDCWD
}

/// symlinkat(target, dirfd, linkpath) — with dirfd support
pub fn symlink_at(target_ptr: usize, dirfd: usize, link_ptr: usize) -> isize {
    unsafe {
        let target = crate::uaccess::read_user_cstr(target_ptr);
        let mut target_buf = [0u8; 256];
        let tlen = target.len().min(255);
        target_buf[..tlen].copy_from_slice(&target[..tlen]);

        let (dir_ino, fname) = match super::resolve_parent_fname_at(dirfd, link_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_symlink(dir_ino, fname, &target_buf[..tlen], &cred) {
            Ok(_) => 0,
            Err(e) => -(e.as_errno() as isize),
        }
    }
}

/// fchownat(dirfd, path, uid, gid, flags) — with dirfd support
pub fn fchownat(dirfd: usize, path_ptr: usize, uid: usize, gid: usize) -> isize {
    unsafe {
        let path = crate::uaccess::read_user_cstr(path_ptr);
        let ino = match super::resolve_at(dirfd, path) {
            Ok(ino) => ino,
            Err(_) => return 0, // Silently succeed for non-existent (matches chown behavior)
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_chown(ino, uid as u32, gid as u32, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EPERM,
        }
    }
}

/// link(oldpath, newpath) — POSIX.1: create a hard link.
pub fn link(old_ptr: usize, new_ptr: usize) -> isize {
    link_at((-100isize) as usize, old_ptr, (-100isize) as usize, new_ptr) // AT_FDCWD
}

/// chmod(path, mode) — POSIX.1: change file permissions.
pub fn chmod(path_ptr: usize, mode: usize) -> isize {
    chmod_at((-100isize) as usize, path_ptr, mode) // AT_FDCWD
}

/// fchmod(fd, mode) — POSIX.1: change file permissions by fd.
pub fn fchmod(fd: usize, mode: usize) -> isize {
    unsafe {
        let f = match fdt::get_fd(fd) { Some(f) => f, None => return crate::errno::EBADF };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_chmod(f.ino, mode as u32, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EPERM,
        }
    }
}

/// chown(path, uid, gid) — POSIX.1: change file ownership.
pub fn chown(path_ptr: usize, uid: usize, gid: usize) -> isize {
    fchownat((-100isize) as usize, path_ptr, uid, gid) // AT_FDCWD
}

/// fchown(fd, uid, gid) — POSIX.1: change file ownership by fd.
pub fn fchown(fd: usize, uid: usize, gid: usize) -> isize {
    unsafe {
        let f = match fdt::get_fd(fd) { Some(f) => f, None => return crate::errno::EBADF };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_chown(f.ino, uid as u32, gid as u32, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EPERM,
        }
    }
}

const UTIME_NOW: u64 = 0x3FFFFFFF;
const UTIME_OMIT: u64 = 0x3FFFFFFE;

/// utimensat(dirfd, path, times, flags) — POSIX.1-2008: set file timestamps.
/// times is a pointer to two timespec structs (atime, mtime), or NULL for current time.
pub fn utimensat(dirfd: usize, path_ptr: usize, times_ptr: usize, _flags: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        let now = super::current_time_secs();
        if path_ptr == 0 { return 0; }
        let path = crate::uaccess::read_user_cstr(path_ptr);
        let ino = match super::resolve_at(dirfd, path) {
            Ok(ino) => ino,
            Err(_) => return 0,
        };
        let (atime, mtime) = if times_ptr == 0 {
            (now, now)
        } else {
            if crate::uaccess::validate_user_ptr(times_ptr, 32).is_err() { return crate::errno::EFAULT; }
            let a_sec = *(times_ptr as *const u64);
            let a_nsec = *((times_ptr + 8) as *const u64);
            let m_sec = *((times_ptr + 16) as *const u64);
            let m_nsec = *((times_ptr + 24) as *const u64);
            // Get current values for UTIME_OMIT
            let mut cur = core::mem::zeroed::<rux_fs::InodeStat>();
            let _ = crate::kstate::fs().stat(ino, &mut cur);
            let a = if a_nsec == UTIME_OMIT { cur.atime } else if a_nsec == UTIME_NOW { now } else { a_sec };
            let m = if m_nsec == UTIME_OMIT { cur.mtime } else if m_nsec == UTIME_NOW { now } else { m_sec };
            (a, m)
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_utimes(ino, atime, mtime, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EPERM,
        }
    }
}

/// readlinkat(dirfd, pathname, buf, bufsiz) — with dirfd support
pub fn readlink_at(dirfd: usize, path_ptr: usize, buf: usize, bufsiz: usize) -> isize {
    unsafe {
        use rux_fs::FileSystem;
        let (dir_ino, fname) = match super::resolve_parent_fname_at(dirfd, path_ptr) {
            Ok(v) => v, Err(e) => return e,
        };
        let fs = crate::kstate::fs();
        let ino = match fs.lookup(dir_ino, fname) {
            Ok(ino) => ino,
            Err(_) => return crate::errno::ENOENT,
        };
        if crate::uaccess::validate_user_ptr(buf, bufsiz).is_err() { return crate::errno::EFAULT; }
        let user_buf = core::slice::from_raw_parts_mut(buf as *mut u8, bufsiz);
        match fs.readlink(ino, user_buf) {
            Ok(n) => n as isize,
            Err(_) => crate::errno::EINVAL,
        }
    }
}

/// fchmodat(dirfd, path, mode) — with dirfd support
pub fn chmod_at(dirfd: usize, path_ptr: usize, mode: usize) -> isize {
    unsafe {
        let path = crate::uaccess::read_user_cstr(path_ptr);
        let ino = match super::resolve_at(dirfd, path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_chmod(ino, mode as u32, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EPERM,
        }
    }
}

/// linkat(olddirfd, old, newdirfd, new, flags) — with dirfd support
pub fn link_at(olddirfd: usize, old_ptr: usize, newdirfd: usize, new_ptr: usize) -> isize {
    unsafe {
        let old_path = crate::uaccess::read_user_cstr(old_ptr);
        let old_ino = match super::resolve_at(olddirfd, old_path) {
            Ok(ino) => ino,
            Err(e) => return e,
        };
        let (dir_ino, fname) = match super::resolve_parent_fname_at(newdirfd, new_ptr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let cred = super::current_cred();
        match crate::kstate::fs().checked_link(dir_ino, fname, old_ino, &cred) {
            Ok(()) => 0,
            Err(e) => -(e.as_errno() as isize),
        }
    }
}

/// faccessat(dirfd, path, amode, flags) — check file accessibility
pub fn faccessat(dirfd: usize, path_ptr: usize, amode: usize) -> isize {
    unsafe {
        let path = crate::uaccess::read_user_cstr(path_ptr);
        if path.is_empty() { return crate::errno::ENOENT; }
        let ino = match super::resolve_at(dirfd, path) {
            Ok(ino) => ino,
            Err(_) => return crate::errno::ENOENT,
        };
        if amode == 0 { return 0; } // F_OK: existence check only
        let cred = super::current_cred();
        match crate::kstate::fs().check_access(ino, amode as u32, &cred) {
            Ok(()) => 0,
            Err(_) => crate::errno::EACCES,
        }
    }
}

/// readlink(pathname, buf, bufsiz) — POSIX.1
/// Must NOT follow the symlink — resolve parent, lookup name, readlink on the symlink inode.
pub fn readlink(path_ptr: usize, buf: usize, bufsiz: usize) -> isize {
    readlink_at((-100isize) as usize, path_ptr, buf, bufsiz) // AT_FDCWD
}
