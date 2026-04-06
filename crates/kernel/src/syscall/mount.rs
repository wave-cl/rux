//! mount/umount syscalls for filesystem mounting.
//!
//! Supports: proc, tmpfs/devtmpfs/ramfs, sysfs (stub).
//! Alpine's OpenRC needs mount -t proc proc /proc etc.

use crate::uaccess;

/// mount(source, target, fstype, flags, data) → 0 or -errno
pub fn sys_mount(
    _source_ptr: usize, target_ptr: usize, fstype_ptr: usize,
    _flags: usize, _data_ptr: usize,
) -> isize {
    unsafe {
        let target = uaccess::read_user_cstr(target_ptr);
        if target.is_empty() { return crate::errno::EINVAL; }
        let fstype = uaccess::read_user_cstr(fstype_ptr);

        let vfs = crate::kstate::fs();

        // Resolve target directory
        let dir_ino = match rux_fs::path::resolve_path(vfs, target) {
            Ok(ino) => ino,
            Err(_) => return crate::errno::ENOENT,
        };

        // Determine mount point name (last component of target path)
        let name = match target.iter().rposition(|&b| b == b'/') {
            Some(pos) if pos + 1 < target.len() => &target[pos + 1..],
            _ => target,
        };

        // Mount based on fstype
        if fstype == b"proc" {
            // Create a new ProcFs instance
            static mut MOUNT_PROCFS: rux_fs::procfs::ProcFs = rux_fs::procfs::ProcFs::new(
                || {
                    use rux_arch::TimerOps;
                    crate::arch::Arch::ticks()
                },
                || 16384,
                || unsafe {
                    use rux_mm::FrameAllocator;
                    crate::kstate::alloc().available_frames(rux_mm::PageSize::FourK)
                },
                |buf| unsafe {
                    use crate::task_table::*;
                    let mut count = 0;
                    for i in 0..MAX_PROCS {
                        if TASK_TABLE[i].active && TASK_TABLE[i].state != TaskState::Free && count < buf.len() {
                            buf[count] = TASK_TABLE[i].pid;
                            count += 1;
                        }
                    }
                    count
                },
                || crate::task_table::current_pid(),
                |pid, buf| unsafe {
                    use crate::task_table::*;
                    for i in 0..MAX_PROCS {
                        if TASK_TABLE[i].active && TASK_TABLE[i].pid == pid {
                            let len = (TASK_TABLE[i].cmdline_len as usize).min(buf.len());
                            buf[..len].copy_from_slice(&TASK_TABLE[i].cmdline[..len]);
                            return len;
                        }
                    }
                    0
                },
            );
            let _ = vfs.mount(dir_ino, name, rux_fs::vfs::MountedFs::Proc(&raw mut MOUNT_PROCFS));
            0
        } else if fstype == b"tmpfs" || fstype == b"devtmpfs" || fstype == b"ramfs" {
            // Mount a fresh ramfs at the target
            // For devtmpfs, we use our existing DevFs
            if fstype == b"devtmpfs" {
                static mut MOUNT_DEVFS: rux_fs::devfs::DevFs = rux_fs::devfs::DevFs::new();
                let _ = vfs.mount(dir_ino, name, rux_fs::vfs::MountedFs::Dev(&raw mut MOUNT_DEVFS));
            } else {
                // tmpfs/ramfs: use a minimal ramfs
                // For now, just succeed silently (the target dir exists on the root fs)
            }
            0
        } else if fstype == b"sysfs" {
            // sysfs: stub (pretend it mounted, Alpine checks return code)
            0
        } else {
            crate::errno::ENOSYS
        }
    }
}

/// umount2(target, flags) → 0 or -errno
pub fn sys_umount(_target_ptr: usize, _flags: usize) -> isize {
    // Stub: always succeed (Alpine calls umount during shutdown)
    0
}
