//! Native test harness.
//!
//! Run with: `cargo test -p rux-kernel --features native -- --test-threads=1`
//!
//! Tests share global kernel state (PROCESS, FD_TABLE, VFS), so they must run
//! sequentially. The `setup()` call is idempotent after first invocation.

use crate::syscall::{self, Syscall};

// Path to the initramfs cpio relative to the workspace root.
// Built by `bash initramfs/build.sh` before running tests.
const CPIO_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../initramfs/initramfs_x86_64.cpio"
);

static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Initialize kernel state once. Safe to call from multiple tests.
fn setup() {
    INIT.get_or_init(|| unsafe {
        let data = std::fs::read(CPIO_PATH)
            .unwrap_or_else(|_| {
                // Try aarch64 if x86 not present
                let alt = CPIO_PATH.replace("x86_64", "aarch64");
                std::fs::read(&alt)
                    .unwrap_or_else(|e| panic!("cpio not found at {CPIO_PATH} or {alt}: {e}"))
            });
        crate::boot::init_native(&data);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Filesystem tests ──────────────────────────────────────────────────

    #[test]
    fn test_getcwd_is_root() {
        setup();
        let mut buf = [0u8; 256];
        let r = unsafe {
            syscall::dispatch(Syscall::Getcwd, buf.as_mut_ptr() as usize, 256, 0, 0, 0)
        };
        assert_eq!(r, buf.as_ptr() as isize, "getcwd returned error");
        assert_eq!(buf[0], b'/', "cwd should start with /");
        assert_eq!(buf[1], 0, "cwd should be exactly /");
    }

    #[test]
    fn test_open_close_file() {
        setup();
        // /etc/hostname was created by initramfs/build.sh with content "rux"
        let path = b"/etc/hostname\0";
        let fd = unsafe {
            syscall::dispatch(Syscall::Open, path.as_ptr() as usize, 0, 0, 0, 0)
        };
        assert!(fd >= 3, "open returned error {fd}");
        let r = unsafe { syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0) };
        assert_eq!(r, 0, "close failed");
    }

    #[test]
    fn test_read_hostname() {
        setup();
        let path = b"/etc/hostname\0";
        let fd = unsafe {
            syscall::dispatch(Syscall::Open, path.as_ptr() as usize, 0, 0, 0, 0)
        };
        assert!(fd >= 3, "open failed: {fd}");

        let mut buf = [0u8; 64];
        let n = unsafe {
            syscall::dispatch(Syscall::Read, fd as usize, buf.as_mut_ptr() as usize, 64, 0, 0)
        };
        assert!(n > 0, "read returned {n}");
        assert_eq!(&buf[..3], b"rux", "hostname should start with 'rux'");

        unsafe { syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0) };
    }

    #[test]
    fn test_write_stdout() {
        setup();
        let msg = b"native test write\n";
        let n = unsafe {
            syscall::dispatch(Syscall::Write, 1, msg.as_ptr() as usize, msg.len(), 0, 0)
        };
        assert_eq!(n, msg.len() as isize, "write to stdout failed");
    }

    #[test]
    fn test_open_nonexistent_returns_error() {
        setup();
        let path = b"/this/does/not/exist\0";
        let r = unsafe {
            syscall::dispatch(Syscall::Open, path.as_ptr() as usize, 0, 0, 0, 0)
        };
        assert!(r < 0, "expected error, got {r}");
    }

    #[test]
    fn test_mkdir_and_chdir() {
        setup();
        // Create /tmp/testdir
        let path = b"/tmp/testdir\0";
        let r = unsafe {
            syscall::dispatch(Syscall::Mkdir, path.as_ptr() as usize, 0o755, 0, 0, 0)
        };
        assert!(r == 0 || r == -17, "mkdir failed: {r}"); // -EEXIST is fine

        // Chdir into it
        let r = unsafe {
            syscall::dispatch(Syscall::Chdir, path.as_ptr() as usize, 0, 0, 0, 0)
        };
        assert_eq!(r, 0, "chdir failed: {r}");

        // Verify getcwd
        let mut buf = [0u8; 256];
        let r = unsafe {
            syscall::dispatch(Syscall::Getcwd, buf.as_mut_ptr() as usize, 256, 0, 0, 0)
        };
        assert!(r > 0);
        let cwd = std::ffi::CStr::from_bytes_until_nul(&buf).unwrap().to_bytes();
        assert!(cwd.ends_with(b"testdir"), "cwd should end with testdir, got {:?}", cwd);

        // Chdir back to /
        let root = b"/\0";
        unsafe { syscall::dispatch(Syscall::Chdir, root.as_ptr() as usize, 0, 0, 0, 0) };
    }

    #[test]
    fn test_pipe_write_read() {
        setup();
        // pipe2(fds, 0)
        let mut fds = [0i32; 2];
        let r = unsafe {
            syscall::dispatch(Syscall::Pipe2, fds.as_mut_ptr() as usize, 0, 0, 0, 0)
        };
        assert_eq!(r, 0, "pipe2 failed: {r}");

        let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
        assert!(rfd >= 3 && wfd >= 3, "bad pipe fds: {rfd} {wfd}");

        let msg = b"hello pipe";
        let n = unsafe {
            syscall::dispatch(Syscall::Write, wfd, msg.as_ptr() as usize, msg.len(), 0, 0)
        };
        assert_eq!(n, msg.len() as isize, "pipe write failed: {n}");

        let mut rbuf = [0u8; 64];
        let n = unsafe {
            syscall::dispatch(Syscall::Read, rfd, rbuf.as_mut_ptr() as usize, 64, 0, 0)
        };
        assert_eq!(n, msg.len() as isize, "pipe read returned {n}");
        assert_eq!(&rbuf[..n as usize], msg);

        unsafe { syscall::dispatch(Syscall::Close, rfd, 0, 0, 0, 0) };
        unsafe { syscall::dispatch(Syscall::Close, wfd, 0, 0, 0, 0) };
    }

    #[test]
    fn test_stat_file() {
        setup();
        let path = b"/bin/busybox\0";
        let mut stat_buf = [0u8; 128];
        let r = unsafe {
            syscall::dispatch(Syscall::Stat, path.as_ptr() as usize, stat_buf.as_mut_ptr() as usize, 0, 0, 0)
        };
        assert_eq!(r, 0, "stat failed: {r}");
        // size field at offset 48 (both x86_64 and aarch64 layouts)
        let size = unsafe { *(stat_buf.as_ptr().add(48) as *const i64) };
        assert!(size > 0, "busybox size should be > 0, got {size}");
    }

    #[test]
    fn test_dup_and_close() {
        setup();
        let path = b"/etc/passwd\0";
        let fd = unsafe {
            syscall::dispatch(Syscall::Open, path.as_ptr() as usize, 0, 0, 0, 0)
        };
        assert!(fd >= 3, "open failed: {fd}");

        let fd2 = unsafe { syscall::dispatch(Syscall::Dup, fd as usize, 0, 0, 0, 0) };
        assert!(fd2 > fd, "dup failed: {fd2}");

        unsafe { syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0) };
        unsafe { syscall::dispatch(Syscall::Close, fd2 as usize, 0, 0, 0, 0) };
    }

    #[test]
    fn test_lseek() {
        setup();
        let path = b"/etc/hostname\0";
        let fd = unsafe {
            syscall::dispatch(Syscall::Open, path.as_ptr() as usize, 0, 0, 0, 0)
        };
        assert!(fd >= 3);

        // Seek to offset 1
        let pos = unsafe {
            syscall::dispatch(Syscall::Lseek, fd as usize, 1, 0 /* SEEK_SET */, 0, 0)
        };
        assert_eq!(pos, 1, "lseek failed: {pos}");

        // Read from offset 1
        let mut buf = [0u8; 4];
        let n = unsafe {
            syscall::dispatch(Syscall::Read, fd as usize, buf.as_mut_ptr() as usize, 4, 0, 0)
        };
        assert!(n > 0, "read after lseek failed: {n}");
        // "rux" → from offset 1 we get "ux"
        assert_eq!(buf[0], b'u');

        unsafe { syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0) };
    }

    #[test]
    fn test_getpid_nonzero() {
        setup();
        let pid = unsafe { syscall::dispatch(Syscall::Getpid, 0, 0, 0, 0, 0) };
        assert!(pid > 0, "getpid should return a positive PID, got {pid}");
    }

    #[test]
    fn test_uname() {
        setup();
        let mut buf = [0u8; 325];
        let r = unsafe {
            syscall::dispatch(Syscall::Uname, buf.as_mut_ptr() as usize, 0, 0, 0, 0)
        };
        assert_eq!(r, 0, "uname failed: {r}");
        assert_eq!(&buf[..3], b"rux", "sysname should be 'rux'");
    }

    #[test]
    fn test_symlink_and_readlink() {
        setup();
        unsafe {
            // Create symlink: symlink("/bin/busybox", "/tmp/mylink")
            let target = b"/bin/busybox\0";
            let link = b"/tmp/mylink\0";
            let r = syscall::dispatch(Syscall::Symlink, target.as_ptr() as usize, link.as_ptr() as usize, 0, 0, 0);
            assert!(r >= 0, "symlink failed: {r}");
            // Readlink
            let mut buf = [0u8; 64];
            let n = syscall::dispatch(Syscall::Readlink, link.as_ptr() as usize, buf.as_mut_ptr() as usize, 64, 0, 0);
            assert!(n > 0, "readlink failed: {n}");
            assert_eq!(&buf[..n as usize], b"/bin/busybox");
        }
    }

    #[test]
    fn test_unlink_file() {
        setup();
        unsafe {
            // Create a file
            let path = b"/tmp/unlinktest\0";
            let fd = syscall::dispatch(Syscall::Creat, path.as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0, "creat failed: {fd}");
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
            // Unlink
            let r = syscall::dispatch(Syscall::Unlink, path.as_ptr() as usize, 0, 0, 0, 0);
            assert_eq!(r, 0, "unlink failed: {r}");
            // Stat should fail
            let mut stat_buf = [0u8; 256];
            let r2 = syscall::dispatch(Syscall::Stat, path.as_ptr() as usize, stat_buf.as_mut_ptr() as usize, 0, 0, 0);
            assert!(r2 < 0, "stat after unlink should fail");
        }
    }

    #[test]
    fn test_unknown_syscall_returns_enosys() {
        setup();
        let r = syscall::dispatch(Syscall::Unknown(9999), 0, 0, 0, 0, 0);
        assert_eq!(r, crate::errno::ENOSYS);
    }

    #[test]
    fn test_rename_file() {
        setup();
        unsafe {
            let old = b"/tmp/rename_src\0";
            let new = b"/tmp/rename_dst\0";
            let fd = syscall::dispatch(Syscall::Creat, old.as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0);
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
            let r = syscall::dispatch(Syscall::Rename, old.as_ptr() as usize, new.as_ptr() as usize, 0, 0, 0);
            assert_eq!(r, 0, "rename failed: {r}");
        }
    }

    #[test]
    fn test_pipe_multiple_writes() {
        setup();
        unsafe {
            // Create pipe
            let mut fds = [0i32; 2];
            let r = syscall::dispatch(Syscall::Pipe2, fds.as_mut_ptr() as usize, 0, 0, 0, 0);
            assert!(r >= 0, "pipe2 failed: {r}");
            let rfd = fds[0] as usize;
            let wfd = fds[1] as usize;
            // Write 3 chunks
            let d1 = b"aaa";
            let d2 = b"bbb";
            let d3 = b"ccc";
            syscall::dispatch(Syscall::Write, wfd, d1.as_ptr() as usize, 3, 0, 0);
            syscall::dispatch(Syscall::Write, wfd, d2.as_ptr() as usize, 3, 0, 0);
            syscall::dispatch(Syscall::Write, wfd, d3.as_ptr() as usize, 3, 0, 0);
            // Read all back
            let mut buf = [0u8; 9];
            let n = syscall::dispatch(Syscall::Read, rfd, buf.as_mut_ptr() as usize, 9, 0, 0);
            assert_eq!(n, 9, "read returned {n}");
            assert_eq!(&buf, b"aaabbbccc");
            syscall::dispatch(Syscall::Close, rfd, 0, 0, 0, 0);
            syscall::dispatch(Syscall::Close, wfd, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_mkdir_and_chdir_nested() {
        setup();
        unsafe {
            let dir = b"/tmp/nested\0";
            let r = syscall::dispatch(Syscall::Mkdir, dir.as_ptr() as usize, 0, 0, 0, 0);
            assert!(r >= 0 || r == -17, "mkdir failed: {r}"); // -EEXIST ok
            let r = syscall::dispatch(Syscall::Chdir, dir.as_ptr() as usize, 0, 0, 0, 0);
            assert_eq!(r, 0, "chdir failed: {r}");
            // Verify cwd changed
            let mut buf = [0u8; 64];
            let n = syscall::dispatch(Syscall::Getcwd, buf.as_mut_ptr() as usize, 64, 0, 0, 0);
            assert!(n > 0);
            let cwd = std::ffi::CStr::from_bytes_until_nul(&buf).unwrap().to_bytes();
            assert!(cwd.ends_with(b"nested"), "cwd should end with nested, got {:?}", cwd);
            // Restore cwd
            syscall::dispatch(Syscall::Chdir, b"/\0".as_ptr() as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_getdents64() {
        setup();
        unsafe {
            // Open root directory
            let fd = syscall::dispatch(Syscall::Open, b"/\0".as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0, "open / failed: {fd}");
            let mut buf = [0u8; 512];
            let n = syscall::dispatch(Syscall::Getdents64, fd as usize, buf.as_mut_ptr() as usize, 512, 0, 0);
            assert!(n > 0, "getdents64 returned {n}");
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
        }
    }

    // ── pid hash ──────────────────────────────────────────────────────
    #[test]
    fn test_pid_hash_insert_lookup_remove() {
        setup();
        use crate::task_table::{
            find_task_by_pid, pid_hash_insert, pid_hash_remove, TASK_TABLE, MAX_PROCS,
        };
        unsafe {
            // Use a slot well past the usual test range to avoid clashes.
            const SLOT: usize = MAX_PROCS - 1;
            const TEST_PID: u32 = 54321;

            // Stash whatever's in the slot so we can restore it.
            let saved_active = TASK_TABLE[SLOT].active;
            let saved_pid = TASK_TABLE[SLOT].pid;

            TASK_TABLE[SLOT].active = true;
            TASK_TABLE[SLOT].pid = TEST_PID;
            pid_hash_insert(TEST_PID, SLOT);

            // Lookup via the public wrapper — should find our slot.
            assert_eq!(find_task_by_pid(TEST_PID), Some(SLOT));

            // Unknown pid returns None.
            assert_eq!(find_task_by_pid(65535), None);

            // Remove and verify.
            pid_hash_remove(TEST_PID);
            assert_eq!(find_task_by_pid(TEST_PID), None);

            // Restore.
            TASK_TABLE[SLOT].active = saved_active;
            TASK_TABLE[SLOT].pid = saved_pid;
        }
    }

    // ── fs_ops coverage: fd validation + metadata ops ────────────────
    //
    // These tests target the handlers in crates/kernel/src/syscall/
    // fs_ops.rs that had no native coverage before — especially the
    // fd-validation branches added in commit 46465b2. Each test covers
    // either the EBADF path, the happy path, or both.

    // AT_FDCWD is passed as a signed -100 but the syscall takes usize.
    const AT_FDCWD: usize = (-100isize) as usize;
    // EBADF as returned by handlers (negative errno, no ctypes wrap).
    const EBADF: isize = -9;
    const ENOENT: isize = -2;

    #[test]
    fn test_fchmod_bad_fd() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Fchmod, (-1isize) as usize, 0o644, 0, 0, 0);
            assert_eq!(r, EBADF, "fchmod(-1) should be EBADF, got {r}");
        }
    }

    #[test]
    fn test_fchmod_valid_fd() {
        setup();
        unsafe {
            // /etc/hostname is owned by root=0 in the test rootfs; we
            // run as root in native tests so fchmod should succeed.
            let fd = syscall::dispatch(Syscall::Open, b"/etc/hostname\0".as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0, "open hostname: {fd}");
            let r = syscall::dispatch(Syscall::Fchmod, fd as usize, 0o644, 0, 0, 0);
            assert_eq!(r, 0, "fchmod on valid fd: {r}");
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_fchown_bad_fd() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Fchown, (-1isize) as usize, 0, 0, 0, 0);
            assert_eq!(r, EBADF, "fchown(-1) should be EBADF, got {r}");
        }
    }

    #[test]
    fn test_fchown_valid_fd() {
        setup();
        unsafe {
            let fd = syscall::dispatch(Syscall::Open, b"/etc/hostname\0".as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0);
            // Root can chown to any uid/gid.
            let r = syscall::dispatch(Syscall::Fchown, fd as usize, 0, 0, 0, 0);
            assert_eq!(r, 0, "fchown on valid fd: {r}");
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_fchdir_bad_fd() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Fchdir, (-1isize) as usize, 0, 0, 0, 0);
            assert!(r < 0, "fchdir(-1) should fail, got {r}");
        }
    }

    #[test]
    fn test_fchdir_valid_dir() {
        setup();
        unsafe {
            // Open / then fchdir into it — should leave cwd at /.
            let fd = syscall::dispatch(Syscall::Open, b"/\0".as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0);
            let r = syscall::dispatch(Syscall::Fchdir, fd as usize, 0, 0, 0, 0);
            assert_eq!(r, 0, "fchdir(/) failed: {r}");
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_utimensat_bad_dirfd() {
        setup();
        unsafe {
            // dirfd=-1 with any path (or NULL) must be EBADF — not the
            // former "NULL path silently succeeds" behaviour.
            let r = syscall::dispatch(Syscall::Utimensat, (-1isize) as usize, 0, 0, 0, 0);
            assert_eq!(r, EBADF, "utimensat(-1) should be EBADF, got {r}");
        }
    }

    #[test]
    fn test_utimensat_atcwd_happy_path() {
        setup();
        unsafe {
            // AT_FDCWD + existing path + NULL times = "set to now".
            let r = syscall::dispatch(Syscall::Utimensat, AT_FDCWD,
                b"/etc/hostname\0".as_ptr() as usize, 0, 0, 0);
            assert_eq!(r, 0, "utimensat AT_FDCWD happy path: {r}");
        }
    }

    #[test]
    fn test_faccessat_bad_dirfd() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Faccessat, (-1isize) as usize,
                b"hostname\0".as_ptr() as usize, 0, 0, 0);
            assert_eq!(r, EBADF, "faccessat(-1) should be EBADF, got {r}");
        }
    }

    #[test]
    fn test_faccessat_atcwd_exists() {
        setup();
        unsafe {
            // F_OK=0 = existence check only.
            let r = syscall::dispatch(Syscall::Faccessat, AT_FDCWD,
                b"/etc/hostname\0".as_ptr() as usize, 0, 0, 0);
            assert_eq!(r, 0, "faccessat(AT_FDCWD, hostname, F_OK): {r}");
        }
    }

    #[test]
    fn test_faccessat_atcwd_missing() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Faccessat, AT_FDCWD,
                b"/nonexistent/file\0".as_ptr() as usize, 0, 0, 0);
            assert_eq!(r, ENOENT, "faccessat missing should be ENOENT, got {r}");
        }
    }

    #[test]
    fn test_truncate_missing() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Truncate,
                b"/nonexistent/path\0".as_ptr() as usize, 0, 0, 0, 0);
            assert!(r < 0, "truncate(missing) should fail, got {r}");
        }
    }

    #[test]
    fn test_ftruncate_bad_fd() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Ftruncate, (-1isize) as usize, 0, 0, 0, 0);
            assert_eq!(r, EBADF, "ftruncate(-1) should be EBADF, got {r}");
        }
    }

    #[test]
    fn test_ftruncate_happy_path() {
        setup();
        unsafe {
            let path = b"/tmp/trunctest\0";
            let fd = syscall::dispatch(Syscall::Creat, path.as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0, "creat: {fd}");
            // Write 10 bytes.
            let data = b"0123456789";
            syscall::dispatch(Syscall::Write, fd as usize, data.as_ptr() as usize, 10, 0, 0);
            // Truncate to 4.
            let r = syscall::dispatch(Syscall::Ftruncate, fd as usize, 4, 0, 0, 0);
            assert_eq!(r, 0, "ftruncate: {r}");
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
            // Stat to confirm size = 4.
            let mut buf = [0u8; 256];
            syscall::dispatch(Syscall::Stat, path.as_ptr() as usize, buf.as_mut_ptr() as usize, 0, 0, 0);
            let size = *(buf.as_ptr().add(48) as *const i64);
            assert_eq!(size, 4, "truncated file size: {size}");
            syscall::dispatch(Syscall::Unlink, path.as_ptr() as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_fstatat_atcwd() {
        setup();
        unsafe {
            let mut buf = [0u8; 256];
            let r = syscall::dispatch(Syscall::FstatAt, AT_FDCWD,
                b"/etc/hostname\0".as_ptr() as usize, buf.as_mut_ptr() as usize, 0, 0);
            assert_eq!(r, 0, "fstatat AT_FDCWD: {r}");
            let size = *(buf.as_ptr().add(48) as *const i64);
            assert!(size > 0, "hostname size > 0, got {size}");
        }
    }

    #[test]
    fn test_chmod_atcwd_missing() {
        setup();
        unsafe {
            // chmod on a missing path must fail (used to be a silent
            // success when the handler didn't validate the inode).
            let r = syscall::dispatch(Syscall::Chmod,
                b"/nonexistent/chmod\0".as_ptr() as usize, 0o644, 0, 0, 0);
            assert!(r < 0, "chmod(missing) should fail, got {r}");
        }
    }

    /// Exercise the relative-path branch of chdir's path-concatenation
    /// logic. Other chdir tests only use absolute paths, which skip
    /// lines 219-231 (the `else` branch + for loop).
    #[test]
    fn test_chdir_relative_path_concatenation() {
        setup();
        unsafe {
            // Absolute chdir first to pin cwd.
            syscall::dispatch(Syscall::Chdir, b"/tmp\0".as_ptr() as usize, 0, 0, 0, 0);
            // Make a nested dir.
            let nested = b"/tmp/reldir\0";
            let r = syscall::dispatch(Syscall::Mkdir, nested.as_ptr() as usize, 0o755, 0, 0, 0);
            assert!(r == 0 || r == -17, "mkdir reldir: {r}");
            // Relative chdir — no leading slash.
            let r = syscall::dispatch(Syscall::Chdir, b"reldir\0".as_ptr() as usize, 0, 0, 0, 0);
            assert_eq!(r, 0, "relative chdir: {r}");
            // Verify the cwd_path got concatenated correctly.
            let mut buf = [0u8; 64];
            let n = syscall::dispatch(Syscall::Getcwd, buf.as_mut_ptr() as usize, 64, 0, 0, 0);
            assert!(n > 0);
            let cwd = std::ffi::CStr::from_bytes_until_nul(&buf).unwrap().to_bytes();
            // Should be exactly /tmp/reldir — not /tmp//reldir (slash
            // dedup) and not /reldir (parent lost).
            assert_eq!(cwd, b"/tmp/reldir", "concatenated cwd: {:?}", cwd);
            // Restore to /.
            syscall::dispatch(Syscall::Chdir, b"/\0".as_ptr() as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_chdir_empty_path() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Chdir, b"\0".as_ptr() as usize, 0, 0, 0, 0);
            assert_eq!(r, ENOENT, "chdir('') should be ENOENT, got {r}");
        }
    }

    #[test]
    fn test_chdir_not_a_directory() {
        setup();
        unsafe {
            // /etc/hostname is a regular file → ENOTDIR.
            let r = syscall::dispatch(Syscall::Chdir, b"/etc/hostname\0".as_ptr() as usize, 0, 0, 0, 0);
            assert!(r < 0, "chdir(regular file) should fail, got {r}");
        }
    }

    #[test]
    fn test_fstat_valid_fd() {
        setup();
        unsafe {
            let fd = syscall::dispatch(Syscall::Open, b"/etc/hostname\0".as_ptr() as usize, 0, 0, 0, 0);
            assert!(fd >= 0);
            let mut buf = [0u8; 256];
            let r = syscall::dispatch(Syscall::Fstat, fd as usize, buf.as_mut_ptr() as usize, 0, 0, 0);
            assert_eq!(r, 0, "fstat: {r}");
            // size field > 0
            let size = *(buf.as_ptr().add(48) as *const i64);
            assert!(size > 0, "fstat size: {size}");
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_fstat_bad_fd() {
        setup();
        unsafe {
            let mut buf = [0u8; 256];
            let r = syscall::dispatch(Syscall::Fstat, (-1isize) as usize,
                buf.as_mut_ptr() as usize, 0, 0, 0);
            assert!(r < 0, "fstat(-1) should fail, got {r}");
        }
    }

    #[test]
    fn test_statx_happy_path() {
        setup();
        unsafe {
            let mut buf = [0u8; 256];
            // statx(dirfd=AT_FDCWD, path, flags=0, mask=0, buf)
            let r = syscall::dispatch(Syscall::Statx, AT_FDCWD,
                b"/etc/hostname\0".as_ptr() as usize, 0, 0, buf.as_mut_ptr() as usize);
            assert_eq!(r, 0, "statx: {r}");
        }
    }

    #[test]
    fn test_statx_missing() {
        setup();
        unsafe {
            let mut buf = [0u8; 256];
            let r = syscall::dispatch(Syscall::Statx, AT_FDCWD,
                b"/no/such/file\0".as_ptr() as usize, 0, 0, buf.as_mut_ptr() as usize);
            assert!(r < 0, "statx missing: {r}");
        }
    }

    #[test]
    fn test_lstat_valid() {
        setup();
        unsafe {
            let mut buf = [0u8; 256];
            let r = syscall::dispatch(Syscall::Lstat,
                b"/etc/hostname\0".as_ptr() as usize, buf.as_mut_ptr() as usize, 0, 0, 0);
            assert_eq!(r, 0, "lstat: {r}");
        }
    }

    #[test]
    fn test_mkdir_at_fdcwd() {
        setup();
        unsafe {
            let path = b"/tmp/mkdirat_test\0";
            syscall::dispatch(Syscall::Unlinkat, AT_FDCWD, path.as_ptr() as usize, 0, 0, 0); // cleanup
            let r = syscall::dispatch(Syscall::Mkdirat, AT_FDCWD,
                path.as_ptr() as usize, 0o755, 0, 0);
            assert!(r == 0 || r == -17, "mkdirat: {r}");
        }
    }

    #[test]
    fn test_unlink_at_missing() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::Unlinkat, AT_FDCWD,
                b"/nonexistent/unlinkat\0".as_ptr() as usize, 0, 0, 0);
            assert!(r < 0, "unlinkat missing: {r}");
        }
    }

    // ── posix_timer coverage: sys_timer_* syscall handlers ─────────
    //
    // Targets crates/kernel/src/posix_timer.rs. The 5 unit tests in
    // that module only cover the PosixTimer struct (is_cpu_clock,
    // EMPTY, valid_clock, cleanup). None of the sys_timer_* handlers
    // that Phase 1 coverage showed as well-exercised by QEMU are
    // tested natively — mutation baseline started at 5%.

    const CLOCK_REALTIME: usize = 0;
    const CLOCK_MONOTONIC: usize = 1;
    const EINVAL: isize = -22;
    const EFAULT: isize = -14;

    #[test]
    fn test_timer_create_valid_clock() {
        setup();
        unsafe {
            let mut tid: u32 = 0xffffffff;
            let r = syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            assert_eq!(r, 0, "timer_create MONOTONIC: {r}");
            assert_ne!(tid, 0xffffffff, "timer id not written");
            // Clean up so slots stay fresh for subsequent tests.
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_timer_create_rejects_bad_clock() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            let r = syscall::dispatch(Syscall::TimerCreate, 99, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            assert_eq!(r, EINVAL, "timer_create bad clock: {r}");
        }
    }

    #[test]
    fn test_timer_create_null_timerid() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC, 0, 0, 0, 0);
            assert_eq!(r, EFAULT, "timer_create NULL tid_ptr: {r}");
        }
    }

    #[test]
    fn test_timer_delete_roundtrip() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            // First delete succeeds.
            let r = syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
            assert_eq!(r, 0, "first delete: {r}");
            // Second delete fails.
            let r = syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
            assert!(r < 0, "second delete should fail, got {r}");
        }
    }

    #[test]
    fn test_timer_delete_out_of_range() {
        setup();
        unsafe {
            // timerid >= MAX_POSIX_TIMERS (128) must fail.
            let r = syscall::dispatch(Syscall::TimerDelete, 9999, 0, 0, 0, 0);
            assert!(r < 0, "timer_delete bad id: {r}");
        }
    }

    #[test]
    fn test_timer_settime_arm_and_gettime() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            // itimerspec: interval = 0, value = 1 sec.
            let itspec: [u64; 4] = [0, 0, 1, 0];
            let r = syscall::dispatch(Syscall::TimerSettime, tid as usize, 0,
                itspec.as_ptr() as usize, 0, 0);
            assert_eq!(r, 0, "timer_settime arm: {r}");
            // timer_gettime writes 4 u64s into the buffer.
            let mut got: [u64; 4] = [0; 4];
            let r = syscall::dispatch(Syscall::TimerGettime, tid as usize,
                got.as_mut_ptr() as usize, 0, 0, 0);
            assert_eq!(r, 0, "timer_gettime: {r}");
            // Remaining time should be non-zero (we just armed for 1s).
            assert!(got[2] > 0 || got[3] > 0, "remaining time: {got:?}");
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_timer_settime_disarm() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            // Arm first.
            let arm: [u64; 4] = [0, 0, 5, 0];
            syscall::dispatch(Syscall::TimerSettime, tid as usize, 0,
                arm.as_ptr() as usize, 0, 0);
            // Disarm by setting value = 0.
            let disarm: [u64; 4] = [0, 0, 0, 0];
            let r = syscall::dispatch(Syscall::TimerSettime, tid as usize, 0,
                disarm.as_ptr() as usize, 0, 0);
            assert_eq!(r, 0, "timer_settime disarm: {r}");
            // Clean up.
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_timer_settime_null_newval() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::TimerSettime, 0, 0, 0, 0, 0);
            assert_eq!(r, EFAULT, "timer_settime NULL: {r}");
        }
    }

    #[test]
    fn test_timer_settime_bad_id() {
        setup();
        unsafe {
            let arm: [u64; 4] = [0, 0, 1, 0];
            let r = syscall::dispatch(Syscall::TimerSettime, 9999, 0,
                arm.as_ptr() as usize, 0, 0);
            assert!(r < 0, "timer_settime bad id: {r}");
        }
    }

    #[test]
    fn test_timer_gettime_bad_id() {
        setup();
        unsafe {
            let mut got: [u64; 4] = [0; 4];
            let r = syscall::dispatch(Syscall::TimerGettime, 9999,
                got.as_mut_ptr() as usize, 0, 0, 0);
            assert!(r < 0, "timer_gettime bad id: {r}");
        }
    }

    #[test]
    fn test_timer_getoverrun_bad_id() {
        setup();
        unsafe {
            let r = syscall::dispatch(Syscall::TimerGetoverrun, 9999, 0, 0, 0, 0);
            assert!(r < 0, "timer_getoverrun bad id: {r}");
        }
    }

    #[test]
    fn test_timer_getoverrun_fresh_is_zero() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            syscall::dispatch(Syscall::TimerCreate, CLOCK_REALTIME, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            let r = syscall::dispatch(Syscall::TimerGetoverrun, tid as usize, 0, 0, 0, 0);
            assert_eq!(r, 0, "fresh overrun should be 0, got {r}");
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_timer_create_cpu_clock() {
        setup();
        unsafe {
            // CLOCK_PROCESS_CPUTIME_ID = 2 (uses ns path instead of ms).
            let mut tid: u32 = 0;
            let r = syscall::dispatch(Syscall::TimerCreate, 2, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            assert_eq!(r, 0, "timer_create CPU clock: {r}");
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    /// SIGEV_SIGNAL is the default path. Passing a sigevent with
    /// explicit SIGEV_SIGNAL + custom signo exercises the notify
    /// matching + signo validation branches.
    #[test]
    fn test_timer_create_sigev_signal_explicit() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            // struct sigevent layout (see sys_timer_create comments):
            //   sigev_value:  offset 0  (8 bytes)
            //   sigev_signo:  offset 8  (4 bytes)   = SIGRTMIN (34)
            //   sigev_notify: offset 12 (4 bytes)   = SIGEV_SIGNAL = 0
            let mut sev = [0u8; 64];
            *(sev.as_mut_ptr().add(8) as *mut i32) = 34;
            *(sev.as_mut_ptr().add(12) as *mut i32) = 0;
            let r = syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC,
                sev.as_ptr() as usize, &mut tid as *mut u32 as usize, 0, 0);
            assert_eq!(r, 0, "sigev SIGNAL: {r}");
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    /// SIGEV_NONE: "no signal delivery, polling only." Exercises the
    /// sigev_notify match arm that zeros signo.
    #[test]
    fn test_timer_create_sigev_none() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            let mut sev = [0u8; 64];
            // sigev_notify = SIGEV_NONE = 1
            *(sev.as_mut_ptr().add(12) as *mut i32) = 1;
            let r = syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC,
                sev.as_ptr() as usize, &mut tid as *mut u32 as usize, 0, 0);
            assert_eq!(r, 0, "sigev NONE: {r}");
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    /// Unknown sigev_notify value must be rejected with EINVAL.
    #[test]
    fn test_timer_create_sigev_unknown() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            let mut sev = [0u8; 64];
            *(sev.as_mut_ptr().add(12) as *mut i32) = 99;
            let r = syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC,
                sev.as_ptr() as usize, &mut tid as *mut u32 as usize, 0, 0);
            assert_eq!(r, EINVAL, "sigev bad notify: {r}");
        }
    }

    /// Signo < 1 or > 64 is rejected (even for SIGEV_SIGNAL).
    #[test]
    fn test_timer_create_sigev_bad_signo() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            let mut sev = [0u8; 64];
            *(sev.as_mut_ptr().add(8) as *mut i32) = 0; // signo=0 is invalid
            *(sev.as_mut_ptr().add(12) as *mut i32) = 0;
            let r = syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC,
                sev.as_ptr() as usize, &mut tid as *mut u32 as usize, 0, 0);
            assert_eq!(r, EINVAL, "sigev bad signo: {r}");
        }
    }

    /// Arm a timer with a non-zero *interval* (periodic). Exercises
    /// the interval_ms branch and the gettime path that reports
    /// remaining + interval separately.
    #[test]
    fn test_timer_settime_interval_periodic() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            // interval = 2s, value = 1s → periodic 2-second reload
            // with first expiry at t=1s.
            let itspec: [u64; 4] = [2, 0, 1, 0];
            let r = syscall::dispatch(Syscall::TimerSettime, tid as usize, 0,
                itspec.as_ptr() as usize, 0, 0);
            assert_eq!(r, 0, "periodic settime: {r}");
            // gettime should return interval=2s, remaining<=1s.
            let mut got: [u64; 4] = [0; 4];
            syscall::dispatch(Syscall::TimerGettime, tid as usize,
                got.as_mut_ptr() as usize, 0, 0, 0);
            assert_eq!(got[0], 2, "interval.tv_sec: {}", got[0]);
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    /// timer_settime with old_value pointer — writes the PREVIOUS
    /// itimerspec out so the caller can save/restore. Exercises the
    /// write_itimerspec code path.
    #[test]
    fn test_timer_settime_returns_old_value() {
        setup();
        unsafe {
            let mut tid: u32 = 0;
            syscall::dispatch(Syscall::TimerCreate, CLOCK_MONOTONIC, 0,
                &mut tid as *mut u32 as usize, 0, 0);
            // First arm: interval=3s, value=1s.
            let first: [u64; 4] = [3, 0, 1, 0];
            syscall::dispatch(Syscall::TimerSettime, tid as usize, 0,
                first.as_ptr() as usize, 0, 0);
            // Second arm: asks for the previous state via old_value.
            let second: [u64; 4] = [0, 0, 5, 0];
            let mut old: [u64; 4] = [0; 4];
            let r = syscall::dispatch(Syscall::TimerSettime, tid as usize, 0,
                second.as_ptr() as usize, old.as_mut_ptr() as usize, 0);
            assert_eq!(r, 0, "settime with old: {r}");
            // Old value should report interval=3s.
            assert_eq!(old[0], 3, "old interval.tv_sec: {}", old[0]);
            syscall::dispatch(Syscall::TimerDelete, tid as usize, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_creat_and_write() {
        setup();
        unsafe {
            let path = b"/tmp/creat_test\0";
            let fd = syscall::dispatch(Syscall::Creat, path.as_ptr() as usize, 0o644, 0, 0, 0);
            assert!(fd >= 0, "creat: {fd}");
            let data = b"creat_ok";
            let n = syscall::dispatch(Syscall::Write, fd as usize, data.as_ptr() as usize, 8, 0, 0);
            assert_eq!(n, 8);
            syscall::dispatch(Syscall::Close, fd as usize, 0, 0, 0, 0);
            // Stat it
            let mut buf = [0u8; 256];
            let r = syscall::dispatch(Syscall::Stat, path.as_ptr() as usize, buf.as_mut_ptr() as usize, 0, 0, 0);
            assert_eq!(r, 0);
            let size = *(buf.as_ptr().add(48) as *const i64);
            assert_eq!(size, 8);
            syscall::dispatch(Syscall::Unlink, path.as_ptr() as usize, 0, 0, 0, 0);
        }
    }

    // ── Signal coalescing for standard signals ───────────────────────
    #[test]
    fn test_signal_coalescing() {
        setup();
        use rux_proc::signal::{SignalHot, SignalSet};
        let mut hot = SignalHot::new();

        // Send SIGTERM (15) twice — should coalesce to one pending bit.
        hot.pending = hot.pending.add(15);
        hot.pending = hot.pending.add(15);

        // Only one signal pending (bit 15 set).
        assert!(hot.pending.contains(15));
        assert_eq!(hot.pending, SignalSet::EMPTY.add(15));

        // Removing it clears the pending bit.
        hot.pending = hot.pending.remove(15);
        assert!(!hot.pending.contains(15));
    }
}
