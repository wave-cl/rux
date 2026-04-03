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
}
