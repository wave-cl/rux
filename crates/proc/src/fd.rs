use crate::error::ProcError;

/// Maximum file descriptors per process.
pub const MAX_FDS: usize = 256;

/// Per-fd flags.
pub const FD_CLOEXEC: u32 = 1;

/// A single open file descriptor entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FdEntry {
    /// Inode ID of the open file (0 = entry is unused/closed).
    pub inode: u64,
    /// Current file offset for read/write.
    pub offset: u64,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, etc.).
    pub flags: u32,
    /// Per-fd flags (FD_CLOEXEC).
    pub fd_flags: u32,
}

const _: () = assert!(core::mem::size_of::<FdEntry>() == 24);

impl FdEntry {
    pub const CLOSED: Self = Self { inode: 0, offset: 0, flags: 0, fd_flags: 0 };

    #[inline(always)]
    pub const fn is_open(&self) -> bool { self.inode != 0 }
}

/// Per-process file descriptor table.
/// Stored by pointer in Task (6 KiB is too large to inline).
/// Shared between threads created with CLONE_FILES (via refcount).
#[repr(C)]
pub struct FdTable {
    /// File descriptor entries, indexed by fd number.
    pub entries: [FdEntry; MAX_FDS],
    /// Number of currently open file descriptors.
    pub count: u32,
    pub _pad: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<FdTable>() == 6152);

impl FdTable {
    /// Empty file descriptor table.
    pub const fn new() -> Self {
        Self {
            entries: [FdEntry::CLOSED; MAX_FDS],
            count: 0,
            _pad: [0; 4],
        }
    }

    /// Validate and bounds-check an fd number.
    #[inline(always)]
    fn validate_fd(fd: i32) -> Result<usize, ProcError> {
        if fd < 0 || fd as usize >= MAX_FDS {
            return Err(ProcError::InvalidFd);
        }
        Ok(fd as usize)
    }

    /// Find the lowest free fd slot.
    #[inline]
    fn find_free(&self) -> Result<usize, ProcError> {
        for i in 0..MAX_FDS {
            if !self.entries[i].is_open() {
                return Ok(i);
            }
        }
        Err(ProcError::FdTableFull)
    }
}

impl Default for FdTable {
    fn default() -> Self { Self::new() }
}

/// File descriptor operations trait.
pub trait FdOps {
    fn open(&mut self, inode: u64, flags: u32) -> Result<i32, ProcError>;
    fn close(&mut self, fd: i32) -> Result<(), ProcError>;
    fn dup(&mut self, old_fd: i32) -> Result<i32, ProcError>;
    fn dup2(&mut self, old_fd: i32, new_fd: i32) -> Result<i32, ProcError>;
    fn get(&self, fd: i32) -> Result<&FdEntry, ProcError>;
    fn get_mut(&mut self, fd: i32) -> Result<&mut FdEntry, ProcError>;
    fn close_on_exec(&mut self);
}

impl FdOps for FdTable {
    fn open(&mut self, inode: u64, flags: u32) -> Result<i32, ProcError> {
        if inode == 0 {
            return Err(ProcError::InvalidArgument);
        }
        let idx = self.find_free()?;
        self.entries[idx] = FdEntry {
            inode,
            offset: 0,
            flags,
            fd_flags: 0,
        };
        self.count += 1;
        Ok(idx as i32)
    }

    fn close(&mut self, fd: i32) -> Result<(), ProcError> {
        let idx = FdTable::validate_fd(fd)?;
        if !self.entries[idx].is_open() {
            return Err(ProcError::InvalidFd);
        }
        self.entries[idx] = FdEntry::CLOSED;
        self.count -= 1;
        Ok(())
    }

    fn dup(&mut self, old_fd: i32) -> Result<i32, ProcError> {
        let old_idx = FdTable::validate_fd(old_fd)?;
        if !self.entries[old_idx].is_open() {
            return Err(ProcError::InvalidFd);
        }
        let new_idx = self.find_free()?;
        self.entries[new_idx] = self.entries[old_idx];
        self.entries[new_idx].fd_flags &= !FD_CLOEXEC; // dup clears CLOEXEC
        self.count += 1;
        Ok(new_idx as i32)
    }

    fn dup2(&mut self, old_fd: i32, new_fd: i32) -> Result<i32, ProcError> {
        let old_idx = FdTable::validate_fd(old_fd)?;
        let new_idx = FdTable::validate_fd(new_fd)?;
        if !self.entries[old_idx].is_open() {
            return Err(ProcError::InvalidFd);
        }
        if old_idx == new_idx {
            return Ok(new_fd);
        }
        // Close new_fd if open
        if self.entries[new_idx].is_open() {
            self.entries[new_idx] = FdEntry::CLOSED;
            self.count -= 1;
        }
        self.entries[new_idx] = self.entries[old_idx];
        self.entries[new_idx].fd_flags &= !FD_CLOEXEC;
        self.count += 1;
        Ok(new_fd)
    }

    fn get(&self, fd: i32) -> Result<&FdEntry, ProcError> {
        let idx = FdTable::validate_fd(fd)?;
        if !self.entries[idx].is_open() {
            return Err(ProcError::InvalidFd);
        }
        Ok(&self.entries[idx])
    }

    fn get_mut(&mut self, fd: i32) -> Result<&mut FdEntry, ProcError> {
        let idx = FdTable::validate_fd(fd)?;
        if !self.entries[idx].is_open() {
            return Err(ProcError::InvalidFd);
        }
        Ok(&mut self.entries[idx])
    }

    fn close_on_exec(&mut self) {
        for i in 0..MAX_FDS {
            if self.entries[i].is_open() && (self.entries[i].fd_flags & FD_CLOEXEC) != 0 {
                self.entries[i] = FdEntry::CLOSED;
                self.count -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::boxed::Box;

    fn make_table() -> Box<FdTable> {
        Box::new(FdTable::new())
    }

    #[test]
    fn open_returns_lowest_fd() {
        let mut t = make_table();
        let fd0 = t.open(1, 0).expect("open fd 0");
        assert_eq!(fd0, 0, "first open should return fd 0");
        let fd1 = t.open(2, 0).expect("open fd 1");
        assert_eq!(fd1, 1, "second open should return fd 1");
        let fd2 = t.open(3, 0).expect("open fd 2");
        assert_eq!(fd2, 2, "third open should return fd 2");
    }

    #[test]
    fn open_fills_table_returns_error() {
        let mut t = make_table();
        for i in 0..MAX_FDS {
            t.open((i + 1) as u64, 0).expect("open should succeed");
        }
        let err = t.open(9999, 0).unwrap_err();
        assert_eq!(err, ProcError::FdTableFull, "should get FdTableFull when all slots used");
    }

    #[test]
    fn close_and_reopen_reuses_fd() {
        let mut t = make_table();
        let fd0 = t.open(1, 0).unwrap();
        let fd1 = t.open(2, 0).unwrap();
        let _fd2 = t.open(3, 0).unwrap();
        t.close(fd0).expect("close fd 0");
        t.close(fd1).expect("close fd 1");
        // Reopening should reuse fd 0 (lowest free)
        let reused = t.open(4, 0).unwrap();
        assert_eq!(reused, 0, "should reuse lowest available fd (0)");
        let reused2 = t.open(5, 0).unwrap();
        assert_eq!(reused2, 1, "should reuse next lowest available fd (1)");
    }

    #[test]
    fn close_invalid_fd_errors() {
        let mut t = make_table();
        // Close on a never-opened fd
        assert_eq!(t.close(0).unwrap_err(), ProcError::InvalidFd, "closing unopened fd should fail");
        // Negative fd
        assert_eq!(t.close(-1).unwrap_err(), ProcError::InvalidFd, "negative fd should fail");
        // Out of range
        assert_eq!(t.close(MAX_FDS as i32).unwrap_err(), ProcError::InvalidFd, "out-of-range fd should fail");
    }

    #[test]
    fn dup_copies_entry() {
        let mut t = make_table();
        let fd0 = t.open(42, 0x0800).unwrap(); // O_APPEND-ish
        let fd1 = t.dup(fd0).unwrap();
        assert_ne!(fd0, fd1, "dup should return a different fd");
        let e0 = t.get(fd0).unwrap();
        let e1 = t.get(fd1).unwrap();
        assert_eq!(e0.inode, e1.inode, "dup should copy inode");
        assert_eq!(e0.flags, e1.flags, "dup should copy flags");
    }

    #[test]
    fn dup_clears_cloexec() {
        let mut t = make_table();
        let fd0 = t.open(42, 0).unwrap();
        t.get_mut(fd0).unwrap().fd_flags = FD_CLOEXEC;
        let fd1 = t.dup(fd0).unwrap();
        let e1 = t.get(fd1).unwrap();
        assert_eq!(e1.fd_flags & FD_CLOEXEC, 0, "dup must clear FD_CLOEXEC on new fd");
    }

    #[test]
    fn dup_on_closed_fd_errors() {
        let mut t = make_table();
        assert_eq!(t.dup(0).unwrap_err(), ProcError::InvalidFd, "dup on closed fd should fail");
    }

    #[test]
    fn dup2_overwrites_target() {
        let mut t = make_table();
        let fd0 = t.open(10, 0).unwrap();
        let fd1 = t.open(20, 0).unwrap();
        let result = t.dup2(fd0, fd1).unwrap();
        assert_eq!(result, fd1, "dup2 should return new_fd");
        let entry = t.get(fd1).unwrap();
        assert_eq!(entry.inode, 10, "dup2 should overwrite target with source inode");
    }

    #[test]
    fn dup2_same_fd_noop() {
        let mut t = make_table();
        let fd0 = t.open(10, 0).unwrap();
        let count_before = t.count;
        let result = t.dup2(fd0, fd0).unwrap();
        assert_eq!(result, fd0, "dup2 with same fd should return fd");
        assert_eq!(t.count, count_before, "dup2 with same fd should not change count");
    }

    #[test]
    fn close_on_exec_closes_flagged() {
        let mut t = make_table();
        let fd0 = t.open(1, 0).unwrap();
        let fd1 = t.open(2, 0).unwrap();
        let fd2 = t.open(3, 0).unwrap();
        // Mark fd0 and fd2 as CLOEXEC
        t.get_mut(fd0).unwrap().fd_flags = FD_CLOEXEC;
        t.get_mut(fd2).unwrap().fd_flags = FD_CLOEXEC;
        t.close_on_exec();
        assert!(!t.entries[fd0 as usize].is_open(), "fd0 with CLOEXEC should be closed");
        assert!(t.entries[fd1 as usize].is_open(), "fd1 without CLOEXEC should remain open");
        assert!(!t.entries[fd2 as usize].is_open(), "fd2 with CLOEXEC should be closed");
        assert_eq!(t.count, 1, "count should reflect only the remaining open fd");
    }

    #[test]
    fn get_returns_correct_entry() {
        let mut t = make_table();
        let fd = t.open(77, 0x42).unwrap();
        let entry = t.get(fd).unwrap();
        assert_eq!(entry.inode, 77, "get should return correct inode");
        assert_eq!(entry.flags, 0x42, "get should return correct flags");
    }

    #[test]
    fn get_closed_fd_errors() {
        let t = make_table();
        assert_eq!(t.get(0).unwrap_err(), ProcError::InvalidFd, "get on closed fd should fail");
    }

    #[test]
    fn get_mut_modifies_entry() {
        let mut t = make_table();
        let fd = t.open(1, 0).unwrap();
        t.get_mut(fd).unwrap().offset = 1024;
        assert_eq!(t.get(fd).unwrap().offset, 1024, "get_mut should allow modifying offset");
    }

    #[test]
    fn count_tracks_correctly() {
        let mut t = make_table();
        assert_eq!(t.count, 0, "initial count should be 0");
        let fd0 = t.open(1, 0).unwrap();
        assert_eq!(t.count, 1, "count after one open");
        let fd1 = t.open(2, 0).unwrap();
        assert_eq!(t.count, 2, "count after two opens");
        let _fd2 = t.dup(fd0).unwrap();
        assert_eq!(t.count, 3, "count after dup");
        t.close(fd1).unwrap();
        assert_eq!(t.count, 2, "count after close");
        // dup2 onto an open fd: closes target then opens new = net 0
        t.dup2(fd0, _fd2).unwrap();
        assert_eq!(t.count, 2, "count after dup2 onto open fd");
    }

    #[test]
    fn open_with_zero_inode_errors() {
        let mut t = make_table();
        assert_eq!(t.open(0, 0).unwrap_err(), ProcError::InvalidArgument, "inode 0 should be rejected");
    }
}
