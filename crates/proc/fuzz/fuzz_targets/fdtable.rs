#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_proc::fd::{FdTable, FdOps, FdEntry, FD_CLOEXEC, MAX_FDS};
use rux_proc::error::ProcError;

#[derive(Debug, Arbitrary)]
enum FdOp {
    Open { inode: u8 },
    Close { fd: u8 },
    Dup { fd: u8 },
    Dup2 { old_fd: u8, new_fd: u8 },
    SetCloexec { fd: u8 },
    CloseOnExec,
    Get { fd: u8 },
}

fuzz_target!(|ops: Vec<FdOp>| {
    if ops.len() > 512 {
        return;
    }

    let mut t = Box::new(FdTable::new());

    for op in &ops {
        match op {
            FdOp::Open { inode } => {
                let inode_val = *inode as u64 + 1; // avoid inode 0
                let _ = t.open(inode_val, 0);
            }
            FdOp::Close { fd } => {
                let _ = t.close(*fd as i32);
            }
            FdOp::Dup { fd } => {
                let _ = t.dup(*fd as i32);
            }
            FdOp::Dup2 { old_fd, new_fd } => {
                let _ = t.dup2(*old_fd as i32, *new_fd as i32);
            }
            FdOp::SetCloexec { fd } => {
                if let Ok(entry) = t.get_mut(*fd as i32) {
                    entry.fd_flags |= FD_CLOEXEC;
                }
            }
            FdOp::CloseOnExec => {
                t.close_on_exec();
            }
            FdOp::Get { fd } => {
                let _ = t.get(*fd as i32);
            }
        }

        // ── Invariant: count must match actual open entries ──
        let actual_count = t.entries.iter().filter(|e| e.is_open()).count() as u32;
        assert_eq!(
            t.count, actual_count,
            "count {} != actual open entries {}",
            t.count, actual_count
        );

        // ── Invariant: count <= MAX_FDS ──
        assert!(t.count as usize <= MAX_FDS, "count exceeds MAX_FDS");

        // ── Invariant: closed entries have all-zero fields ──
        for i in 0..MAX_FDS {
            if !t.entries[i].is_open() {
                assert_eq!(t.entries[i].inode, 0);
                assert_eq!(t.entries[i].offset, 0);
                assert_eq!(t.entries[i].flags, 0);
                assert_eq!(t.entries[i].fd_flags, 0);
            }
        }
    }
});
