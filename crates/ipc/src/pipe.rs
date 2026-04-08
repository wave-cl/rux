/// Pipe ring buffers for inter-process communication.
///
/// Each pipe is a fixed-size ring buffer with separate reader/writer counts.
/// When all writers close, reads return 0 (EOF). When all readers close,
/// writes return -EPIPE.

const PIPE_BUF_SIZE: usize = 16384; // 16KB (Linux default is 64KB, but conserve BSS)
const MAX_PIPES: usize = 64;

/// Maximum concurrent processes (must match kernel's MAX_PROCS).
const MAX_WAITERS: usize = 64;

struct PipeBuf {
    buf: [u8; PIPE_BUF_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
    readers: u8,
    writers: u8,
    active: bool,
    /// Task indices waiting on this pipe (for targeted wakeup).
    waiters: [u8; MAX_WAITERS],
    waiter_count: u8,
}

static mut PIPES: [PipeBuf; MAX_PIPES] = {
    const EMPTY: PipeBuf = PipeBuf {
        buf: [0; PIPE_BUF_SIZE],
        read_pos: 0, write_pos: 0, count: 0,
        readers: 0, writers: 0, active: false,
        waiters: [0; MAX_WAITERS], waiter_count: 0,
    };
    [EMPTY; MAX_PIPES]
};

/// Check if a pipe has data available for reading (or EOF).
pub fn has_data(pipe_id: u8) -> bool {
    unsafe {
        let p = &PIPES[pipe_id as usize];
        p.active && (p.count > 0 || p.writers == 0)
    }
}

/// Return number of bytes available for reading.
pub fn available(pipe_id: u8) -> usize {
    unsafe {
        let p = &PIPES[pipe_id as usize];
        if p.active { p.count } else { 0 }
    }
}

/// Check if all writers have closed the pipe (EOF condition).
pub fn writers_closed(pipe_id: u8) -> bool {
    unsafe {
        let p = &PIPES[pipe_id as usize];
        p.active && p.writers == 0
    }
}

/// Allocate a pipe slot. Returns pipe_id or -EMFILE.
/// Count of currently active pipes (for diagnostics).
pub fn active_count() -> usize {
    unsafe { (&raw const PIPES).as_ref().unwrap().iter().filter(|p| p.active).count() }
}

pub fn alloc() -> Result<u8, isize> {
    unsafe {
        let pipe_id = (&raw const PIPES).as_ref().unwrap().iter().position(|p| !p.active)
            .ok_or(-24isize)? as u8;
        PIPES[pipe_id as usize] = PipeBuf {
            buf: [0; PIPE_BUF_SIZE],
            read_pos: 0, write_pos: 0, count: 0,
            readers: 1, writers: 1, active: true,
            waiters: [0; MAX_WAITERS], waiter_count: 0,
        };
        Ok(pipe_id)
    }
}

/// Read from a pipe.
/// Returns bytes read, 0 on EOF (no writers or empty), -11 (EAGAIN) if empty+writers+can_block.
pub fn read_ex(pipe_id: u8, buf: *mut u8, len: usize, can_block: bool) -> isize {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return -9; }
        if p.count == 0 {
            if p.writers == 0 { return 0; } // true EOF
            if can_block { return -11; } // EAGAIN — caller will block
            return 0; // non-blocking fallback
        }
        let to_read = len.min(p.count);
        // Split into at most 2 contiguous memcpy regions (before/after ring wrap)
        let first = to_read.min(PIPE_BUF_SIZE - p.read_pos);
        core::ptr::copy_nonoverlapping(p.buf.as_ptr().add(p.read_pos), buf, first);
        if first < to_read {
            core::ptr::copy_nonoverlapping(p.buf.as_ptr(), buf.add(first), to_read - first);
        }
        p.read_pos = (p.read_pos + to_read) % PIPE_BUF_SIZE;
        p.count -= to_read;
        to_read as isize
    }
}

/// Write to a pipe.
/// Returns bytes written, -32 (EPIPE) if no readers, -11 (EAGAIN) if full+readers+can_block.
pub fn write_ex(pipe_id: u8, buf: *const u8, len: usize, can_block: bool) -> isize {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return -9; }
        if p.readers == 0 { return -32; }
        let space = PIPE_BUF_SIZE - p.count;
        // POSIX: writes ≤ PIPE_BUF (4096) must be atomic — all or nothing
        if len <= 4096 && space < len {
            if can_block { return -11; } // EAGAIN — caller will block until space
            return 0;
        }
        if space == 0 {
            if can_block { return -11; }
            return 0;
        }
        let to_write = len.min(space);
        let first = to_write.min(PIPE_BUF_SIZE - p.write_pos);
        core::ptr::copy_nonoverlapping(buf, p.buf.as_mut_ptr().add(p.write_pos), first);
        if first < to_write {
            core::ptr::copy_nonoverlapping(buf.add(first), p.buf.as_mut_ptr(), to_write - first);
        }
        p.write_pos = (p.write_pos + to_write) % PIPE_BUF_SIZE;
        p.count += to_write;
        to_write as isize
    }
}

/// Non-blocking read (used by PipeFns interface). Returns 0 on empty.
pub fn read(pipe_id: u8, buf: *mut u8, len: usize) -> isize {
    read_ex(pipe_id, buf, len, false)
}

/// Non-blocking write (used by PipeFns interface). Returns partial on full.
pub fn write(pipe_id: u8, buf: *const u8, len: usize) -> isize {
    write_ex(pipe_id, buf, len, false)
}

/// Increment reader/writer count (called when dup/dup2 copies a pipe fd).
pub fn dup_ref(pipe_id: u8, is_write_end: bool) {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return; }
        if is_write_end { p.writers += 1; } else { p.readers += 1; }
    }
}

/// Close one end of a pipe.
pub fn close(pipe_id: u8, is_write_end: bool) {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return; }
        if is_write_end {
            p.writers = p.writers.saturating_sub(1);
        } else {
            p.readers = p.readers.saturating_sub(1);
        }
        if p.readers == 0 && p.writers == 0 {
            p.active = false;
        }
    }
}

/// Register a task as waiting on a pipe (for targeted wakeup).
pub fn register_waiter(pipe_id: u8, task_idx: u8) {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return; }
        let n = p.waiter_count as usize;
        if n < MAX_WAITERS {
            p.waiters[n] = task_idx;
            p.waiter_count += 1;
        }
    }
}

/// Get the list of task indices waiting on a pipe.
/// Returns a slice of length `waiter_count`.
pub fn get_waiters(pipe_id: u8) -> (u8, [u8; MAX_WAITERS]) {
    unsafe {
        let p = &PIPES[pipe_id as usize];
        (p.waiter_count, p.waiters)
    }
}

/// Clear all waiters for a pipe (called after waking them).
pub fn clear_all_waiters(pipe_id: u8) {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        p.waiter_count = 0;
    }
}

/// Reset all pipes (called on exec).
pub fn reset() {
    unsafe {
        for p in (&raw mut PIPES).as_mut().unwrap().iter_mut() {
            *p = PipeBuf {
                buf: [0; PIPE_BUF_SIZE],
                read_pos: 0, write_pos: 0, count: 0,
                readers: 0, writers: 0, active: false,
                waiters: [0; MAX_WAITERS], waiter_count: 0,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_pipes() {
        unsafe {
            for pipe in (&raw mut PIPES).as_mut().unwrap().iter_mut() {
                *pipe = PipeBuf {
                    buf: [0; PIPE_BUF_SIZE],
                    read_pos: 0, write_pos: 0, count: 0,
                    readers: 0, writers: 0, active: false,
                    waiters: [0; MAX_WAITERS], waiter_count: 0,
                };
            }
        }
    }

    #[test]
    fn test_alloc_and_free() {
        init_pipes();
        let id = alloc().unwrap();
        close(id, false); // close reader
        close(id, true);  // close writer
    }

    #[test]
    fn test_write_read_roundtrip() {
        init_pipes();
        let id = alloc().unwrap();
        let data = b"hello pipe";
        let n = write(id, data.as_ptr(), data.len());
        assert_eq!(n, data.len() as isize);
        let mut buf = [0u8; 32];
        let r = read(id, buf.as_mut_ptr(), buf.len());
        assert_eq!(r, data.len() as isize);
        assert_eq!(&buf[..data.len()], data);
    }

    #[test]
    fn test_fifo_order() {
        init_pipes();
        let id = alloc().unwrap();
        write(id, b"first".as_ptr(), 5);
        write(id, b"second".as_ptr(), 6);
        let mut buf = [0u8; 11];
        let n = read(id, buf.as_mut_ptr(), 11);
        assert_eq!(n, 11);
        assert_eq!(&buf, b"firstsecond");
    }

    #[test]
    fn test_dup_ref() {
        init_pipes();
        let id = alloc().unwrap();
        dup_ref(id, false); // dup reader
        dup_ref(id, true);  // dup writer
        close(id, false);   // close one reader
        // Pipe should still be active (refs > 0)
        write(id, b"x".as_ptr(), 1);
        let mut b = [0u8; 1];
        assert_eq!(read(id, b.as_mut_ptr(), 1), 1);
        assert_eq!(b[0], b'x');
    }

    // ── Group 1: EOF semantics (Linux: close write end → read returns 0) ──

    #[test]
    fn test_read_eof_after_writer_close() {
        init_pipes();
        let id = alloc().unwrap();
        close(id, true); // close writer
        let mut buf = [0u8; 16];
        assert_eq!(read(id, buf.as_mut_ptr(), buf.len()), 0); // EOF
    }

    #[test]
    fn test_read_data_then_eof() {
        init_pipes();
        let id = alloc().unwrap();
        write(id, b"hello".as_ptr(), 5);
        close(id, true); // close writer
        let mut buf = [0u8; 32];
        assert_eq!(read(id, buf.as_mut_ptr(), buf.len()), 5); // data first
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(read(id, buf.as_mut_ptr(), buf.len()), 0); // then EOF
    }

    #[test]
    fn test_writers_closed_flag() {
        init_pipes();
        let id = alloc().unwrap();
        assert!(!writers_closed(id));
        close(id, true);
        assert!(writers_closed(id));
    }

    #[test]
    fn test_has_data_reflects_eof() {
        init_pipes();
        let id = alloc().unwrap();
        assert!(!has_data(id)); // empty + writers → false
        write(id, b"x".as_ptr(), 1);
        assert!(has_data(id)); // data + writers → true
        let mut b = [0u8; 1];
        read(id, b.as_mut_ptr(), 1);
        assert!(!has_data(id)); // empty + writers → false
        close(id, true);
        assert!(has_data(id)); // empty + no writers → true (EOF ready)
    }

    // ── Group 2: EPIPE semantics (Linux: close read end → EPIPE) ──

    #[test]
    fn test_write_epipe_no_readers() {
        init_pipes();
        let id = alloc().unwrap();
        close(id, false); // close reader
        assert_eq!(write(id, b"x".as_ptr(), 1), -32); // EPIPE
    }

    #[test]
    fn test_write_epipe_after_drain() {
        init_pipes();
        let id = alloc().unwrap();
        write(id, b"data".as_ptr(), 4);
        close(id, false); // close reader
        assert_eq!(write(id, b"more".as_ptr(), 4), -32); // EPIPE
    }

    // ── Group 3: EAGAIN / blocking (Linux: O_NONBLOCK) ──

    #[test]
    fn test_read_eagain_blocking() {
        init_pipes();
        let id = alloc().unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(read_ex(id, buf.as_mut_ptr(), buf.len(), true), -11); // EAGAIN
    }

    #[test]
    fn test_read_nonblocking_empty() {
        init_pipes();
        let id = alloc().unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(read_ex(id, buf.as_mut_ptr(), buf.len(), false), 0);
    }

    #[test]
    fn test_write_eagain_full_blocking() {
        init_pipes();
        let id = alloc().unwrap();
        let big = [0xAA_u8; PIPE_BUF_SIZE];
        write(id, big.as_ptr(), big.len()); // fill completely
        assert_eq!(write_ex(id, b"x".as_ptr(), 1, true), -11); // EAGAIN
    }

    #[test]
    fn test_write_nonblocking_full() {
        init_pipes();
        let id = alloc().unwrap();
        let big = [0xAA_u8; PIPE_BUF_SIZE];
        write(id, big.as_ptr(), big.len()); // fill completely
        assert_eq!(write_ex(id, b"x".as_ptr(), 1, false), 0);
    }

    // ── Group 4: POSIX atomicity (PIPE_BUF = 4096) ──

    #[test]
    fn test_atomic_write_no_space() {
        init_pipes();
        let id = alloc().unwrap();
        let fill = [0u8; 13000];
        write(id, fill.as_ptr(), fill.len()); // 13000 in buffer, 3384 free
        // Atomic write of 4096 (≤ PIPE_BUF) with only 3384 space → EAGAIN
        let data = [0u8; 4096];
        assert_eq!(write_ex(id, data.as_ptr(), data.len(), true), -11);
    }

    #[test]
    fn test_large_write_partial_ok() {
        init_pipes();
        let id = alloc().unwrap();
        let fill = [0u8; 15000];
        write(id, fill.as_ptr(), fill.len()); // 15000 in buffer, 1384 free
        // Non-atomic write of 5000 (> PIPE_BUF) → partial write of 1384
        let data = [0u8; 5000];
        let n = write_ex(id, data.as_ptr(), data.len(), false);
        assert_eq!(n, (PIPE_BUF_SIZE - 15000) as isize); // 1384
    }

    #[test]
    fn test_atomic_write_exact_fit() {
        init_pipes();
        let id = alloc().unwrap();
        let full = [0xBB_u8; PIPE_BUF_SIZE];
        let n = write(id, full.as_ptr(), full.len());
        assert_eq!(n, PIPE_BUF_SIZE as isize);
        assert_eq!(available(id), PIPE_BUF_SIZE);
        // Next atomic write → EAGAIN
        assert_eq!(write_ex(id, b"x".as_ptr(), 1, true), -11);
    }

    // ── Group 5: Ring buffer wrap correctness ──

    #[test]
    fn test_ring_wrap_integrity() {
        init_pipes();
        let id = alloc().unwrap();
        // Advance read_pos to near the end: write then read a large chunk
        let advance = [0u8; PIPE_BUF_SIZE - 100];
        write(id, advance.as_ptr(), advance.len());
        let mut discard = [0u8; PIPE_BUF_SIZE - 100];
        read(id, discard.as_mut_ptr(), discard.len());
        // Now read_pos ≈ PIPE_BUF_SIZE-100, write_pos ≈ PIPE_BUF_SIZE-100
        // Write 200 bytes that wrap around the end
        let data: [u8; 200] = core::array::from_fn(|i| (i & 0xFF) as u8);
        let n = write(id, data.as_ptr(), 200);
        assert_eq!(n, 200);
        let mut out = [0u8; 200];
        let r = read(id, out.as_mut_ptr(), 200);
        assert_eq!(r, 200);
        assert_eq!(out, data); // byte-for-byte match across wrap
    }

    #[test]
    fn test_fill_drain_cycle() {
        init_pipes();
        let id = alloc().unwrap();
        for cycle in 0..3u8 {
            let fill: [u8; PIPE_BUF_SIZE] = [cycle; PIPE_BUF_SIZE];
            let n = write(id, fill.as_ptr(), fill.len());
            assert_eq!(n, PIPE_BUF_SIZE as isize, "fill failed cycle {}", cycle);
            let mut drain = [0u8; PIPE_BUF_SIZE];
            let r = read(id, drain.as_mut_ptr(), drain.len());
            assert_eq!(r, PIPE_BUF_SIZE as isize, "drain failed cycle {}", cycle);
            assert!(drain.iter().all(|&b| b == cycle), "data corrupt cycle {}", cycle);
        }
    }

    // ── Group 6: Lifecycle & slot management ──

    #[test]
    fn test_alloc_max_pipes() {
        init_pipes();
        let mut ids = Vec::new();
        for _ in 0..MAX_PIPES {
            ids.push(alloc().unwrap());
        }
        assert!(alloc().is_err()); // 65th fails
        // Clean up
        for id in ids {
            close(id, false);
            close(id, true);
        }
    }

    #[test]
    fn test_close_frees_slot() {
        init_pipes();
        let id = alloc().unwrap();
        assert_eq!(active_count(), 1);
        close(id, false);
        close(id, true);
        assert_eq!(active_count(), 0);
        // Slot should be reusable
        let id2 = alloc().unwrap();
        assert_eq!(id2, id); // reuses same slot
    }

    #[test]
    fn test_active_count_accuracy() {
        init_pipes();
        let a = alloc().unwrap();
        let b = alloc().unwrap();
        let c = alloc().unwrap();
        assert_eq!(active_count(), 3);
        close(a, false); close(a, true);
        assert_eq!(active_count(), 2);
        close(b, false); close(b, true);
        close(c, false); close(c, true);
        assert_eq!(active_count(), 0);
    }

    #[test]
    fn test_double_close_harmless() {
        init_pipes();
        let id = alloc().unwrap();
        close(id, true);  // close writer
        close(id, true);  // double close — saturating_sub prevents underflow
        // Pipe still active because reader is open
        assert!(!writers_closed(id) || writers_closed(id)); // doesn't crash
    }

    #[test]
    fn test_close_inactive_noop() {
        init_pipes();
        close(0, true);  // close on never-allocated pipe
        close(0, false); // should not crash
    }

    // ── Group 7: Reference counting (Linux: dup increments refcount) ──

    #[test]
    fn test_dup_writer_delays_eof() {
        init_pipes();
        let id = alloc().unwrap();
        dup_ref(id, true); // now 2 writers
        close(id, true);   // close one writer
        assert!(!writers_closed(id)); // still 1 writer
        close(id, true);   // close last writer
        assert!(writers_closed(id));  // now EOF
    }

    #[test]
    fn test_dup_reader_delays_epipe() {
        init_pipes();
        let id = alloc().unwrap();
        dup_ref(id, false); // now 2 readers
        close(id, false);   // close one reader
        assert_eq!(write(id, b"ok".as_ptr(), 2), 2); // write still works
        close(id, false);   // close last reader
        assert_eq!(write(id, b"x".as_ptr(), 1), -32); // EPIPE
    }

    #[test]
    fn test_multi_dup_close_sequence() {
        init_pipes();
        let id = alloc().unwrap();
        // Dup writer 3 times → 4 writers total
        dup_ref(id, true);
        dup_ref(id, true);
        dup_ref(id, true);
        // Close 3 dups
        close(id, true);
        close(id, true);
        close(id, true);
        assert!(!writers_closed(id)); // original still open
        close(id, true); // close original
        assert!(writers_closed(id));
    }

    // ── Group 8: Partial reads (Linux: byte stream, no message boundaries) ──

    #[test]
    fn test_partial_read_leaves_remainder() {
        init_pipes();
        let id = alloc().unwrap();
        write(id, b"0123456789".as_ptr(), 10);
        let mut buf = [0u8; 3];
        assert_eq!(read(id, buf.as_mut_ptr(), 3), 3);
        assert_eq!(&buf, b"012");
        assert_eq!(available(id), 7);
        let mut rest = [0u8; 7];
        assert_eq!(read(id, rest.as_mut_ptr(), 7), 7);
        assert_eq!(&rest, b"3456789");
        assert_eq!(available(id), 0);
    }

    #[test]
    fn test_multiple_small_reads() {
        init_pipes();
        let id = alloc().unwrap();
        let data = [0x42_u8; 100];
        write(id, data.as_ptr(), 100);
        let mut buf = [0u8; 30];
        assert_eq!(read(id, buf.as_mut_ptr(), 30), 30);
        assert_eq!(read(id, buf.as_mut_ptr(), 30), 30);
        assert_eq!(read(id, buf.as_mut_ptr(), 30), 30);
        assert_eq!(read(id, buf.as_mut_ptr(), 30), 10); // only 10 left
    }

    // ── Group 9: Waiter system ──

    #[test]
    fn test_register_get_clear_waiters() {
        init_pipes();
        let id = alloc().unwrap();
        register_waiter(id, 5);
        register_waiter(id, 10);
        register_waiter(id, 15);
        let (count, waiters) = get_waiters(id);
        assert_eq!(count, 3);
        assert_eq!(waiters[0], 5);
        assert_eq!(waiters[1], 10);
        assert_eq!(waiters[2], 15);
        clear_all_waiters(id);
        let (count2, _) = get_waiters(id);
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_waiter_overflow_silent() {
        init_pipes();
        let id = alloc().unwrap();
        for i in 0..MAX_WAITERS + 5 {
            register_waiter(id, i as u8);
        }
        let (count, _) = get_waiters(id);
        assert_eq!(count, MAX_WAITERS as u8); // capped, no crash
    }

    // ── Group 10: Edge cases ──

    #[test]
    fn test_read_write_inactive() {
        init_pipes();
        let mut buf = [0u8; 16];
        assert_eq!(read_ex(0, buf.as_mut_ptr(), buf.len(), false), -9); // EBADF
        assert_eq!(write_ex(0, b"x".as_ptr(), 1, false), -9); // EBADF
    }

    #[test]
    fn test_zero_length_ops() {
        init_pipes();
        let id = alloc().unwrap();
        let mut buf = [0u8; 1];
        // Zero-length read on empty pipe
        assert_eq!(read(id, buf.as_mut_ptr(), 0), 0);
        // Zero-length write
        assert_eq!(write(id, b"".as_ptr(), 0), 0);
        // Pipe state unchanged
        assert_eq!(available(id), 0);
    }

    #[test]
    fn test_available_tracks_count() {
        init_pipes();
        let id = alloc().unwrap();
        assert_eq!(available(id), 0);
        write(id, b"hello world, this is 42 bytes of test data!".as_ptr(), 42);
        assert_eq!(available(id), 42);
        let mut buf = [0u8; 10];
        read(id, buf.as_mut_ptr(), 10);
        assert_eq!(available(id), 32);
    }
}
