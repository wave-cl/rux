/// Pipe ring buffers for inter-process communication.
///
/// Each pipe is a fixed-size ring buffer with separate reader/writer counts.
/// When all writers close, reads return 0 (EOF). When all readers close,
/// writes return -EPIPE.

const PIPE_BUF_SIZE: usize = 4096;
const MAX_PIPES: usize = 32;

/// Maximum concurrent processes (must match kernel's MAX_PROCS).
const MAX_WAITERS: usize = 32;

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

/// Check if all writers have closed the pipe (EOF condition).
pub fn writers_closed(pipe_id: u8) -> bool {
    unsafe {
        let p = &PIPES[pipe_id as usize];
        p.active && p.writers == 0
    }
}

/// Allocate a pipe slot. Returns pipe_id or -EMFILE.
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
        if space == 0 {
            if can_block { return -11; } // EAGAIN — caller will block
            return 0; // non-blocking fallback
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
}
