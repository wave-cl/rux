/// Pipe ring buffers for inter-process communication.
///
/// Each pipe is a fixed-size ring buffer with separate reader/writer counts.
/// When all writers close, reads return 0 (EOF). When all readers close,
/// writes return -EPIPE.

const PIPE_BUF_SIZE: usize = 4096;
const MAX_PIPES: usize = 16;

struct PipeBuf {
    buf: [u8; PIPE_BUF_SIZE],
    read_pos: usize,
    write_pos: usize,
    count: usize,
    readers: u8,
    writers: u8,
    active: bool,
}

static mut PIPES: [PipeBuf; MAX_PIPES] = {
    const EMPTY: PipeBuf = PipeBuf {
        buf: [0; PIPE_BUF_SIZE],
        read_pos: 0, write_pos: 0, count: 0,
        readers: 0, writers: 0, active: false,
    };
    [EMPTY; MAX_PIPES]
};

/// Allocate a pipe slot. Returns pipe_id or -EMFILE.
pub fn alloc() -> Result<u8, isize> {
    unsafe {
        let pipe_id = PIPES.iter().position(|p| !p.active)
            .ok_or(-24isize)? as u8;
        PIPES[pipe_id as usize] = PipeBuf {
            buf: [0; PIPE_BUF_SIZE],
            read_pos: 0, write_pos: 0, count: 0,
            readers: 1, writers: 1, active: true,
        };
        Ok(pipe_id)
    }
}

/// Read from a pipe. Returns bytes read, 0 on EOF (no writers left).
pub fn read(pipe_id: u8, buf: *mut u8, len: usize) -> isize {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return -9; }
        if p.count == 0 {
            return 0; // EOF or would-block
        }
        let to_read = len.min(p.count);
        for i in 0..to_read {
            *buf.add(i) = p.buf[p.read_pos];
            p.read_pos = (p.read_pos + 1) % PIPE_BUF_SIZE;
        }
        p.count -= to_read;
        to_read as isize
    }
}

/// Write to a pipe. Returns bytes written, -EPIPE if no readers.
pub fn write(pipe_id: u8, buf: *const u8, len: usize) -> isize {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return -9; }
        if p.readers == 0 { return -32; }
        let space = PIPE_BUF_SIZE - p.count;
        let to_write = len.min(space);
        for i in 0..to_write {
            p.buf[p.write_pos] = *buf.add(i);
            p.write_pos = (p.write_pos + 1) % PIPE_BUF_SIZE;
        }
        p.count += to_write;
        to_write as isize
    }
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

/// Reset all pipes (called on exec).
pub fn reset() {
    unsafe {
        for p in PIPES.iter_mut() {
            *p = PipeBuf {
                buf: [0; PIPE_BUF_SIZE],
                read_pos: 0, write_pos: 0, count: 0,
                readers: 0, writers: 0, active: false,
            };
        }
    }
}
