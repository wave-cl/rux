/// Kernel pipe buffers for inter-process communication.
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

/// Create a new pipe. Returns (pipe_id, read_fd, write_fd) or error.
pub fn create() -> Result<(u8, i64, i64), i64> {
    unsafe {
        // Find a free pipe slot
        let pipe_id = PIPES.iter().position(|p| !p.active)
            .ok_or(-24i64)? as u8; // -EMFILE

        PIPES[pipe_id as usize] = PipeBuf {
            buf: [0; PIPE_BUF_SIZE],
            read_pos: 0, write_pos: 0, count: 0,
            readers: 1, writers: 1, active: true,
        };

        // Allocate two fds: read end and write end
        let read_fd = crate::fdtable::alloc_pipe_fd(pipe_id, false)?;
        let write_fd = match crate::fdtable::alloc_pipe_fd(pipe_id, true) {
            Ok(fd) => fd,
            Err(e) => {
                // Clean up read fd on failure
                crate::fdtable::sys_close(read_fd as usize);
                PIPES[pipe_id as usize].active = false;
                return Err(e);
            }
        };

        Ok((pipe_id, read_fd, write_fd))
    }
}

/// Read from a pipe. Returns bytes read, 0 on EOF (no writers left).
pub fn read(pipe_id: u8, buf: *mut u8, len: usize) -> i64 {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return -9; } // -EBADF

        if p.count == 0 {
            if p.writers == 0 {
                return 0; // EOF — no writers left
            }
            return 0; // Would block, but we don't support blocking pipes yet
        }

        let to_read = len.min(p.count);
        for i in 0..to_read {
            *buf.add(i) = p.buf[p.read_pos];
            p.read_pos = (p.read_pos + 1) % PIPE_BUF_SIZE;
        }
        p.count -= to_read;
        to_read as i64
    }
}

/// Write to a pipe. Returns bytes written, -EPIPE if no readers.
pub fn write(pipe_id: u8, buf: *const u8, len: usize) -> i64 {
    unsafe {
        let p = &mut PIPES[pipe_id as usize];
        if !p.active { return -9; }

        if p.readers == 0 {
            return -32; // -EPIPE
        }

        let space = PIPE_BUF_SIZE - p.count;
        let to_write = len.min(space);
        for i in 0..to_write {
            p.buf[p.write_pos] = *buf.add(i);
            p.write_pos = (p.write_pos + 1) % PIPE_BUF_SIZE;
        }
        p.count += to_write;
        to_write as i64
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
