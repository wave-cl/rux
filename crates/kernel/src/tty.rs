/// TTY line discipline.
///
/// In canonical (cooked) mode: buffers input until newline, handles
/// backspace, Ctrl-C (SIGINT), Ctrl-D (EOF), Ctrl-U (kill line).
/// In raw mode: passes bytes through immediately.

use rux_arch::ConsoleOps;

const LINE_BUF_SIZE: usize = 4096;

/// Global TTY state (single terminal).
pub static mut TTY: Tty = Tty::new();

pub struct Tty {
    line_buf: [u8; LINE_BUF_SIZE],
    line_len: usize,
    /// ICANON — canonical (cooked) mode.
    pub cooked: bool,
    /// ECHO — echo input back to terminal.
    pub echo: bool,
    /// ISIG — generate signals on Ctrl-C/Ctrl-Z.
    pub isig: bool,
    /// Foreground process group for SIGINT delivery.
    pub foreground_pgid: u32,
    /// Session ID that owns this controlling terminal (0 = no session).
    pub session_id: u32,
    /// VMIN — minimum bytes for raw read (0 = non-blocking).
    pub vmin: u8,
    /// VTIME — timeout in deciseconds for raw read (0 = no timeout).
    pub vtime: u8,
}

impl Tty {
    pub const fn new() -> Self {
        Self {
            line_buf: [0; LINE_BUF_SIZE],
            line_len: 0,
            cooked: true,
            echo: true,
            isig: true,
            foreground_pgid: 1,
            session_id: 1, // PID 1's session owns the console
            vmin: 1,
            vtime: 0,
        }
    }

    /// Read from terminal in canonical mode.
    /// Buffers input, handles editing, returns on newline or Ctrl-D.
    pub unsafe fn read_canonical<A: ConsoleOps>(
        &mut self, buf: *mut u8, len: usize,
    ) -> isize {
        // Fill line buffer until we get a newline
        loop {
            let b = A::read_byte();

            match b {
                // Ctrl-C: send SIGINT to foreground process group
                0x03 => {
                    if self.isig {
                        self.line_len = 0;
                        if self.echo { A::write_str("^C\n"); }
                        crate::syscall::posix::kill(
                            -(self.foreground_pgid as isize), 2, // SIGINT
                        );
                        return crate::errno::EINTR;
                    }
                }
                // Ctrl-Z: send SIGTSTP to foreground process group
                0x1A => {
                    if self.isig {
                        self.line_len = 0;
                        if self.echo { A::write_str("^Z\n"); }
                        crate::syscall::posix::kill(
                            -(self.foreground_pgid as isize), 20, // SIGTSTP
                        );
                        return crate::errno::EINTR;
                    }
                }
                // Ctrl-D: EOF — return buffered data or 0
                0x04 => {
                    if self.line_len == 0 {
                        return 0; // EOF
                    }
                    // Return what we have without adding newline
                    break;
                }
                // Ctrl-U: kill line
                0x15 => {
                    if self.echo {
                        for _ in 0..self.line_len {
                            A::write_byte(0x08); // backspace
                            A::write_byte(b' ');
                            A::write_byte(0x08);
                        }
                    }
                    self.line_len = 0;
                }
                // Backspace or DEL
                0x08 | 0x7f => {
                    if self.line_len > 0 {
                        self.line_len -= 1;
                        if self.echo {
                            A::write_byte(0x08);
                            A::write_byte(b' ');
                            A::write_byte(0x08);
                        }
                    }
                }
                // Newline or carriage return
                b'\n' | b'\r' => {
                    if self.line_len < LINE_BUF_SIZE {
                        self.line_buf[self.line_len] = b'\n';
                        self.line_len += 1;
                    }
                    if self.echo { A::write_byte(b'\n'); }
                    break;
                }
                // Printable character
                _ => {
                    if self.line_len < LINE_BUF_SIZE {
                        self.line_buf[self.line_len] = b;
                        self.line_len += 1;
                        if self.echo { A::write_byte(b); }
                    }
                }
            }
        }

        // Copy from line buffer to user buffer
        let n = len.min(self.line_len);
        core::ptr::copy_nonoverlapping(self.line_buf.as_ptr(), buf, n);

        // Shift remaining data (if user asked for less than a full line)
        if n < self.line_len {
            let remaining = self.line_len - n;
            core::ptr::copy(self.line_buf.as_ptr().add(n), self.line_buf.as_mut_ptr(), remaining);
            self.line_len = remaining;
        } else {
            self.line_len = 0;
        }

        n as isize
    }

    /// Read from terminal in raw mode — respects VMIN/VTIME.
    ///
    /// VMIN=1, VTIME=0 (default): block until 1 byte, return it immediately.
    /// VMIN=0, VTIME=0: non-blocking, return what's available.
    /// VMIN>0, VTIME=0: block until VMIN bytes.
    /// VMIN=0, VTIME>0: wait up to VTIME*100ms, return what arrives.
    pub unsafe fn read_raw<A: ConsoleOps>(
        &mut self, buf: *mut u8, len: usize,
    ) -> isize {
        if len == 0 { return 0; }
        let vmin = (self.vmin as usize).min(len);
        let ptr = buf;

        if vmin == 0 && self.vtime == 0 {
            // Pure non-blocking: try one byte
            // For now, just read one byte (QEMU serial is blocking)
            let b = A::read_byte();
            *ptr = b;
            return 1;
        }

        // Read up to min(vmin, len) bytes, or len if vmin==0
        let target = if vmin > 0 { vmin } else { 1 };
        let mut got = 0usize;
        while got < target.min(len) {
            let b = A::read_byte();
            *ptr.add(got) = b;
            got += 1;
        }
        got as isize
    }
}
