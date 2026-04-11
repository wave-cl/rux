/// Shared canonical-mode line discipline for TTY and PTY.
///
/// Extracts the duplicated line editing logic (signal chars, erase, kill,
/// word-erase, literal-next, reprint, EOF, newline) from tty.rs and pty.rs
/// into a single implementation.

use crate::tty::{Termios, VINTR, VQUIT, VSUSP, VEOF, VLNEXT, VWERASE, VREPRINT, VKILL, VERASE, ECHONL};

/// Result of processing one canonical-mode input byte.
pub enum LineEvent {
    /// Signal character detected: send signal `signum` to foreground pgid.
    /// Line buffer is cleared.
    Signal(u8),
    /// Line is complete (newline or CR). Buffer includes trailing '\n'.
    Complete,
    /// EOF on empty line (Ctrl-D with no buffered data).
    Eof,
    /// EOF with data: deliver buffered content without trailing newline.
    EofFlush,
    /// Character buffered or editing performed; keep reading.
    Continue,
}

/// Echo action requested by the line discipline.
pub enum Echo {
    None,
    Byte(u8),
    Erase,           // backspace-space-backspace
    EraseN(usize),   // N times erase
    Ctrl(u8),        // ^X for control char
    Str(&'static [u8]), // static string (e.g., "^C\n")
    Reprint,         // reprint entire line buffer
}

pub struct LineBuffer {
    pub buf: [u8; 4096],
    pub len: usize,
    pub literal_next: bool,
}

impl LineBuffer {
    pub const fn new() -> Self {
        Self { buf: [0; 4096], len: 0, literal_next: false }
    }

    /// Process one input byte in canonical mode.
    /// Returns a `LineEvent` indicating what happened, plus an `Echo` action.
    /// The caller is responsible for performing the echo (writing to serial or ring buffer)
    /// and for delivering signals.
    pub fn process(&mut self, raw: u8, termios: &Termios) -> (LineEvent, Echo) {
        // VLNEXT: literal next character
        if self.literal_next {
            self.literal_next = false;
            if self.len < self.buf.len() {
                self.buf[self.len] = raw;
                self.len += 1;
                let echo = if termios.echo_enabled() {
                    if raw < 0x20 { Echo::Ctrl(raw) } else { Echo::Byte(raw) }
                } else { Echo::None };
                return (LineEvent::Continue, echo);
            }
            return (LineEvent::Continue, Echo::None);
        }

        // Apply input processing (c_iflag: ISTRIP, IGNCR, ICRNL, INLCR)
        let b = match termios.input_process(raw) {
            Some(b) => b,
            None => return (LineEvent::Continue, Echo::None), // IGNCR
        };

        // Signal characters (ISIG)
        if termios.isig_enabled() {
            if b == termios.cc(VINTR) {
                self.len = 0;
                let echo = if termios.echo_enabled() { Echo::Str(b"^C\n") } else { Echo::None };
                return (LineEvent::Signal(2), echo); // SIGINT
            }
            if b == termios.cc(VQUIT) {
                self.len = 0;
                let echo = if termios.echo_enabled() { Echo::Str(b"^\\\n") } else { Echo::None };
                return (LineEvent::Signal(3), echo); // SIGQUIT
            }
            if b == termios.cc(VSUSP) {
                self.len = 0;
                let echo = if termios.echo_enabled() { Echo::Str(b"^Z\n") } else { Echo::None };
                return (LineEvent::Signal(20), echo); // SIGTSTP
            }
        }

        // EOF (Ctrl-D)
        if b == termios.cc(VEOF) {
            if self.len == 0 {
                return (LineEvent::Eof, Echo::None);
            }
            return (LineEvent::EofFlush, Echo::None);
        }

        // VLNEXT (Ctrl-V): literal next
        if termios.iexten_enabled() && b == termios.cc(VLNEXT) {
            self.literal_next = true;
            let echo = if termios.echo_enabled() { Echo::Str(b"^V") } else { Echo::None };
            return (LineEvent::Continue, echo);
        }

        // VWERASE (Ctrl-W): erase word
        if termios.iexten_enabled() && b == termios.cc(VWERASE) {
            let mut erased = 0usize;
            // Erase trailing spaces
            while self.len > 0 && self.buf[self.len - 1] == b' ' {
                self.len -= 1;
                erased += 1;
            }
            // Erase word
            while self.len > 0 && self.buf[self.len - 1] != b' ' {
                self.len -= 1;
                erased += 1;
            }
            let echo = if termios.echo_enabled() { Echo::EraseN(erased) } else { Echo::None };
            return (LineEvent::Continue, echo);
        }

        // VREPRINT (Ctrl-R): reprint line
        if termios.iexten_enabled() && b == termios.cc(VREPRINT) {
            let echo = if termios.echo_enabled() { Echo::Reprint } else { Echo::None };
            return (LineEvent::Continue, echo);
        }

        // VKILL (Ctrl-U): kill line
        if b == termios.cc(VKILL) {
            let erased = self.len;
            self.len = 0;
            let echo = if termios.echo_enabled() { Echo::EraseN(erased) } else { Echo::None };
            return (LineEvent::Continue, echo);
        }

        // VERASE (Backspace/DEL)
        if b == termios.cc(VERASE) || b == 0x08 {
            if self.len > 0 {
                self.len -= 1;
                let echo = if termios.echo_enabled() { Echo::Erase } else { Echo::None };
                return (LineEvent::Continue, echo);
            }
            return (LineEvent::Continue, Echo::None);
        }

        // Newline or carriage return → complete line
        if b == b'\n' || b == b'\r' {
            if self.len < self.buf.len() {
                self.buf[self.len] = b'\n';
                self.len += 1;
            }
            let echo = if termios.echo_enabled() || (termios.c_lflag & ECHONL != 0) {
                Echo::Byte(b'\n')
            } else { Echo::None };
            return (LineEvent::Complete, echo);
        }

        // Regular character
        if self.len < self.buf.len() {
            self.buf[self.len] = b;
            self.len += 1;
            let echo = if termios.echo_enabled() {
                if b < 0x20 && termios.echoctl_enabled() {
                    Echo::Ctrl(b)
                } else {
                    Echo::Byte(b)
                }
            } else { Echo::None };
            return (LineEvent::Continue, echo);
        }

        (LineEvent::Continue, Echo::None)
    }

    /// Get the buffered line content.
    pub fn content(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Reset the buffer.
    pub fn reset(&mut self) {
        self.len = 0;
        self.literal_next = false;
    }
}
