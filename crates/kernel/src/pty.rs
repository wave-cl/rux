/// Pseudo-terminal (PTY) support — Linux-compatible master/slave pairs.
///
/// open(/dev/ptmx) → master fd (pty_id allocated)
/// ioctl(master, TIOCGPTN) → get slave number N
/// ioctl(master, TIOCSPTLCK, 0) → unlock slave
/// open(/dev/pts/N) → slave fd
///
/// Master write → slave input queue (slave reads it)
/// Slave write → master output queue (master reads it)
/// Slave side applies termios processing (canonical mode, echo, signals).

const MAX_PTYS: usize = 16;
const PTY_BUF_SIZE: usize = 4096;

pub struct PtyPair {
    pub active: bool,
    pub locked: bool,
    pub master_refs: u8,
    pub slave_refs: u8,
    // Input queue: master writes → slave reads
    input: [u8; PTY_BUF_SIZE],
    input_head: usize,
    input_tail: usize,
    input_count: usize,
    // Output queue: slave writes → master reads
    output: [u8; PTY_BUF_SIZE],
    output_head: usize,
    output_tail: usize,
    output_count: usize,
    // Slave terminal state
    pub termios: crate::tty::Termios,
    pub foreground_pgid: u32,
    pub session_id: u32,
    pub winsize: [u16; 4], // rows, cols, xpixel, ypixel
    pub col: usize, // output column tracking
    // Shared canonical-mode line buffer
    pub line: crate::line_discipline::LineBuffer,
}

impl PtyPair {
    const fn new() -> Self {
        Self {
            active: false, locked: true,
            master_refs: 0, slave_refs: 0,
            input: [0; PTY_BUF_SIZE],
            input_head: 0, input_tail: 0, input_count: 0,
            output: [0; PTY_BUF_SIZE],
            output_head: 0, output_tail: 0, output_count: 0,
            termios: crate::tty::Termios::default_cooked(),
            foreground_pgid: 0, session_id: 0,
            winsize: [24, 80, 0, 0],
            col: 0,
            line: crate::line_discipline::LineBuffer::new(),
        }
    }

    /// Flush input queues (for TCSETSF).
    pub fn flush_input(&mut self) {
        self.line.reset();
        self.input_count = 0;
        self.input_head = 0;
        self.input_tail = 0;
    }
}

static mut PTYS: [PtyPair; MAX_PTYS] = {
    const EMPTY: PtyPair = PtyPair::new();
    [EMPTY; MAX_PTYS]
};

// ── Ring buffer helpers ────────────────────────────────────────────

fn ring_write(buf: &mut [u8; PTY_BUF_SIZE], head: &mut usize, count: &mut usize, data: &[u8]) -> usize {
    let space = PTY_BUF_SIZE - *count;
    let n = data.len().min(space);
    for i in 0..n {
        buf[*head] = data[i];
        *head = (*head + 1) % PTY_BUF_SIZE;
    }
    *count += n;
    n
}

fn ring_read(buf: &[u8; PTY_BUF_SIZE], tail: &mut usize, count: &mut usize, dst: &mut [u8]) -> usize {
    let n = dst.len().min(*count);
    for i in 0..n {
        dst[i] = buf[*tail];
        *tail = (*tail + 1) % PTY_BUF_SIZE;
    }
    *count -= n;
    n
}

#[allow(dead_code)]
fn ring_has_data(count: usize) -> bool { count > 0 }

// ── Public API ─────────────────────────────────────────────────────

/// Allocate a new PTY pair. Returns pty_id or None if full.
pub unsafe fn alloc() -> Option<u8> {
    for i in 0..MAX_PTYS {
        if !PTYS[i].active {
            PTYS[i] = PtyPair::new();
            PTYS[i].active = true;
            PTYS[i].locked = true;
            PTYS[i].master_refs = 1;
            return Some(i as u8);
        }
    }
    None
}

/// Check if a PTY slot is active and unlocked (for slave open).
pub unsafe fn is_slave_available(id: u8) -> bool {
    let i = id as usize;
    i < MAX_PTYS && PTYS[i].active && !PTYS[i].locked
}

/// Open the slave side (increment refs).
pub unsafe fn open_slave(id: u8) {
    let i = id as usize;
    if i < MAX_PTYS { PTYS[i].slave_refs = PTYS[i].slave_refs.saturating_add(1); }
}

/// Increment master refs (for dup/fork).
pub unsafe fn dup_master(id: u8) {
    let i = id as usize;
    if i < MAX_PTYS { PTYS[i].master_refs = PTYS[i].master_refs.saturating_add(1); }
}

/// Increment slave refs (for dup/fork).
pub unsafe fn dup_slave(id: u8) {
    let i = id as usize;
    if i < MAX_PTYS { PTYS[i].slave_refs = PTYS[i].slave_refs.saturating_add(1); }
}

/// Close master side. When last master closes, slave reads get EIO.
pub unsafe fn close_master(id: u8) {
    let i = id as usize;
    if i >= MAX_PTYS { return; }
    PTYS[i].master_refs = PTYS[i].master_refs.saturating_sub(1);
    if PTYS[i].master_refs == 0 && PTYS[i].slave_refs == 0 {
        PTYS[i].active = false;
    }
}

/// Close slave side. When last slave closes, master reads get 0 (EOF).
pub unsafe fn close_slave(id: u8) {
    let i = id as usize;
    if i >= MAX_PTYS { return; }
    PTYS[i].slave_refs = PTYS[i].slave_refs.saturating_sub(1);
    if PTYS[i].master_refs == 0 && PTYS[i].slave_refs == 0 {
        PTYS[i].active = false;
    }
}

/// Set/clear the slave lock (TIOCSPTLCK).
pub unsafe fn set_lock(id: u8, locked: bool) {
    let i = id as usize;
    if i < MAX_PTYS { PTYS[i].locked = locked; }
}

/// Master write: put bytes into the slave's input queue (raw, no processing).
pub unsafe fn master_write(id: u8, data: &[u8]) -> isize {
    let i = id as usize;
    if i >= MAX_PTYS || !PTYS[i].active { return crate::errno::EIO; }
    if PTYS[i].slave_refs == 0 { return crate::errno::EIO; }
    let p = &mut PTYS[i];

    if p.termios.echo_enabled() {
        // Echo: also write to output queue so master sees what was typed
        ring_write(&mut p.output, &mut p.output_head, &mut p.output_count, data);
    }

    if p.termios.is_canonical() {
        // Canonical mode: use shared line discipline
        use crate::line_discipline::LineEvent;
        for &raw in data {
            let (event, _echo) = p.line.process(raw, &p.termios);
            // PTY echo is handled separately (already written to output above)
            match event {
                LineEvent::Signal(signum) => {
                    if p.foreground_pgid > 0 {
                        crate::syscall::posix::kill(-(p.foreground_pgid as isize), signum as usize);
                    }
                }
                LineEvent::Complete => {
                    // Line complete — deliver buffered content to slave input
                    let content = &p.line.buf[..p.line.len];
                    ring_write(&mut p.input, &mut p.input_head, &mut p.input_count, content);
                    p.line.len = 0;
                }
                LineEvent::EofFlush => {
                    let content = &p.line.buf[..p.line.len];
                    ring_write(&mut p.input, &mut p.input_head, &mut p.input_count, content);
                    p.line.len = 0;
                }
                LineEvent::Eof => {
                    // Empty EOF marker
                    ring_write(&mut p.input, &mut p.input_head, &mut p.input_count, b"\x04");
                }
                LineEvent::Continue => {}
            }
        }
        data.len() as isize
    } else {
        // Raw mode: write directly to input queue
        ring_write(&mut p.input, &mut p.input_head, &mut p.input_count, data) as isize
    }
}

/// Master read: get bytes from the slave's output queue.
pub unsafe fn master_read(id: u8, dst: &mut [u8]) -> isize {
    let i = id as usize;
    if i >= MAX_PTYS || !PTYS[i].active { return crate::errno::EIO; }
    let p = &mut PTYS[i];
    if p.output_count == 0 {
        if p.slave_refs == 0 { return 0; } // EOF
        return crate::errno::EAGAIN;
    }
    ring_read(&p.output, &mut p.output_tail, &mut p.output_count, dst) as isize
}

/// Slave write: put bytes into the master's output queue (with output processing).
pub unsafe fn slave_write(id: u8, data: &[u8]) -> isize {
    let i = id as usize;
    if i >= MAX_PTYS || !PTYS[i].active { return crate::errno::EIO; }
    if PTYS[i].master_refs == 0 { return crate::errno::EIO; }
    let p = &mut PTYS[i];
    // Apply output processing (c_oflag)
    for &b in data {
        let (b1, b2) = p.termios.output_process(b, &mut p.col);
        ring_write(&mut p.output, &mut p.output_head, &mut p.output_count, &[b1]);
        if let Some(b2) = b2 {
            ring_write(&mut p.output, &mut p.output_head, &mut p.output_count, &[b2]);
        }
    }
    data.len() as isize
}

/// Slave read: get bytes from the master's input queue.
pub unsafe fn slave_read(id: u8, dst: &mut [u8]) -> isize {
    let i = id as usize;
    if i >= MAX_PTYS || !PTYS[i].active { return crate::errno::EIO; }
    let p = &mut PTYS[i];
    if p.input_count == 0 {
        if p.master_refs == 0 { return crate::errno::EIO; }
        return crate::errno::EAGAIN;
    }
    let n = ring_read(&p.input, &mut p.input_tail, &mut p.input_count, dst);
    // Check for Ctrl-D EOF marker
    if n == 1 && dst[0] == 0x04 { return 0; }
    n as isize
}

/// Check if master has data to read.
#[allow(dead_code)]
pub unsafe fn master_has_data(id: u8) -> bool {
    let i = id as usize;
    i < MAX_PTYS && PTYS[i].active && ring_has_data(PTYS[i].output_count)
}

/// Check if slave has data to read.
#[allow(dead_code)]
pub unsafe fn slave_has_data(id: u8) -> bool {
    let i = id as usize;
    i < MAX_PTYS && PTYS[i].active && ring_has_data(PTYS[i].input_count)
}

/// Get mutable reference to PTY pair (for ioctl).
pub unsafe fn get_mut(id: u8) -> Option<&'static mut PtyPair> {
    let i = id as usize;
    if i < MAX_PTYS && PTYS[i].active { Some(&mut PTYS[i]) } else { None }
}
