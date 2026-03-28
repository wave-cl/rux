use crate::id::{Pid, Uid};

/// All 31 standard POSIX signals. Real-time signals (32-64) are
/// represented numerically via `SignalSet` bitmask operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Signal {
    Hup     = 1,
    Int     = 2,
    Quit    = 3,
    Ill     = 4,
    Trap    = 5,
    Abrt    = 6,
    Bus     = 7,
    Fpe     = 8,
    Kill    = 9,
    Usr1    = 10,
    Segv    = 11,
    Usr2    = 12,
    Pipe    = 13,
    Alrm    = 14,
    Term    = 15,
    StkFlt  = 16,
    Chld    = 17,
    Cont    = 18,
    Stop    = 19,
    Tstp    = 20,
    Ttin    = 21,
    Ttou    = 22,
    Urg     = 23,
    Xcpu    = 24,
    Xfsz    = 25,
    Vtalrm  = 26,
    Prof    = 27,
    Winch   = 28,
    Io      = 29,
    Pwr     = 30,
    Sys     = 31,
}

/// POSIX default signal disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignalDefault {
    Terminate = 0,
    Ignore    = 1,
    Stop      = 2,
    CoreDump  = 3,
    Continue  = 4,
}

impl Signal {
    /// POSIX-mandated default action for each signal.
    #[inline(always)]
    pub const fn default_action(self) -> SignalDefault {
        match self {
            // Terminate
            Signal::Hup | Signal::Int | Signal::Pipe | Signal::Alrm |
            Signal::Term | Signal::Usr1 | Signal::Usr2 | Signal::StkFlt |
            Signal::Io | Signal::Pwr | Signal::Xcpu | Signal::Xfsz |
            Signal::Vtalrm | Signal::Prof => SignalDefault::Terminate,
            // Core dump
            Signal::Quit | Signal::Ill | Signal::Trap | Signal::Abrt |
            Signal::Bus | Signal::Fpe | Signal::Segv | Signal::Sys => SignalDefault::CoreDump,
            // Stop
            Signal::Stop | Signal::Tstp | Signal::Ttin | Signal::Ttou => SignalDefault::Stop,
            // Ignore
            Signal::Chld | Signal::Urg | Signal::Winch => SignalDefault::Ignore,
            // Continue
            Signal::Cont => SignalDefault::Continue,
            // Kill cannot be caught/ignored — default is terminate
            Signal::Kill => SignalDefault::Terminate,
        }
    }

    /// Convert signal number to bit position (signal N → bit N-1).
    #[inline(always)]
    pub const fn to_bit(self) -> u64 {
        1u64 << (self as u8 - 1)
    }

    /// Try to construct from raw signal number (1-31).
    #[inline(always)]
    pub const fn from_raw(num: u8) -> Option<Self> {
        if num >= 1 && num <= 31 {
            // SAFETY: Signal is repr(u8) with values 1-31, all contiguous.
            Some(unsafe { core::mem::transmute(num) })
        } else {
            None
        }
    }
}

// ── Signal set ──────────────────────────────────────────────────────────

/// Bitmask for signals 1-64. Signal N is bit (N-1).
/// Covers standard signals (1-31) and real-time signals (32-64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SignalSet(pub u64);

impl SignalSet {
    pub const EMPTY: Self = Self(0);
    pub const FULL: Self = Self(u64::MAX);

    #[inline(always)]
    pub const fn empty() -> Self { Self(0) }

    #[inline(always)]
    pub const fn full() -> Self { Self(u64::MAX) }

    /// Add signal number `sig` (1-64) to the set.
    #[inline(always)]
    pub const fn add(self, sig: u8) -> Self {
        Self(self.0 | (1u64 << (sig - 1)))
    }

    /// Remove signal number `sig` (1-64) from the set.
    #[inline(always)]
    pub const fn remove(self, sig: u8) -> Self {
        Self(self.0 & !(1u64 << (sig - 1)))
    }

    /// Check if signal number `sig` (1-64) is in the set.
    #[inline(always)]
    pub const fn contains(self, sig: u8) -> bool {
        (self.0 >> (sig - 1)) & 1 != 0
    }

    #[inline(always)]
    pub const fn and(self, other: Self) -> Self { Self(self.0 & other.0) }

    #[inline(always)]
    pub const fn or(self, other: Self) -> Self { Self(self.0 | other.0) }

    #[inline(always)]
    pub const fn not(self) -> Self { Self(!self.0) }

    #[inline(always)]
    pub const fn is_empty(self) -> bool { self.0 == 0 }

    /// Lowest pending signal number (1-64), or None if empty.
    /// Maps to TZCNT/CTZ instruction.
    #[inline(always)]
    pub const fn lowest(self) -> Option<u8> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as u8 + 1)
        }
    }
}

// ── Signal action ───────────────────────────────────────────────────────

/// Handler disposition for a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignalHandler {
    /// Use POSIX default action (terminate, core dump, stop, ignore, continue).
    Default = 0,
    /// Explicitly ignore the signal.
    Ignore = 1,
    /// Invoke user-space handler function.
    User = 2,
}

/// sigaction flags (SA_*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SaFlags {
    Restart    = 1 << 0,
    NoCldStop  = 1 << 1,
    NoCldWait  = 1 << 2,
    SigInfo    = 1 << 3,
    OnStack    = 1 << 4,
    NoDeFer    = 1 << 5,
    ResetHand  = 1 << 6,
}

/// Per-signal handler configuration (analogous to `struct sigaction`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SignalAction {
    /// Handler type (default, ignore, or user function).
    pub handler_type: SignalHandler,
    pub _pad0: [u8; 7],
    /// User-space handler address. Only valid when `handler_type == User`.
    pub handler: usize,
    /// Signals blocked during handler execution.
    pub mask: SignalSet,
    /// SA_* flags OR'd together.
    pub flags: u32,
    pub _pad1: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<SignalAction>() == 32);

impl SignalAction {
    /// Default signal action: use POSIX default disposition.
    pub const DEFAULT: Self = Self {
        handler_type: SignalHandler::Default,
        _pad0: [0; 7],
        handler: 0,
        mask: SignalSet::EMPTY,
        flags: 0,
        _pad1: [0; 4],
    };

    /// Ignore action.
    pub const IGNORE: Self = Self {
        handler_type: SignalHandler::Ignore,
        _pad0: [0; 7],
        handler: 0,
        mask: SignalSet::EMPTY,
        flags: 0,
        _pad1: [0; 4],
    };
}

// ── Signal info ─────────────────────────────────────────────────────────

/// Why a signal was generated (si_code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigCode {
    /// Sent by kill(), raise(), or abort().
    User       = 0,
    /// Sent by the kernel.
    Kernel     = 1,
    /// Sent by sigqueue().
    Queue      = 2,
    /// Generated by timer expiration.
    Timer      = 3,
    /// Generated by async I/O completion.
    AsyncIo    = 4,
    /// Sent by tkill/tgkill.
    TkIll      = 5,
    /// Page fault: mapping error (address not mapped).
    FaultMapErr = 6,
    /// Page fault: permission error (protection violation).
    FaultAccErr = 7,
}

/// Information about a delivered signal (analogous to `siginfo_t`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SigInfo {
    /// Signal number (1-64).
    pub signo: u8,
    /// Why the signal was generated.
    pub code: SigCode,
    pub _pad0: [u8; 2],
    /// Sending process ID (for SI_USER, SI_QUEUE).
    pub pid: Pid,
    /// Real user ID of sending process.
    pub uid: Uid,
    pub _pad1: [u8; 4],
    /// Fault address (SIGSEGV, SIGBUS) or timer ID.
    pub addr: usize,
    /// Child exit status (SIGCHLD) or signal value (sigqueue).
    pub status: i32,
    pub _pad2: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<SigInfo>() == 32);

impl SigInfo {
    pub const EMPTY: Self = Self {
        signo: 0,
        code: SigCode::Kernel,
        _pad0: [0; 2],
        pid: Pid(0),
        uid: Uid(0),
        _pad1: [0; 4],
        addr: 0,
        status: 0,
        _pad2: [0; 4],
    };
}

// ── Signal queue (RT signals) ───────────────────────────────────────────

/// Maximum queued RT signals per task.
pub const MAX_PENDING_SIGNALS: usize = 64;

/// Fixed-capacity ring buffer for queued real-time signals.
/// POSIX requires RT signals (32-64) to be queued and delivered in order.
/// Standard signals (1-31) are coalesced into the `pending` bitmask.
#[repr(C)]
pub struct SigQueue {
    pub entries: [SigInfo; MAX_PENDING_SIGNALS],
    pub head: u16,
    pub tail: u16,
    pub count: u16,
    pub _pad: [u8; 2],
}

const _: () = assert!(core::mem::size_of::<SigQueue>() == 2056);

impl SigQueue {
    /// Empty signal queue.
    pub const fn new() -> Self {
        Self {
            entries: [SigInfo::EMPTY; MAX_PENDING_SIGNALS],
            head: 0,
            tail: 0,
            count: 0,
            _pad: [0; 2],
        }
    }

    /// Enqueue a signal. Returns false if the queue is full.
    #[inline]
    pub fn enqueue(&mut self, info: SigInfo) -> bool {
        if self.count as usize >= MAX_PENDING_SIGNALS {
            return false;
        }
        self.entries[self.tail as usize] = info;
        self.tail = ((self.tail as usize + 1) % MAX_PENDING_SIGNALS) as u16;
        self.count += 1;
        true
    }

    /// Dequeue the oldest signal. Returns None if empty.
    #[inline]
    pub fn dequeue(&mut self) -> Option<SigInfo> {
        if self.count == 0 {
            return None;
        }
        let info = self.entries[self.head as usize];
        self.head = ((self.head as usize + 1) % MAX_PENDING_SIGNALS) as u16;
        self.count -= 1;
        Some(info)
    }

    /// Peek at the head without removing.
    #[inline]
    pub fn peek(&self) -> Option<&SigInfo> {
        if self.count == 0 {
            None
        } else {
            Some(&self.entries[self.head as usize])
        }
    }

    #[inline(always)]
    pub const fn is_full(&self) -> bool { self.count as usize >= MAX_PENDING_SIGNALS }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool { self.count == 0 }

    /// Reset the queue to empty.
    #[inline]
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

// ── Alternate signal stack flags ────────────────────────────────────────

/// sigaltstack SS_* flags.
pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;

// ── Per-task signal state ───────────────────────────────────────────────

/// Hot signal fields — checked on every syscall return.
/// Placed inline in the Task hot region (near SchedEntity).
#[repr(C)]
pub struct SignalHot {
    /// Standard signals pending delivery (bitmask, signals 1-64).
    pub pending: SignalSet,
    /// Currently blocked signals (sigprocmask).
    pub blocked: SignalSet,
}

const _: () = assert!(core::mem::size_of::<SignalHot>() == 16);

impl SignalHot {
    pub const fn new() -> Self {
        Self {
            pending: SignalSet::EMPTY,
            blocked: SignalSet::EMPTY,
        }
    }

    /// Check if there are deliverable signals (pending & !blocked != 0).
    /// Called on every syscall return — must be as fast as possible.
    #[inline(always)]
    pub fn has_deliverable(&self) -> bool {
        self.pending.and(self.blocked.not()).0 != 0
    }

    /// Get the next deliverable signal number (lowest pending & !blocked).
    /// Returns signal number 1-64, or None.
    #[inline(always)]
    pub fn next_deliverable(&self) -> Option<u8> {
        self.pending.and(self.blocked.not()).lowest()
    }
}

/// Cold signal fields — accessed only during signal delivery, sigaction,
/// sigaltstack, and sigsuspend. Placed after all hot/warm fields in Task.
#[repr(C)]
pub struct SignalCold {
    /// Saved mask for sigsuspend/pselect restore.
    pub saved_mask: SignalSet,
    /// Per-signal handler configuration (indices 0-31; index 0 unused).
    pub actions: [SignalAction; 32],
    /// Queued real-time signals.
    pub rt_queue: SigQueue,
    /// Alternate signal stack base address (sigaltstack).
    pub alt_stack_base: usize,
    /// Alternate signal stack size.
    pub alt_stack_size: usize,
    /// Alternate signal stack flags (SS_ONSTACK, SS_DISABLE).
    pub alt_stack_flags: u32,
    pub _pad: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<SignalCold>() == 3112);

impl SignalCold {
    pub const fn new() -> Self {
        Self {
            saved_mask: SignalSet::EMPTY,
            actions: [SignalAction::DEFAULT; 32],
            rt_queue: SigQueue::new(),
            alt_stack_base: 0,
            alt_stack_size: 0,
            alt_stack_flags: SS_DISABLE,
            _pad: [0; 4],
        }
    }

    /// Send a standard signal (1-31). Coalesces into pending bitmask.
    pub fn send_standard(&mut self, hot: &mut SignalHot, sig: Signal, _info: &SigInfo) -> Result<(), crate::error::ProcError> {
        hot.pending = hot.pending.add(sig as u8);
        Ok(())
    }

    /// Send an RT signal (32-64). Queued in rt_queue.
    pub fn send_rt(&mut self, hot: &mut SignalHot, signo: u8, info: SigInfo) -> Result<(), crate::error::ProcError> {
        if signo < 32 || signo > 64 {
            return Err(crate::error::ProcError::InvalidSignal);
        }
        if !self.rt_queue.enqueue(info) {
            return Err(crate::error::ProcError::ResourceLimit);
        }
        hot.pending = hot.pending.add(signo);
        Ok(())
    }

    /// Dequeue the next deliverable signal, returning its action and info.
    pub fn dequeue_signal(&mut self, hot: &mut SignalHot) -> Option<(Signal, SignalAction, SigInfo)> {
        let signo = hot.next_deliverable()?;

        // Standard signal (1-31)
        if signo <= 31 {
            let sig = Signal::from_raw(signo)?;
            let action = self.actions[signo as usize];
            let info = SigInfo {
                signo,
                code: SigCode::Kernel,
                _pad0: [0; 2],
                pid: Pid(0),
                uid: Uid(0),
                _pad1: [0; 4],
                addr: 0,
                status: 0,
                _pad2: [0; 4],
            };
            hot.pending = hot.pending.remove(signo);
            return Some((sig, action, info));
        }

        // RT signal (32-64) — dequeue from ring buffer
        if let Some(info) = self.rt_queue.dequeue() {
            hot.pending = hot.pending.remove(signo);
            // RT signals use default action (Terminate)
            let action = SignalAction::DEFAULT;
            // Synthesize a Signal — RT signals don't have named variants,
            // but we return the closest match or the caller handles by signo.
            // For now, return Hup as placeholder; caller uses info.signo.
            return Some((Signal::Hup, action, info));
        }

        // Pending bit set but nothing in queue — clear stale bit
        hot.pending = hot.pending.remove(signo);
        None
    }

    /// Set the handler for a signal (sigaction). Returns the old action.
    /// SIGKILL (9) and SIGSTOP (19) cannot be caught or ignored.
    pub fn set_action(&mut self, sig: Signal, action: SignalAction) -> Result<SignalAction, crate::error::ProcError> {
        match sig {
            Signal::Kill | Signal::Stop => return Err(crate::error::ProcError::InvalidSignal),
            _ => {}
        }
        let idx = sig as u8 as usize;
        let old = self.actions[idx];
        self.actions[idx] = action;
        Ok(old)
    }

    /// Get the handler for a signal.
    #[inline(always)]
    pub fn get_action(&self, sig: Signal) -> &SignalAction {
        &self.actions[sig as u8 as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Pid, Uid};
    extern crate alloc;
    use alloc::boxed::Box;

    fn make_siginfo(signo: u8) -> SigInfo {
        SigInfo {
            signo,
            code: SigCode::User,
            _pad0: [0; 2],
            pid: Pid(1),
            uid: Uid(0),
            _pad1: [0; 4],
            addr: 0,
            status: 0,
            _pad2: [0; 4],
        }
    }

    // ── SigQueue tests ──────────────────────────────────────────────────

    #[test]
    fn sigqueue_enqueue_dequeue_fifo() {
        let mut q = Box::new(SigQueue::new());
        let info1 = make_siginfo(32);
        let info2 = make_siginfo(33);
        let info3 = make_siginfo(34);
        assert!(q.enqueue(info1), "enqueue 1 should succeed");
        assert!(q.enqueue(info2), "enqueue 2 should succeed");
        assert!(q.enqueue(info3), "enqueue 3 should succeed");
        assert_eq!(q.count, 3, "count should be 3");
        let d1 = q.dequeue().expect("dequeue 1");
        assert_eq!(d1.signo, 32, "FIFO: first dequeue should be signo 32");
        let d2 = q.dequeue().expect("dequeue 2");
        assert_eq!(d2.signo, 33, "FIFO: second dequeue should be signo 33");
        let d3 = q.dequeue().expect("dequeue 3");
        assert_eq!(d3.signo, 34, "FIFO: third dequeue should be signo 34");
    }

    #[test]
    fn sigqueue_enqueue_full_returns_false() {
        let mut q = Box::new(SigQueue::new());
        for i in 0..MAX_PENDING_SIGNALS {
            assert!(q.enqueue(make_siginfo((i % 33 + 32) as u8)), "enqueue {} should succeed", i);
        }
        assert!(q.is_full(), "queue should be full");
        assert!(!q.enqueue(make_siginfo(40)), "enqueue on full queue should return false");
    }

    #[test]
    fn sigqueue_dequeue_empty_returns_none() {
        let mut q = Box::new(SigQueue::new());
        assert!(q.dequeue().is_none(), "dequeue on empty queue should return None");
    }

    #[test]
    fn sigqueue_peek_doesnt_remove() {
        let mut q = Box::new(SigQueue::new());
        q.enqueue(make_siginfo(32));
        let peeked = q.peek().expect("peek should return something");
        assert_eq!(peeked.signo, 32, "peek should show head element");
        assert_eq!(q.count, 1, "peek should not change count");
        let peeked2 = q.peek().expect("second peek should still work");
        assert_eq!(peeked2.signo, 32, "peek should be idempotent");
    }

    #[test]
    fn sigqueue_clear_resets() {
        let mut q = Box::new(SigQueue::new());
        q.enqueue(make_siginfo(32));
        q.enqueue(make_siginfo(33));
        q.clear();
        assert!(q.is_empty(), "clear should make queue empty");
        assert_eq!(q.count, 0, "count should be 0 after clear");
        assert_eq!(q.head, 0, "head should be 0 after clear");
        assert_eq!(q.tail, 0, "tail should be 0 after clear");
    }

    #[test]
    fn sigqueue_wraparound() {
        let mut q = Box::new(SigQueue::new());
        // Fill and drain half the queue to advance head/tail
        for i in 0..MAX_PENDING_SIGNALS / 2 {
            q.enqueue(make_siginfo((i % 33 + 32) as u8));
        }
        for _ in 0..MAX_PENDING_SIGNALS / 2 {
            q.dequeue().expect("should dequeue");
        }
        assert!(q.is_empty(), "queue should be empty after draining");
        // Now fill completely — this should wrap around
        for i in 0..MAX_PENDING_SIGNALS {
            assert!(q.enqueue(make_siginfo(((i % 33) + 32) as u8)), "wraparound enqueue {} should succeed", i);
        }
        assert!(q.is_full(), "queue should be full after wraparound fill");
        // Drain and verify count
        for _ in 0..MAX_PENDING_SIGNALS {
            q.dequeue().expect("wraparound dequeue should succeed");
        }
        assert!(q.is_empty(), "queue should be empty after full drain");
    }

    // ── SignalHot tests ─────────────────────────────────────────────────

    #[test]
    fn signalhot_has_deliverable() {
        let mut hot = SignalHot::new();
        assert!(!hot.has_deliverable(), "no pending = no deliverable");
        hot.pending = hot.pending.add(Signal::Int as u8);
        assert!(hot.has_deliverable(), "pending INT should be deliverable");
        // Block INT
        hot.blocked = hot.blocked.add(Signal::Int as u8);
        assert!(!hot.has_deliverable(), "blocked pending should not be deliverable");
        // Add unblocked signal
        hot.pending = hot.pending.add(Signal::Term as u8);
        assert!(hot.has_deliverable(), "unblocked TERM should be deliverable");
    }

    #[test]
    fn signalhot_next_deliverable() {
        let mut hot = SignalHot::new();
        assert!(hot.next_deliverable().is_none(), "no pending = None");
        hot.pending = hot.pending.add(Signal::Term as u8);
        hot.pending = hot.pending.add(Signal::Int as u8);
        // Both pending, INT (2) < TERM (15), so INT should be next
        assert_eq!(hot.next_deliverable(), Some(Signal::Int as u8), "lowest signal number should be delivered first");
        // Block INT
        hot.blocked = hot.blocked.add(Signal::Int as u8);
        assert_eq!(hot.next_deliverable(), Some(Signal::Term as u8), "after blocking INT, TERM should be next");
    }

    // ── SignalCold tests ────────────────────────────────────────────────

    #[test]
    fn signalcold_send_standard() {
        let mut cold = Box::new(SignalCold::new());
        let mut hot = SignalHot::new();
        let info = make_siginfo(Signal::Int as u8);
        cold.send_standard(&mut hot, Signal::Int, &info).expect("send_standard should succeed");
        assert!(hot.pending.contains(Signal::Int as u8), "INT should be in pending set");
    }

    #[test]
    fn signalcold_send_rt() {
        let mut cold = Box::new(SignalCold::new());
        let mut hot = SignalHot::new();
        let info = make_siginfo(34);
        cold.send_rt(&mut hot, 34, info).expect("send_rt with signo 34 should succeed");
        assert!(hot.pending.contains(34), "RT signal 34 should be in pending set");
        assert_eq!(cold.rt_queue.count, 1, "RT queue should have 1 entry");
    }

    #[test]
    fn signalcold_send_rt_invalid_signo() {
        let mut cold = Box::new(SignalCold::new());
        let mut hot = SignalHot::new();
        let err = cold.send_rt(&mut hot, 10, make_siginfo(10)).unwrap_err();
        assert_eq!(err, crate::error::ProcError::InvalidSignal, "RT signo < 32 should fail");
        let err = cold.send_rt(&mut hot, 65, make_siginfo(65)).unwrap_err();
        assert_eq!(err, crate::error::ProcError::InvalidSignal, "RT signo > 64 should fail");
    }

    #[test]
    fn signalcold_dequeue_signal() {
        let mut cold = Box::new(SignalCold::new());
        let mut hot = SignalHot::new();
        let info = make_siginfo(Signal::Term as u8);
        cold.send_standard(&mut hot, Signal::Term, &info).unwrap();
        let (sig, action, dequeued_info) = cold.dequeue_signal(&mut hot).expect("should dequeue TERM");
        assert_eq!(sig, Signal::Term, "dequeued signal should be TERM");
        assert_eq!(action.handler_type, SignalHandler::Default, "default action for unconfigured signal");
        assert_eq!(dequeued_info.signo, Signal::Term as u8, "info signo should match");
        assert!(!hot.pending.contains(Signal::Term as u8), "TERM should be cleared from pending");
    }

    #[test]
    fn signalcold_set_action_returns_old() {
        let mut cold = Box::new(SignalCold::new());
        let custom = SignalAction {
            handler_type: SignalHandler::User,
            _pad0: [0; 7],
            handler: 0xDEAD,
            mask: SignalSet::EMPTY,
            flags: 0,
            _pad1: [0; 4],
        };
        let old = cold.set_action(Signal::Int, custom).expect("set_action should succeed");
        assert_eq!(old.handler_type, SignalHandler::Default, "old action should be Default");
        let current = cold.get_action(Signal::Int);
        assert_eq!(current.handler_type, SignalHandler::User, "new action should be User");
        assert_eq!(current.handler, 0xDEAD, "handler address should be set");
    }

    #[test]
    fn signalcold_sigkill_cannot_be_caught() {
        let mut cold = Box::new(SignalCold::new());
        let err = cold.set_action(Signal::Kill, SignalAction::IGNORE).unwrap_err();
        assert_eq!(err, crate::error::ProcError::InvalidSignal, "SIGKILL must not be caught");
    }

    #[test]
    fn signalcold_sigstop_cannot_be_caught() {
        let mut cold = Box::new(SignalCold::new());
        let err = cold.set_action(Signal::Stop, SignalAction::IGNORE).unwrap_err();
        assert_eq!(err, crate::error::ProcError::InvalidSignal, "SIGSTOP must not be caught");
    }

    // ── Signal enum tests ───────────────────────────────────────────────

    #[test]
    fn signal_from_raw_roundtrip() {
        for num in 1u8..=31 {
            let sig = Signal::from_raw(num).expect(&alloc::format!("from_raw({}) should succeed", num));
            assert_eq!(sig as u8, num, "roundtrip for signal {}", num);
        }
        assert!(Signal::from_raw(0).is_none(), "from_raw(0) should be None");
        assert!(Signal::from_raw(32).is_none(), "from_raw(32) should be None");
        assert!(Signal::from_raw(255).is_none(), "from_raw(255) should be None");
    }

    #[test]
    fn signal_default_actions() {
        // Spot-check POSIX-mandated defaults
        assert_eq!(Signal::Hup.default_action(), SignalDefault::Terminate);
        assert_eq!(Signal::Int.default_action(), SignalDefault::Terminate);
        assert_eq!(Signal::Quit.default_action(), SignalDefault::CoreDump);
        assert_eq!(Signal::Ill.default_action(), SignalDefault::CoreDump);
        assert_eq!(Signal::Abrt.default_action(), SignalDefault::CoreDump);
        assert_eq!(Signal::Segv.default_action(), SignalDefault::CoreDump);
        assert_eq!(Signal::Kill.default_action(), SignalDefault::Terminate);
        assert_eq!(Signal::Stop.default_action(), SignalDefault::Stop);
        assert_eq!(Signal::Tstp.default_action(), SignalDefault::Stop);
        assert_eq!(Signal::Cont.default_action(), SignalDefault::Continue);
        assert_eq!(Signal::Chld.default_action(), SignalDefault::Ignore);
        assert_eq!(Signal::Urg.default_action(), SignalDefault::Ignore);
        assert_eq!(Signal::Winch.default_action(), SignalDefault::Ignore);
        assert_eq!(Signal::Pipe.default_action(), SignalDefault::Terminate);
        assert_eq!(Signal::Term.default_action(), SignalDefault::Terminate);
        assert_eq!(Signal::Bus.default_action(), SignalDefault::CoreDump);
        assert_eq!(Signal::Fpe.default_action(), SignalDefault::CoreDump);
        assert_eq!(Signal::Sys.default_action(), SignalDefault::CoreDump);
        assert_eq!(Signal::Ttin.default_action(), SignalDefault::Stop);
        assert_eq!(Signal::Ttou.default_action(), SignalDefault::Stop);
    }

    // ── SignalSet tests ─────────────────────────────────────────────────

    #[test]
    fn signalset_add_contains_remove() {
        let set = SignalSet::EMPTY;
        assert!(!set.contains(1), "empty set should not contain signal 1");
        let set = set.add(1);
        assert!(set.contains(1), "set should contain signal 1 after add");
        let set = set.add(15);
        assert!(set.contains(15), "set should contain signal 15");
        let set = set.remove(1);
        assert!(!set.contains(1), "signal 1 should be removed");
        assert!(set.contains(15), "signal 15 should still be present");
    }

    #[test]
    fn signalset_and_or_not() {
        let a = SignalSet::EMPTY.add(1).add(2).add(3);
        let b = SignalSet::EMPTY.add(2).add(3).add(4);
        let intersection = a.and(b);
        assert!(intersection.contains(2), "AND should keep common signals");
        assert!(intersection.contains(3), "AND should keep common signals");
        assert!(!intersection.contains(1), "AND should remove 1");
        assert!(!intersection.contains(4), "AND should remove 4");

        let union = a.or(b);
        assert!(union.contains(1), "OR should include 1");
        assert!(union.contains(4), "OR should include 4");

        let neg = SignalSet::EMPTY.add(5).not();
        assert!(!neg.contains(5), "NOT should flip bit for signal 5");
        assert!(neg.contains(1), "NOT should set bit for signal 1");
    }

    #[test]
    fn signalset_lowest() {
        assert!(SignalSet::EMPTY.lowest().is_none(), "empty set lowest is None");
        let set = SignalSet::EMPTY.add(10).add(5).add(20);
        assert_eq!(set.lowest(), Some(5), "lowest should return 5");
    }

    #[test]
    fn signalset_full_and_empty() {
        assert!(SignalSet::EMPTY.is_empty(), "EMPTY should be empty");
        assert!(!SignalSet::FULL.is_empty(), "FULL should not be empty");
        // FULL should contain all 64 signals
        for i in 1..=64 {
            assert!(SignalSet::FULL.contains(i), "FULL should contain signal {}", i);
        }
    }
}
