/// Min-heap deadline queue for O(1) per-tick timer checks.
///
/// Replaces the O(n) per-tick scan in `wake_sleepers()`. The timer ISR
/// peeks the root of the heap — if the earliest deadline hasn't passed,
/// no work is done. Expired entries are popped and processed.
///
/// Lazy removal: tasks woken early (signal, pipe, futex) aren't removed
/// from the heap. The pop loop skips stale entries by checking task state.

/// Maximum simultaneous deadline entries (wake_at + itimer + margin).
const MAX_DEADLINES: usize = 192;

/// Entry kind: distinguishes sleep deadlines from interval timers.
pub const KIND_WAKE: u8 = 0;
pub const KIND_ITIMER: u8 = 1;
pub const KIND_POSIX_TIMER: u8 = 2;

#[derive(Clone, Copy)]
pub struct Entry {
    pub deadline: u64,
    pub task_idx: u16,
    pub kind: u8,
    _pad: u8,
}

impl Entry {
    const EMPTY: Self = Self { deadline: u64::MAX, task_idx: 0, kind: 0, _pad: 0 };
}

pub struct DeadlineQueue {
    heap: [Entry; MAX_DEADLINES],
    len: usize,
}

impl DeadlineQueue {
    pub const fn new() -> Self {
        Self {
            heap: [Entry::EMPTY; MAX_DEADLINES],
            len: 0,
        }
    }

    /// Peek the earliest deadline. Returns u64::MAX if empty.
    #[inline(always)]
    pub fn peek_deadline(&self) -> u64 {
        if self.len == 0 { u64::MAX } else { self.heap[0].deadline }
    }

    /// Pop the earliest entry. Caller must check peek_deadline first.
    pub fn pop(&mut self) -> Entry {
        debug_assert!(self.len > 0);
        let top = self.heap[0];
        self.len -= 1;
        if self.len > 0 {
            self.heap[0] = self.heap[self.len];
            self.sift_down(0);
        }
        top
    }

    /// Insert an entry. Silently drops if full.
    pub fn insert(&mut self, deadline: u64, task_idx: u16, kind: u8) {
        if self.len >= MAX_DEADLINES { return; }
        let i = self.len;
        self.heap[i] = Entry { deadline, task_idx, kind, _pad: 0 };
        self.len += 1;
        self.sift_up(i);
    }

    #[inline]
    fn sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if self.heap[i].deadline >= self.heap[parent].deadline { break; }
            self.heap.swap(i, parent);
            i = parent;
        }
    }

    #[inline]
    fn sift_down(&mut self, mut i: usize) {
        loop {
            let left = 2 * i + 1;
            let right = 2 * i + 2;
            let mut smallest = i;
            if left < self.len && self.heap[left].deadline < self.heap[smallest].deadline {
                smallest = left;
            }
            if right < self.len && self.heap[right].deadline < self.heap[smallest].deadline {
                smallest = right;
            }
            if smallest == i { break; }
            self.heap.swap(i, smallest);
            i = smallest;
        }
    }
}

pub static mut DEADLINE_QUEUE: DeadlineQueue = DeadlineQueue::new();

// ── Safe accessors ────────────────────────────────────────────────────
// Wrap the static-mut access so call sites don't trip the
// `static_mut_refs` lint (which becomes a hard error in future editions).

#[inline]
pub unsafe fn dq_peek_deadline() -> u64 {
    (*(&raw const DEADLINE_QUEUE)).peek_deadline()
}

#[inline]
pub unsafe fn dq_pop() -> Entry {
    (*(&raw mut DEADLINE_QUEUE)).pop()
}

#[inline]
pub unsafe fn dq_insert(deadline: u64, task_idx: u16, kind: u8) {
    (*(&raw mut DEADLINE_QUEUE)).insert(deadline, task_idx, kind);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_peek_returns_max() {
        let q = DeadlineQueue::new();
        assert_eq!(q.peek_deadline(), u64::MAX);
    }

    #[test]
    fn insert_single_then_peek() {
        let mut q = DeadlineQueue::new();
        q.insert(100, 5, KIND_WAKE);
        assert_eq!(q.peek_deadline(), 100);
    }

    #[test]
    fn pop_returns_minimum() {
        let mut q = DeadlineQueue::new();
        q.insert(300, 0, KIND_WAKE);
        q.insert(100, 1, KIND_WAKE);
        q.insert(200, 2, KIND_WAKE);
        assert_eq!(q.pop().deadline, 100);
        assert_eq!(q.pop().deadline, 200);
        assert_eq!(q.pop().deadline, 300);
    }

    #[test]
    fn pop_preserves_task_idx_and_kind() {
        let mut q = DeadlineQueue::new();
        q.insert(50, 7, KIND_ITIMER);
        q.insert(10, 3, KIND_POSIX_TIMER);
        let first = q.pop();
        assert_eq!(first.deadline, 10);
        assert_eq!(first.task_idx, 3);
        assert_eq!(first.kind, KIND_POSIX_TIMER);
        let second = q.pop();
        assert_eq!(second.deadline, 50);
        assert_eq!(second.task_idx, 7);
        assert_eq!(second.kind, KIND_ITIMER);
    }

    #[test]
    fn many_inserts_pop_in_order() {
        let mut q = DeadlineQueue::new();
        // Insert 50 deadlines in reverse order
        for d in (1..=50u64).rev() {
            q.insert(d * 10, d as u16, KIND_WAKE);
        }
        // Pop them — should come out in ascending order
        for d in 1..=50u64 {
            let e = q.pop();
            assert_eq!(e.deadline, d * 10);
            assert_eq!(e.task_idx, d as u16);
        }
        assert_eq!(q.peek_deadline(), u64::MAX);
    }

    #[test]
    fn duplicate_deadlines_both_pop() {
        let mut q = DeadlineQueue::new();
        q.insert(100, 1, KIND_WAKE);
        q.insert(100, 2, KIND_WAKE);
        q.insert(100, 3, KIND_WAKE);
        assert_eq!(q.pop().deadline, 100);
        assert_eq!(q.pop().deadline, 100);
        assert_eq!(q.pop().deadline, 100);
        assert_eq!(q.peek_deadline(), u64::MAX);
    }

    #[test]
    fn capacity_exhaustion_drops_silently() {
        let mut q = DeadlineQueue::new();
        for i in 0..MAX_DEADLINES {
            q.insert(i as u64 + 1, i as u16, KIND_WAKE);
        }
        // One more insert past capacity — should silently drop
        q.insert(99999, 0, KIND_WAKE);
        // We should still get exactly MAX_DEADLINES entries out
        let mut popped = 0;
        while q.peek_deadline() != u64::MAX {
            q.pop();
            popped += 1;
        }
        assert_eq!(popped, MAX_DEADLINES);
    }

    #[test]
    fn interleaved_insert_pop() {
        let mut q = DeadlineQueue::new();
        q.insert(50, 1, KIND_WAKE);
        q.insert(30, 2, KIND_WAKE);
        assert_eq!(q.pop().deadline, 30);
        q.insert(10, 3, KIND_WAKE);
        q.insert(40, 4, KIND_WAKE);
        assert_eq!(q.pop().deadline, 10);
        assert_eq!(q.pop().deadline, 40);
        assert_eq!(q.pop().deadline, 50);
    }
}
