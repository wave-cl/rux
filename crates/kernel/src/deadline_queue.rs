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
