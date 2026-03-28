#![no_std]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LockState {
    Unlocked,
    Locked,
    Contended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyncError {
    Poisoned,
    WouldBlock,
    Timeout,
}

/// # Safety
/// Implementations must provide correct mutual exclusion guarantees
/// using appropriate atomic operations and memory barriers.
pub unsafe trait RawLock {
    fn acquire(&self);

    fn try_acquire(&self) -> bool;

    fn release(&self);
}

pub trait Mutex {
    type Guard<'a>
    where
        Self: 'a;

    fn lock(&self) -> Self::Guard<'_>;

    fn try_lock(&self) -> Result<Self::Guard<'_>, SyncError>;
}

pub trait Semaphore {
    fn up(&self);

    fn down(&self);

    fn try_down(&self) -> bool;
}
