#![no_std]

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

// ── Error types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyncError {
    WouldBlock,
}

// ── SpinMutex<T> ────────────────────────────────────────────────────────

/// Spin-based mutex. Wraps data with an AtomicBool lock and RAII guard.
/// No heap, no OS, no sleeping — just spin with PAUSE/WFE hint.
pub struct SpinMutex<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SpinMutex<T> {}
unsafe impl<T: Send> Sync for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    #[inline(always)]
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> SpinMutexGuard<'_, T> {
        loop {
            // TTAS: spin on Relaxed load (L1 cache, no bus traffic)
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
            // Attempt acquire
            if !self.locked.swap(true, Ordering::Acquire) {
                return SpinMutexGuard { mutex: self };
            }
        }
    }

    #[inline(always)]
    pub fn try_lock(&self) -> Result<SpinMutexGuard<'_, T>, SyncError> {
        if !self.locked.swap(true, Ordering::Acquire) {
            Ok(SpinMutexGuard { mutex: self })
        } else {
            Err(SyncError::WouldBlock)
        }
    }
}

pub struct SpinMutexGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> Deref for SpinMutexGuard<'_, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for SpinMutexGuard<'_, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for SpinMutexGuard<'_, T> {
    #[inline(always)]
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}

// ── IrqSpinMutex<T> ────────────────────────────────────────────────────

/// Spin mutex that disables interrupts before acquiring.
/// Prevents ISR deadlock: if kernel code holds this lock and an IRQ fires,
/// the ISR won't try to acquire because interrupts are masked.
/// The guard restores the previous interrupt state on drop.
pub struct IrqSpinMutex<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for IrqSpinMutex<T> {}
unsafe impl<T: Send> Sync for IrqSpinMutex<T> {}

impl<T> IrqSpinMutex<T> {
    #[inline(always)]
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> IrqSpinMutexGuard<'_, T> {
        let was_enabled = rux_arch::save_irqs_and_disable();
        loop {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
            if !self.locked.swap(true, Ordering::Acquire) {
                return IrqSpinMutexGuard {
                    mutex: self,
                    irq_was_enabled: was_enabled,
                };
            }
        }
    }

    #[inline(always)]
    pub fn try_lock(&self) -> Result<IrqSpinMutexGuard<'_, T>, SyncError> {
        let was_enabled = rux_arch::save_irqs_and_disable();
        if !self.locked.swap(true, Ordering::Acquire) {
            Ok(IrqSpinMutexGuard {
                mutex: self,
                irq_was_enabled: was_enabled,
            })
        } else {
            rux_arch::restore_irqs(was_enabled);
            Err(SyncError::WouldBlock)
        }
    }
}

pub struct IrqSpinMutexGuard<'a, T> {
    mutex: &'a IrqSpinMutex<T>,
    irq_was_enabled: bool,
}

impl<T> Deref for IrqSpinMutexGuard<'_, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for IrqSpinMutexGuard<'_, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for IrqSpinMutexGuard<'_, T> {
    #[inline(always)]
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
        rux_arch::restore_irqs(self.irq_was_enabled);
    }
}
