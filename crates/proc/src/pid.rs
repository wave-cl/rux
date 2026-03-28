use crate::id::Pid;
use crate::error::ProcError;

/// Maximum number of PIDs. 32768 = typical Linux default.
pub const MAX_PIDS: usize = 32768;

/// Bitmap-based PID allocator. Tracks which PIDs are in use.
/// PID 0 is reserved (idle/swapper). PID 1 is init.
///
/// Uses a scan hint for O(1) amortized allocation: the hint tracks
/// the first word that might have a free bit, avoiding full scans.
#[repr(C)]
pub struct PidBitmap {
    /// Bitmap: bit N = 1 means PID N is allocated.
    bits: [u64; MAX_PIDS / 64],
    /// Number of allocated PIDs.
    pub allocated: u32,
    /// Scan hint: first word index that might have a free bit.
    hint: u16,
    pub _pad: [u8; 2],
}

const _: () = assert!(core::mem::size_of::<PidBitmap>() == MAX_PIDS / 8 + 8);

impl PidBitmap {
    /// Create a new PID bitmap with PID 0 reserved.
    pub const fn new() -> Self {
        let mut bits = [0u64; MAX_PIDS / 64];
        bits[0] = 1; // reserve PID 0
        Self {
            bits,
            allocated: 1, // PID 0 is "allocated"
            hint: 0,
            _pad: [0; 2],
        }
    }

    /// Allocate the lowest available PID.
    pub fn alloc(&mut self) -> Result<Pid, ProcError> {
        let start = self.hint as usize;

        // Scan from hint forward
        for word_idx in start..self.bits.len() {
            let word = !self.bits[word_idx]; // invert: 1 = free
            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                let pid = word_idx * 64 + bit;
                if pid >= MAX_PIDS {
                    break;
                }
                self.bits[word_idx] |= 1u64 << bit;
                self.allocated += 1;
                self.hint = word_idx as u16;
                return Ok(Pid::new(pid as u32));
            }
        }
        // Wrap around (hint may have advanced past freed PIDs)
        for word_idx in 0..start {
            let word = !self.bits[word_idx];
            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                let pid = word_idx * 64 + bit;
                self.bits[word_idx] |= 1u64 << bit;
                self.allocated += 1;
                self.hint = word_idx as u16;
                return Ok(Pid::new(pid as u32));
            }
        }

        Err(ProcError::ResourceLimit)
    }

    /// Allocate a specific PID. Returns error if already taken.
    pub fn alloc_specific(&mut self, pid: Pid) -> Result<(), ProcError> {
        let n = pid.as_u32() as usize;
        if n >= MAX_PIDS {
            return Err(ProcError::InvalidPid);
        }
        let word = n / 64;
        let bit = n % 64;
        if self.bits[word] & (1u64 << bit) != 0 {
            return Err(ProcError::ResourceLimit); // already taken
        }
        self.bits[word] |= 1u64 << bit;
        self.allocated += 1;
        Ok(())
    }

    /// Free a PID.
    pub fn free(&mut self, pid: Pid) {
        let n = pid.as_u32() as usize;
        if n >= MAX_PIDS { return; }
        let word = n / 64;
        let bit = n % 64;
        if self.bits[word] & (1u64 << bit) != 0 {
            self.bits[word] &= !(1u64 << bit);
            self.allocated -= 1;
            // Update hint
            if (word as u16) < self.hint {
                self.hint = word as u16;
            }
        }
    }

    /// Check if a PID is allocated.
    #[inline(always)]
    pub fn is_allocated(&self, pid: Pid) -> bool {
        let n = pid.as_u32() as usize;
        if n >= MAX_PIDS { return false; }
        self.bits[n / 64] & (1u64 << (n % 64)) != 0
    }

    /// Number of available PIDs.
    #[inline(always)]
    pub fn available(&self) -> u32 {
        MAX_PIDS as u32 - self.allocated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bitmap() -> Box<PidBitmap> {
        extern crate alloc;
        unsafe {
            let layout = alloc::alloc::Layout::new::<PidBitmap>();
            let ptr = alloc::alloc::alloc_zeroed(layout) as *mut PidBitmap;
            let mut bm = Box::from_raw(ptr);
            *bm = PidBitmap::new();
            bm
        }
    }

    #[test]
    fn pid0_is_reserved() {
        let bm = make_bitmap();
        assert!(bm.is_allocated(Pid::new(0)), "PID 0 must be reserved");
        assert_eq!(bm.allocated, 1);
    }

    #[test]
    fn alloc_returns_lowest() {
        let mut bm = make_bitmap();
        let p1 = bm.alloc().unwrap();
        assert_eq!(p1, Pid::new(1), "first alloc should return PID 1");
        let p2 = bm.alloc().unwrap();
        assert_eq!(p2, Pid::new(2));
        let p3 = bm.alloc().unwrap();
        assert_eq!(p3, Pid::new(3));
    }

    #[test]
    fn free_and_realloc() {
        let mut bm = make_bitmap();
        let p1 = bm.alloc().unwrap();
        let p2 = bm.alloc().unwrap();
        let _p3 = bm.alloc().unwrap();
        bm.free(p1);
        bm.free(p2);
        // Re-alloc should return 1 (lowest free)
        let p = bm.alloc().unwrap();
        assert_eq!(p, Pid::new(1));
        let p = bm.alloc().unwrap();
        assert_eq!(p, Pid::new(2));
    }

    #[test]
    fn alloc_specific() {
        let mut bm = make_bitmap();
        bm.alloc_specific(Pid::new(100)).unwrap();
        assert!(bm.is_allocated(Pid::new(100)));
        assert_eq!(bm.alloc_specific(Pid::new(100)).unwrap_err(), ProcError::ResourceLimit);
    }

    #[test]
    fn alloc_many_unique() {
        let mut bm = make_bitmap();
        let mut pids = alloc::vec::Vec::new();
        for _ in 0..1000 {
            pids.push(bm.alloc().unwrap());
        }
        // All should be unique
        let mut sorted: alloc::vec::Vec<u32> = pids.iter().map(|p| p.as_u32()).collect();
        sorted.sort();
        for i in 1..sorted.len() {
            assert_ne!(sorted[i], sorted[i-1], "duplicate PID at index {}", i);
        }
    }

    #[test]
    fn exhaust_pids() {
        let mut bm = make_bitmap();
        // PID 0 is reserved, so 32767 available
        for _ in 0..MAX_PIDS - 1 {
            bm.alloc().unwrap();
        }
        assert_eq!(bm.available(), 0);
        assert_eq!(bm.alloc().unwrap_err(), ProcError::ResourceLimit);
    }

    #[test]
    fn free_updates_count() {
        let mut bm = make_bitmap();
        let p = bm.alloc().unwrap();
        assert_eq!(bm.allocated, 2); // PID 0 + p
        bm.free(p);
        assert_eq!(bm.allocated, 1); // only PID 0
    }

    #[test]
    fn is_allocated_checks() {
        let mut bm = make_bitmap();
        assert!(!bm.is_allocated(Pid::new(42)));
        let _p = bm.alloc_specific(Pid::new(42));
        assert!(bm.is_allocated(Pid::new(42)));
    }

    extern crate alloc;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
}
