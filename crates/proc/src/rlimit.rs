/// Soft and hard limit pair.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Rlimit {
    /// Current (soft) limit — the enforced limit. Can be raised up to `max`.
    pub cur: u64,
    /// Hard limit — ceiling for `cur`. Only root can raise this.
    pub max: u64,
}

const _: () = assert!(core::mem::size_of::<Rlimit>() == 16);

/// Unlimited resource value.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Resource types for getrlimit/setrlimit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RlimitResource {
    /// CPU time in seconds.
    Cpu        = 0,
    /// Maximum file size in bytes.
    Fsize      = 1,
    /// Maximum data segment size.
    Data       = 2,
    /// Maximum stack size.
    Stack      = 3,
    /// Maximum core file size.
    Core       = 4,
    /// Maximum resident set size.
    Rss        = 5,
    /// Maximum number of processes.
    Nproc      = 6,
    /// Maximum number of open files.
    Nofile     = 7,
    /// Maximum locked memory.
    Memlock    = 8,
    /// Maximum address space size.
    As         = 9,
    /// Maximum file locks.
    Locks      = 10,
    /// Maximum pending signals.
    Sigpending = 11,
    /// Maximum bytes in POSIX message queues.
    Msgqueue   = 12,
    /// Maximum nice priority (20 - nice).
    Nice       = 13,
    /// Maximum real-time priority.
    Rtprio     = 14,
    /// Maximum real-time CPU time (microseconds).
    Rttime     = 15,
}

/// Total number of resource limit types.
pub const RLIMIT_COUNT: usize = 16;

/// Per-process resource limits.
#[repr(C)]
pub struct ResourceLimits {
    /// Indexed by `RlimitResource as usize`.
    pub limits: [Rlimit; RLIMIT_COUNT],
}

const _: () = assert!(core::mem::size_of::<ResourceLimits>() == 256);

impl ResourceLimits {
    /// Default limits: everything unlimited except NOFILE (256) and NPROC (1024).
    pub const DEFAULT: Self = {
        let inf = Rlimit { cur: RLIM_INFINITY, max: RLIM_INFINITY };
        let mut limits = [inf; RLIMIT_COUNT];
        limits[RlimitResource::Nofile as usize] = Rlimit { cur: 256, max: 1024 };
        limits[RlimitResource::Nproc as usize] = Rlimit { cur: 1024, max: 4096 };
        limits[RlimitResource::Stack as usize] = Rlimit { cur: 8 * 1024 * 1024, max: RLIM_INFINITY };
        limits[RlimitResource::Core as usize] = Rlimit { cur: 0, max: RLIM_INFINITY };
        Self { limits }
    };

    #[inline(always)]
    pub const fn get(&self, resource: RlimitResource) -> &Rlimit {
        &self.limits[resource as usize]
    }

    /// Set a resource limit. Enforces POSIX rules:
    /// - cur must be <= max
    /// - Non-root cannot raise max above current max
    pub fn set(&mut self, resource: RlimitResource, new: Rlimit, is_root: bool) -> Result<(), crate::error::ProcError> {
        if new.cur > new.max {
            return Err(crate::error::ProcError::InvalidArgument);
        }
        let old_max = self.limits[resource as usize].max;
        if !is_root && new.max > old_max {
            return Err(crate::error::ProcError::NotPermitted);
        }
        self.limits[resource as usize] = new;
        Ok(())
    }

    /// Check if a value is within the soft limit. Returns true if within limit.
    #[inline(always)]
    pub fn check(&self, resource: RlimitResource, value: u64) -> bool {
        let limit = self.limits[resource as usize].cur;
        limit == RLIM_INFINITY || value <= limit
    }
}

impl Default for ResourceLimits {
    fn default() -> Self { Self::DEFAULT }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_nofile() {
        let rl = ResourceLimits::DEFAULT;
        let nofile = rl.get(RlimitResource::Nofile);
        assert_eq!(nofile.cur, 256, "default NOFILE soft limit should be 256");
        assert_eq!(nofile.max, 1024, "default NOFILE hard limit should be 1024");
    }

    #[test]
    fn defaults_nproc() {
        let rl = ResourceLimits::DEFAULT;
        let nproc = rl.get(RlimitResource::Nproc);
        assert_eq!(nproc.cur, 1024, "default NPROC soft limit should be 1024");
        assert_eq!(nproc.max, 4096, "default NPROC hard limit should be 4096");
    }

    #[test]
    fn defaults_stack() {
        let rl = ResourceLimits::DEFAULT;
        let stack = rl.get(RlimitResource::Stack);
        assert_eq!(stack.cur, 8 * 1024 * 1024, "default stack soft limit should be 8 MiB");
        assert_eq!(stack.max, RLIM_INFINITY, "default stack hard limit should be infinity");
    }

    #[test]
    fn defaults_core() {
        let rl = ResourceLimits::DEFAULT;
        let core = rl.get(RlimitResource::Core);
        assert_eq!(core.cur, 0, "default core soft limit should be 0");
        assert_eq!(core.max, RLIM_INFINITY, "default core hard limit should be infinity");
    }

    #[test]
    fn defaults_unlimited_resources() {
        let rl = ResourceLimits::DEFAULT;
        // Cpu, Fsize, Data, Rss, etc. should all be INFINITY
        let cpu = rl.get(RlimitResource::Cpu);
        assert_eq!(cpu.cur, RLIM_INFINITY, "default CPU soft limit should be infinity");
        assert_eq!(cpu.max, RLIM_INFINITY, "default CPU hard limit should be infinity");
    }

    #[test]
    fn set_valid_as_root() {
        let mut rl = ResourceLimits::DEFAULT;
        let new = Rlimit { cur: 512, max: 2048 };
        rl.set(RlimitResource::Nofile, new, true).expect("root should set any limit");
        assert_eq!(rl.get(RlimitResource::Nofile).cur, 512, "soft limit should be updated");
        assert_eq!(rl.get(RlimitResource::Nofile).max, 2048, "hard limit should be updated");
    }

    #[test]
    fn set_cur_exceeds_max_errors() {
        let mut rl = ResourceLimits::DEFAULT;
        let bad = Rlimit { cur: 2000, max: 1000 };
        let err = rl.set(RlimitResource::Nofile, bad, true).unwrap_err();
        assert_eq!(err, crate::error::ProcError::InvalidArgument, "cur > max should fail");
    }

    #[test]
    fn set_nonroot_cannot_raise_hard() {
        let mut rl = ResourceLimits::DEFAULT;
        // NOFILE hard limit is 1024
        let raise = Rlimit { cur: 512, max: 2048 };
        let err = rl.set(RlimitResource::Nofile, raise, false).unwrap_err();
        assert_eq!(err, crate::error::ProcError::NotPermitted, "non-root cannot raise hard limit");
    }

    #[test]
    fn set_nonroot_can_lower_hard() {
        let mut rl = ResourceLimits::DEFAULT;
        let lower = Rlimit { cur: 100, max: 500 };
        rl.set(RlimitResource::Nofile, lower, false).expect("non-root should lower hard limit");
        assert_eq!(rl.get(RlimitResource::Nofile).max, 500, "hard limit should be lowered");
    }

    #[test]
    fn check_within_limit() {
        let rl = ResourceLimits::DEFAULT;
        assert!(rl.check(RlimitResource::Nofile, 100), "100 < 256 should be within limit");
        assert!(rl.check(RlimitResource::Nofile, 256), "256 == 256 should be within limit");
        assert!(!rl.check(RlimitResource::Nofile, 257), "257 > 256 should exceed limit");
    }

    #[test]
    fn check_infinity_always_passes() {
        let rl = ResourceLimits::DEFAULT;
        assert!(rl.check(RlimitResource::Cpu, u64::MAX), "infinity limit should pass for any value");
    }
}
