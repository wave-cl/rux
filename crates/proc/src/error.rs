#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcError {
    NotFound,
    PermissionDenied,
    ResourceLimit,
    InvalidSignal,
    ZombieProcess,
    InvalidPid,
    InvalidFd,
    FdTableFull,
    NoChildren,
    Interrupted,
    TryAgain,
    InvalidArgument,
    NotPermitted,
    SearchDenied,
}

impl ProcError {
    /// Map to POSIX errno value.
    #[inline(always)]
    pub const fn as_errno(self) -> i32 {
        match self {
            Self::NotFound => 3,          // ESRCH
            Self::PermissionDenied => 13,  // EACCES
            Self::ResourceLimit => 11,     // EAGAIN (resource temporarily unavailable)
            Self::InvalidSignal => 22,     // EINVAL
            Self::ZombieProcess => 3,      // ESRCH
            Self::InvalidPid => 3,         // ESRCH
            Self::InvalidFd => 9,          // EBADF
            Self::FdTableFull => 24,       // EMFILE
            Self::NoChildren => 10,        // ECHILD
            Self::Interrupted => 4,        // EINTR
            Self::TryAgain => 11,          // EAGAIN
            Self::InvalidArgument => 22,   // EINVAL
            Self::NotPermitted => 1,       // EPERM
            Self::SearchDenied => 13,      // EACCES
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_errno_not_found() {
        assert_eq!(ProcError::NotFound.as_errno(), 3, "NotFound should map to ESRCH (3)");
    }

    #[test]
    fn as_errno_permission_denied() {
        assert_eq!(ProcError::PermissionDenied.as_errno(), 13, "PermissionDenied should map to EACCES (13)");
    }

    #[test]
    fn as_errno_resource_limit() {
        assert_eq!(ProcError::ResourceLimit.as_errno(), 11, "ResourceLimit should map to EAGAIN (11)");
    }

    #[test]
    fn as_errno_invalid_signal() {
        assert_eq!(ProcError::InvalidSignal.as_errno(), 22, "InvalidSignal should map to EINVAL (22)");
    }

    #[test]
    fn as_errno_zombie_process() {
        assert_eq!(ProcError::ZombieProcess.as_errno(), 3, "ZombieProcess should map to ESRCH (3)");
    }

    #[test]
    fn as_errno_invalid_pid() {
        assert_eq!(ProcError::InvalidPid.as_errno(), 3, "InvalidPid should map to ESRCH (3)");
    }

    #[test]
    fn as_errno_invalid_fd() {
        assert_eq!(ProcError::InvalidFd.as_errno(), 9, "InvalidFd should map to EBADF (9)");
    }

    #[test]
    fn as_errno_fd_table_full() {
        assert_eq!(ProcError::FdTableFull.as_errno(), 24, "FdTableFull should map to EMFILE (24)");
    }

    #[test]
    fn as_errno_no_children() {
        assert_eq!(ProcError::NoChildren.as_errno(), 10, "NoChildren should map to ECHILD (10)");
    }

    #[test]
    fn as_errno_interrupted() {
        assert_eq!(ProcError::Interrupted.as_errno(), 4, "Interrupted should map to EINTR (4)");
    }

    #[test]
    fn as_errno_try_again() {
        assert_eq!(ProcError::TryAgain.as_errno(), 11, "TryAgain should map to EAGAIN (11)");
    }

    #[test]
    fn as_errno_invalid_argument() {
        assert_eq!(ProcError::InvalidArgument.as_errno(), 22, "InvalidArgument should map to EINVAL (22)");
    }

    #[test]
    fn as_errno_not_permitted() {
        assert_eq!(ProcError::NotPermitted.as_errno(), 1, "NotPermitted should map to EPERM (1)");
    }

    #[test]
    fn as_errno_search_denied() {
        assert_eq!(ProcError::SearchDenied.as_errno(), 13, "SearchDenied should map to EACCES (13)");
    }

    #[test]
    fn as_errno_all_variants_covered() {
        // Ensure every variant returns a positive errno
        let variants = [
            ProcError::NotFound,
            ProcError::PermissionDenied,
            ProcError::ResourceLimit,
            ProcError::InvalidSignal,
            ProcError::ZombieProcess,
            ProcError::InvalidPid,
            ProcError::InvalidFd,
            ProcError::FdTableFull,
            ProcError::NoChildren,
            ProcError::Interrupted,
            ProcError::TryAgain,
            ProcError::InvalidArgument,
            ProcError::NotPermitted,
            ProcError::SearchDenied,
        ];
        for v in variants {
            assert!(v.as_errno() > 0, "{:?} should map to a positive errno", v);
        }
    }
}
