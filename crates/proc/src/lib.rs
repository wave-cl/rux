#![no_std]

pub mod id;
pub mod error;
pub mod signal;
pub mod creds;
pub mod rlimit;
pub mod fs;
pub mod times;
pub mod fd;
pub mod group;
pub mod task;
pub mod lifecycle;
pub mod pid;
pub mod manager;

// Re-export core types at crate root
pub use id::{Pid, Tgid, Pgid, Sid, Uid, Gid};
pub use error::ProcError;
pub use signal::{Signal, SignalSet, SignalAction, SignalHot, SignalCold, SignalDefault, SigInfo};
pub use creds::Credentials;
pub use rlimit::{Rlimit, RlimitResource, ResourceLimits};
pub use fs::FsContext;
pub use times::ProcessTimes;
pub use fd::{FdEntry, FdTable, FdOps};
pub use group::{ProcessGroup, Session};
pub use task::Task;
pub use lifecycle::{ExitStatus, CloneFlags, WaitOptions, ProcessOps};

// Re-export TaskState from sched as the unified process/task state.
// ProcessState is eliminated — TaskState's Interruptible/Uninterruptible
// distinction is required for correct POSIX signal delivery semantics.
pub use rux_sched::TaskState;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SignalDefault, SignalHandler, SigCode, SaFlags};
    use crate::fd::{FdEntry, MAX_FDS, FD_CLOEXEC};
    use crate::rlimit::{RLIMIT_COUNT, RLIM_INFINITY};
    use crate::lifecycle::{CloneFlags, WaitOptions};
    use crate::task::TaskFlags;
    use crate::creds::MAX_SUPPLEMENTARY_GROUPS;
    use crate::signal::MAX_PENDING_SIGNALS;

    // ── Size assertions ─────────────────────────────────────────────────

    #[test]
    fn size_fd_entry() {
        assert_eq!(core::mem::size_of::<FdEntry>(), 24, "FdEntry must be 24 bytes");
    }

    #[test]
    fn size_fd_table() {
        assert_eq!(core::mem::size_of::<FdTable>(), 6152, "FdTable must be 6152 bytes");
    }

    #[test]
    fn size_signal_action() {
        assert_eq!(core::mem::size_of::<SignalAction>(), 32, "SignalAction must be 32 bytes");
    }

    #[test]
    fn size_sig_info() {
        assert_eq!(core::mem::size_of::<SigInfo>(), 32, "SigInfo must be 32 bytes");
    }

    #[test]
    fn size_sig_queue() {
        assert_eq!(core::mem::size_of::<signal::SigQueue>(), 2056, "SigQueue must be 2056 bytes");
    }

    #[test]
    fn size_signal_hot() {
        assert_eq!(core::mem::size_of::<SignalHot>(), 16, "SignalHot must be 16 bytes");
    }

    #[test]
    fn size_signal_cold() {
        assert_eq!(core::mem::size_of::<SignalCold>(), 3112, "SignalCold must be 3112 bytes");
    }

    #[test]
    fn size_credentials() {
        assert_eq!(core::mem::size_of::<Credentials>(), 192, "Credentials must be 192 bytes");
    }

    #[test]
    fn size_resource_limits() {
        assert_eq!(core::mem::size_of::<ResourceLimits>(), 256, "ResourceLimits must be 256 bytes");
    }

    #[test]
    fn size_rlimit() {
        assert_eq!(core::mem::size_of::<Rlimit>(), 16, "Rlimit must be 16 bytes");
    }

    #[test]
    fn size_fs_context() {
        assert_eq!(core::mem::size_of::<FsContext>(), 24, "FsContext must be 24 bytes");
    }

    #[test]
    fn size_process_times() {
        assert_eq!(core::mem::size_of::<ProcessTimes>(), 40, "ProcessTimes must be 40 bytes");
    }

    #[test]
    fn size_task() {
        assert_eq!(core::mem::size_of::<task::Task>(), 1024, "Task must be 1024 bytes");
    }

    #[test]
    fn size_signal_set() {
        assert_eq!(core::mem::size_of::<SignalSet>(), 8, "SignalSet must be 8 bytes (u64)");
    }

    // ── Discriminant value assertions ───────────────────────────────────

    #[test]
    fn signal_discriminants() {
        assert_eq!(Signal::Hup as u8, 1);
        assert_eq!(Signal::Int as u8, 2);
        assert_eq!(Signal::Quit as u8, 3);
        assert_eq!(Signal::Ill as u8, 4);
        assert_eq!(Signal::Trap as u8, 5);
        assert_eq!(Signal::Abrt as u8, 6);
        assert_eq!(Signal::Bus as u8, 7);
        assert_eq!(Signal::Fpe as u8, 8);
        assert_eq!(Signal::Kill as u8, 9);
        assert_eq!(Signal::Usr1 as u8, 10);
        assert_eq!(Signal::Segv as u8, 11);
        assert_eq!(Signal::Usr2 as u8, 12);
        assert_eq!(Signal::Pipe as u8, 13);
        assert_eq!(Signal::Alrm as u8, 14);
        assert_eq!(Signal::Term as u8, 15);
        assert_eq!(Signal::StkFlt as u8, 16);
        assert_eq!(Signal::Chld as u8, 17);
        assert_eq!(Signal::Cont as u8, 18);
        assert_eq!(Signal::Stop as u8, 19);
        assert_eq!(Signal::Tstp as u8, 20);
        assert_eq!(Signal::Ttin as u8, 21);
        assert_eq!(Signal::Ttou as u8, 22);
        assert_eq!(Signal::Urg as u8, 23);
        assert_eq!(Signal::Xcpu as u8, 24);
        assert_eq!(Signal::Xfsz as u8, 25);
        assert_eq!(Signal::Vtalrm as u8, 26);
        assert_eq!(Signal::Prof as u8, 27);
        assert_eq!(Signal::Winch as u8, 28);
        assert_eq!(Signal::Io as u8, 29);
        assert_eq!(Signal::Pwr as u8, 30);
        assert_eq!(Signal::Sys as u8, 31);
    }

    #[test]
    fn signal_default_discriminants() {
        assert_eq!(SignalDefault::Terminate as u8, 0);
        assert_eq!(SignalDefault::Ignore as u8, 1);
        assert_eq!(SignalDefault::Stop as u8, 2);
        assert_eq!(SignalDefault::CoreDump as u8, 3);
        assert_eq!(SignalDefault::Continue as u8, 4);
    }

    #[test]
    fn signal_handler_discriminants() {
        assert_eq!(SignalHandler::Default as u8, 0);
        assert_eq!(SignalHandler::Ignore as u8, 1);
        assert_eq!(SignalHandler::User as u8, 2);
    }

    #[test]
    fn sig_code_discriminants() {
        assert_eq!(SigCode::User as u8, 0);
        assert_eq!(SigCode::Kernel as u8, 1);
        assert_eq!(SigCode::Queue as u8, 2);
        assert_eq!(SigCode::Timer as u8, 3);
        assert_eq!(SigCode::AsyncIo as u8, 4);
        assert_eq!(SigCode::TkIll as u8, 5);
        assert_eq!(SigCode::FaultMapErr as u8, 6);
        assert_eq!(SigCode::FaultAccErr as u8, 7);
    }

    #[test]
    fn sa_flags_discriminants() {
        assert_eq!(SaFlags::Restart as u32, 1);
        assert_eq!(SaFlags::NoCldStop as u32, 2);
        assert_eq!(SaFlags::NoCldWait as u32, 4);
        assert_eq!(SaFlags::SigInfo as u32, 8);
        assert_eq!(SaFlags::OnStack as u32, 16);
        assert_eq!(SaFlags::NoDeFer as u32, 32);
        assert_eq!(SaFlags::ResetHand as u32, 64);
    }

    #[test]
    fn proc_error_discriminants() {
        assert_eq!(ProcError::NotFound as u8, 0);
        assert_eq!(ProcError::PermissionDenied as u8, 1);
        assert_eq!(ProcError::ResourceLimit as u8, 2);
        assert_eq!(ProcError::InvalidSignal as u8, 3);
        assert_eq!(ProcError::ZombieProcess as u8, 4);
        assert_eq!(ProcError::InvalidPid as u8, 5);
        assert_eq!(ProcError::InvalidFd as u8, 6);
        assert_eq!(ProcError::FdTableFull as u8, 7);
        assert_eq!(ProcError::NoChildren as u8, 8);
        assert_eq!(ProcError::Interrupted as u8, 9);
        assert_eq!(ProcError::TryAgain as u8, 10);
        assert_eq!(ProcError::InvalidArgument as u8, 11);
        assert_eq!(ProcError::NotPermitted as u8, 12);
        assert_eq!(ProcError::SearchDenied as u8, 13);
    }

    #[test]
    fn task_flags_discriminants() {
        assert_eq!(TaskFlags::Exiting as u32, 1 << 2);
        assert_eq!(TaskFlags::ForkNoExec as u32, 1 << 6);
        assert_eq!(TaskFlags::Signaled as u32, 1 << 10);
        assert_eq!(TaskFlags::Kthread as u32, 1 << 21);
    }

    #[test]
    fn clone_flags_discriminants() {
        assert_eq!(CloneFlags::Vm as u32, 1 << 8);
        assert_eq!(CloneFlags::Fs as u32, 1 << 9);
        assert_eq!(CloneFlags::Files as u32, 1 << 10);
        assert_eq!(CloneFlags::Sighand as u32, 1 << 11);
        assert_eq!(CloneFlags::Vfork as u32, 1 << 14);
        assert_eq!(CloneFlags::Parent as u32, 1 << 15);
        assert_eq!(CloneFlags::Thread as u32, 1 << 16);
        assert_eq!(CloneFlags::NewPid as u32, 1 << 29);
    }

    #[test]
    fn wait_options_discriminants() {
        assert_eq!(WaitOptions::NoHang as u32, 1);
        assert_eq!(WaitOptions::Untraced as u32, 2);
        assert_eq!(WaitOptions::Continued as u32, 8);
    }

    #[test]
    fn rlimit_resource_discriminants() {
        assert_eq!(rlimit::RlimitResource::Cpu as u8, 0);
        assert_eq!(rlimit::RlimitResource::Fsize as u8, 1);
        assert_eq!(rlimit::RlimitResource::Data as u8, 2);
        assert_eq!(rlimit::RlimitResource::Stack as u8, 3);
        assert_eq!(rlimit::RlimitResource::Core as u8, 4);
        assert_eq!(rlimit::RlimitResource::Rss as u8, 5);
        assert_eq!(rlimit::RlimitResource::Nproc as u8, 6);
        assert_eq!(rlimit::RlimitResource::Nofile as u8, 7);
        assert_eq!(rlimit::RlimitResource::Memlock as u8, 8);
        assert_eq!(rlimit::RlimitResource::As as u8, 9);
        assert_eq!(rlimit::RlimitResource::Locks as u8, 10);
        assert_eq!(rlimit::RlimitResource::Sigpending as u8, 11);
        assert_eq!(rlimit::RlimitResource::Msgqueue as u8, 12);
        assert_eq!(rlimit::RlimitResource::Nice as u8, 13);
        assert_eq!(rlimit::RlimitResource::Rtprio as u8, 14);
        assert_eq!(rlimit::RlimitResource::Rttime as u8, 15);
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn constants() {
        assert_eq!(MAX_FDS, 256, "MAX_FDS should be 256");
        assert_eq!(FD_CLOEXEC, 1, "FD_CLOEXEC should be 1");
        assert_eq!(MAX_PENDING_SIGNALS, 64, "MAX_PENDING_SIGNALS should be 64");
        assert_eq!(MAX_SUPPLEMENTARY_GROUPS, 32, "MAX_SUPPLEMENTARY_GROUPS should be 32");
        assert_eq!(RLIMIT_COUNT, 16, "RLIMIT_COUNT should be 16");
        assert_eq!(RLIM_INFINITY, u64::MAX, "RLIM_INFINITY should be u64::MAX");
    }

    // ── Signal default actions match POSIX ──────────────────────────────

    #[test]
    fn posix_terminate_signals() {
        let terminate_sigs = [
            Signal::Hup, Signal::Int, Signal::Pipe, Signal::Alrm,
            Signal::Term, Signal::Usr1, Signal::Usr2, Signal::StkFlt,
            Signal::Io, Signal::Pwr, Signal::Xcpu, Signal::Xfsz,
            Signal::Vtalrm, Signal::Prof, Signal::Kill,
        ];
        for sig in terminate_sigs {
            assert_eq!(sig.default_action(), SignalDefault::Terminate,
                "{:?} should default to Terminate", sig);
        }
    }

    #[test]
    fn posix_coredump_signals() {
        let core_sigs = [
            Signal::Quit, Signal::Ill, Signal::Trap, Signal::Abrt,
            Signal::Bus, Signal::Fpe, Signal::Segv, Signal::Sys,
        ];
        for sig in core_sigs {
            assert_eq!(sig.default_action(), SignalDefault::CoreDump,
                "{:?} should default to CoreDump", sig);
        }
    }

    #[test]
    fn posix_stop_signals() {
        let stop_sigs = [Signal::Stop, Signal::Tstp, Signal::Ttin, Signal::Ttou];
        for sig in stop_sigs {
            assert_eq!(sig.default_action(), SignalDefault::Stop,
                "{:?} should default to Stop", sig);
        }
    }

    #[test]
    fn posix_ignore_signals() {
        let ignore_sigs = [Signal::Chld, Signal::Urg, Signal::Winch];
        for sig in ignore_sigs {
            assert_eq!(sig.default_action(), SignalDefault::Ignore,
                "{:?} should default to Ignore", sig);
        }
    }

    #[test]
    fn posix_continue_signal() {
        assert_eq!(Signal::Cont.default_action(), SignalDefault::Continue,
            "SIGCONT should default to Continue");
    }
}
