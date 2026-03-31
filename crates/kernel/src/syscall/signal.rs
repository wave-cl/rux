//! Signal syscalls (POSIX.1).

type Arch = crate::arch::Arch;

/// sigaction(signum, act, oldact) — POSIX.1
/// Uses the `SigactionLayout` trait to handle arch-specific struct layout.
pub fn sigaction(signum: usize, act_ptr: usize, oldact_ptr: usize) -> isize {
    use rux_proc::signal::*;
    use rux_arch::SigactionLayout;
    if signum < 1 || signum > 31 { return -22; }
    let sig = match Signal::from_raw(signum as u8) {
        Some(s) => s,
        None => return -22,
    };
    if sig == Signal::Kill || sig == Signal::Stop { return -22; }

    unsafe {
        let cold = &mut super::PROCESS.signal_cold;

        // Write old action to user oldact
        if oldact_ptr != 0 {
            let old = cold.get_action(sig);
            let handler: usize = match old.handler_type {
                SignalHandler::Default => 0,
                SignalHandler::Ignore => 1,
                SignalHandler::User => old.handler,
            };
            Arch::write_sigaction(
                oldact_ptr, handler, old.flags as u32, old.mask.0,
                super::PROCESS.signal_restorer[signum],
            );
        }

        // Read new action from user act
        if act_ptr != 0 {
            let (handler_addr, flags, mask_raw, restorer) = Arch::read_sigaction(act_ptr);

            let handler_type = match handler_addr {
                0 => SignalHandler::Default,
                1 => SignalHandler::Ignore,
                _ => SignalHandler::User,
            };
            let action = SignalAction {
                handler_type,
                _pad0: [0; 7],
                handler: handler_addr,
                mask: SignalSet(mask_raw),
                flags,
                _pad1: [0; 4],
            };
            let _ = cold.set_action(sig, action);
            if Arch::HAS_RESTORER {
                super::PROCESS.signal_restorer[signum] = restorer;
            }
        }
    }
    0
}

/// sigprocmask(how, set, oldset, sigsetsize) — POSIX.1
pub fn sigprocmask(how: usize, set_ptr: usize, oldset_ptr: usize, sigsetsize: usize) -> isize {
    use rux_proc::signal::*;
    if sigsetsize > 8 { return -22; }
    unsafe {
        let hot = &mut super::PROCESS.signal_hot;

        // Write old mask
        if oldset_ptr != 0 {
            *(oldset_ptr as *mut u64) = hot.blocked.0;
        }

        // Apply new mask
        if set_ptr != 0 && sigsetsize > 0 {
            let new_set = SignalSet(*(set_ptr as *const u64));
            // Cannot block SIGKILL (9) or SIGSTOP (19)
            let unblockable = Signal::Kill.to_bit() | Signal::Stop.to_bit();

            const SIG_BLOCK: usize = 0;
            const SIG_UNBLOCK: usize = 1;
            const SIG_SETMASK: usize = 2;

            match how {
                SIG_BLOCK => {
                    hot.blocked = SignalSet((hot.blocked.0 | new_set.0) & !unblockable);
                }
                SIG_UNBLOCK => {
                    hot.blocked = SignalSet(hot.blocked.0 & !new_set.0);
                }
                SIG_SETMASK => {
                    hot.blocked = SignalSet(new_set.0 & !unblockable);
                }
                _ => return -22,
            }
        }
    }
    0
}

/// kill(pid, sig) — POSIX.1: send a signal.
pub fn kill(pid: isize, signum: usize) -> isize {
    use rux_proc::signal::*;
    // Our process is always PID 1. Accept pid=0,1,-1 as "self".
    match pid {
        0 | 1 | -1 => {}
        _ => return -3, // -ESRCH
    }
    if signum == 0 { return 0; } // permission check only
    if signum > 31 { return -22; }
    let sig = match Signal::from_raw(signum as u8) {
        Some(s) => s,
        None => return -22,
    };
    unsafe {
        let hot = &mut super::PROCESS.signal_hot;
        let cold = &mut super::PROCESS.signal_cold;
        let action = cold.get_action(sig);

        // SIGKILL always terminates
        if sig == Signal::Kill {
            posix_exit(128 + 9);
        }

        // If default action is Terminate/CoreDump and handler is Default, exit now
        if action.handler_type == SignalHandler::Default {
            match sig.default_action() {
                SignalDefault::Terminate | SignalDefault::CoreDump => {
                    posix_exit(128 + signum as i32);
                }
                SignalDefault::Ignore | SignalDefault::Stop | SignalDefault::Continue => {
                    return 0;
                }
            }
        }

        // If handler is Ignore, do nothing
        if action.handler_type == SignalHandler::Ignore {
            return 0;
        }

        // Queue the signal for delivery on next syscall return
        let info = SigInfo {
            signo: signum as u8,
            code: SigCode::User,
            _pad0: [0; 2],
            pid: rux_proc::id::Pid(1),
            uid: rux_proc::id::Uid(0),
            _pad1: [0; 4],
            addr: 0,
            status: 0,
            _pad2: [0; 4],
        };
        let _ = cold.send_standard(hot, sig, &info);
    }
    0
}

/// Internal exit helper (avoids circular naming with posix::exit).
fn posix_exit(status: i32) -> ! {
    super::posix::exit(status);
    loop {}
}

