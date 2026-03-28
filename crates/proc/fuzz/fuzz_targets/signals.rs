#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_proc::id::{Pid, Uid};
use rux_proc::signal::{
    Signal, SignalAction, SignalHandler, SignalHot, SignalCold, SignalSet,
    SigInfo, SigCode, MAX_PENDING_SIGNALS,
};

#[derive(Debug, Arbitrary)]
enum SigOp {
    SendStandard { sig: u8 },
    SendRt { signo: u8 },
    DequeueSignal,
    Block { sig: u8 },
    Unblock { sig: u8 },
    SetAction { sig: u8, handler: u8 },
    CheckDeliverable,
}

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

fuzz_target!(|ops: Vec<SigOp>| {
    if ops.len() > 512 {
        return;
    }

    let mut hot = SignalHot::new();
    let mut cold = Box::new(SignalCold::new());

    for op in &ops {
        match op {
            SigOp::SendStandard { sig } => {
                let sig_num = (*sig % 31) + 1; // 1-31
                if let Some(signal) = Signal::from_raw(sig_num) {
                    let info = make_siginfo(sig_num);
                    let _ = cold.send_standard(&mut hot, signal, &info);
                }
            }
            SigOp::SendRt { signo } => {
                let signo = (*signo % 33) + 32; // 32-64
                let _ = cold.send_rt(&mut hot, signo, make_siginfo(signo));
            }
            SigOp::DequeueSignal => {
                let _ = cold.dequeue_signal(&mut hot);
            }
            SigOp::Block { sig } => {
                let sig_num = (*sig % 64) + 1; // 1-64
                hot.blocked = hot.blocked.add(sig_num);
                // SIGKILL (9) and SIGSTOP (19) cannot be blocked — strip them
                hot.blocked = hot.blocked.remove(9);
                hot.blocked = hot.blocked.remove(19);
            }
            SigOp::Unblock { sig } => {
                let sig_num = (*sig % 64) + 1;
                hot.blocked = hot.blocked.remove(sig_num);
            }
            SigOp::SetAction { sig, handler } => {
                let sig_num = (*sig % 31) + 1;
                if let Some(signal) = Signal::from_raw(sig_num) {
                    let action = SignalAction {
                        handler_type: if *handler % 3 == 0 {
                            SignalHandler::Default
                        } else if *handler % 3 == 1 {
                            SignalHandler::Ignore
                        } else {
                            SignalHandler::User
                        },
                        _pad0: [0; 7],
                        handler: 0x1000,
                        mask: SignalSet::EMPTY,
                        flags: 0,
                        _pad1: [0; 4],
                    };
                    let _ = cold.set_action(signal, action);
                }
            }
            SigOp::CheckDeliverable => {
                let _ = hot.has_deliverable();
                let _ = hot.next_deliverable();
            }
        }

        // ── Invariant: SIGKILL and SIGSTOP must never be in blocked mask ──
        assert!(
            !hot.blocked.contains(9),
            "SIGKILL (9) must never be blocked"
        );
        assert!(
            !hot.blocked.contains(19),
            "SIGSTOP (19) must never be blocked"
        );

        // ── Invariant: SIGKILL and SIGSTOP handlers must be Default ──
        assert_eq!(
            cold.get_action(Signal::Kill).handler_type as u8,
            SignalHandler::Default as u8,
            "SIGKILL handler must be Default"
        );
        assert_eq!(
            cold.get_action(Signal::Stop).handler_type as u8,
            SignalHandler::Default as u8,
            "SIGSTOP handler must be Default"
        );

        // ── Invariant: if next_deliverable returns Some(n), then
        //    pending.contains(n) && !blocked.contains(n) ──
        if let Some(n) = hot.next_deliverable() {
            assert!(
                hot.pending.contains(n),
                "next_deliverable {} not in pending",
                n
            );
            assert!(
                !hot.blocked.contains(n),
                "next_deliverable {} is blocked",
                n
            );
        }

        // ── Invariant: rt_queue count matches number of entries ──
        assert!(
            cold.rt_queue.count as usize <= MAX_PENDING_SIGNALS,
            "rt_queue count {} exceeds max",
            cold.rt_queue.count
        );
    }
});
