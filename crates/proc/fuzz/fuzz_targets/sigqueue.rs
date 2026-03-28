#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_proc::id::{Pid, Uid};
use rux_proc::signal::{SigInfo, SigCode, SigQueue, MAX_PENDING_SIGNALS};

#[derive(Debug, Arbitrary)]
enum QueueOp {
    Enqueue { signo: u8 },
    Dequeue,
    Peek,
    Clear,
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

fuzz_target!(|ops: Vec<QueueOp>| {
    if ops.len() > 1024 {
        return;
    }

    let mut q = Box::new(SigQueue::new());
    // Shadow tracking: simple Vec to verify FIFO order
    let mut shadow: Vec<u8> = Vec::new();

    for op in &ops {
        match op {
            QueueOp::Enqueue { signo } => {
                let ok = q.enqueue(make_siginfo(*signo));
                if shadow.len() < MAX_PENDING_SIGNALS {
                    assert!(ok, "enqueue should succeed when not full");
                    shadow.push(*signo);
                } else {
                    assert!(!ok, "enqueue should fail when full");
                }
            }
            QueueOp::Dequeue => {
                let result = q.dequeue();
                if shadow.is_empty() {
                    assert!(result.is_none(), "dequeue should return None when empty");
                } else {
                    let expected = shadow.remove(0);
                    let info = result.expect("dequeue should return Some when non-empty");
                    assert_eq!(
                        info.signo, expected,
                        "FIFO violation: got signo {}, expected {}",
                        info.signo, expected
                    );
                }
            }
            QueueOp::Peek => {
                let result = q.peek();
                if shadow.is_empty() {
                    assert!(result.is_none(), "peek should return None when empty");
                } else {
                    let info = result.expect("peek should return Some when non-empty");
                    assert_eq!(
                        info.signo, shadow[0],
                        "peek should show head element"
                    );
                }
            }
            QueueOp::Clear => {
                q.clear();
                shadow.clear();
            }
        }

        // ── Invariant: count matches shadow length ──
        assert_eq!(
            q.count as usize, shadow.len(),
            "count {} != shadow len {}",
            q.count, shadow.len()
        );

        // ── Invariant: is_empty matches ──
        assert_eq!(q.is_empty(), shadow.is_empty());

        // ── Invariant: is_full matches ──
        assert_eq!(q.is_full(), shadow.len() >= MAX_PENDING_SIGNALS);
    }
});
