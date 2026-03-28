#![feature(test)]
extern crate test;

use rux_proc::id::{Pid, Tgid, Uid, Gid};
use rux_proc::fd::{FdTable, FdOps, FD_CLOEXEC};
use rux_proc::signal::{
    Signal, SignalHot, SignalCold, SigInfo, SigCode, SigQueue, MAX_PENDING_SIGNALS,
};
use rux_proc::creds::Credentials;
use rux_proc::rlimit::{ResourceLimits, RlimitResource};
use rux_proc::task::Task;
use test::Bencher;

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

// ── FdTable benchmarks ──────────────────────────────────────────────────

#[bench]
fn bench_fd_open_close_cycle(b: &mut Bencher) {
    b.iter(|| {
        let mut t = Box::new(FdTable::new());
        for i in 0..256u64 {
            t.open(i + 1, 0).unwrap();
        }
        for i in 0..256i32 {
            t.close(i).unwrap();
        }
        test::black_box(&t);
    });
}

#[bench]
fn bench_fd_dup(b: &mut Bencher) {
    let mut t = Box::new(FdTable::new());
    for i in 0..128u64 {
        t.open(i + 1, 0).unwrap();
    }
    b.iter(|| {
        let fd = t.dup(0).unwrap();
        t.close(fd).unwrap();
        test::black_box(fd);
    });
}

#[bench]
fn bench_fd_get(b: &mut Bencher) {
    let mut t = Box::new(FdTable::new());
    for i in 0..128u64 {
        t.open(i + 1, 0).unwrap();
    }
    b.iter(|| {
        test::black_box(t.get(64).unwrap());
    });
}

#[bench]
fn bench_fd_close_on_exec(b: &mut Bencher) {
    b.iter(|| {
        let mut t = Box::new(FdTable::new());
        for i in 0..128u64 {
            let fd = t.open(i + 1, 0).unwrap();
            if i % 2 == 0 {
                t.get_mut(fd).unwrap().fd_flags = FD_CLOEXEC;
            }
        }
        t.close_on_exec();
        test::black_box(t.count);
    });
}

// ── SigQueue benchmarks ────────────────────────────────────────────────

#[bench]
fn bench_sigqueue_enqueue(b: &mut Bencher) {
    b.iter(|| {
        let mut q = Box::new(SigQueue::new());
        for i in 0..MAX_PENDING_SIGNALS {
            q.enqueue(make_siginfo((i % 33 + 32) as u8));
        }
        test::black_box(q.count);
    });
}

#[bench]
fn bench_sigqueue_dequeue(b: &mut Bencher) {
    let mut q = Box::new(SigQueue::new());
    for i in 0..MAX_PENDING_SIGNALS {
        q.enqueue(make_siginfo((i % 33 + 32) as u8));
    }
    b.iter(|| {
        // Refill then drain
        let mut local = Box::new(SigQueue::new());
        for i in 0..MAX_PENDING_SIGNALS {
            local.enqueue(make_siginfo((i % 33 + 32) as u8));
        }
        while local.dequeue().is_some() {}
        test::black_box(local.count);
    });
}

#[bench]
fn bench_sigqueue_enqueue_dequeue_cycle(b: &mut Bencher) {
    let mut q = Box::new(SigQueue::new());
    // Pre-fill half
    for i in 0..MAX_PENDING_SIGNALS / 2 {
        q.enqueue(make_siginfo((i % 33 + 32) as u8));
    }
    b.iter(|| {
        q.enqueue(make_siginfo(34));
        test::black_box(q.dequeue());
    });
}

// ── Signal hot path benchmarks ─────────────────────────────────────────

#[bench]
fn bench_has_deliverable(b: &mut Bencher) {
    let mut hot = SignalHot::new();
    hot.pending = hot.pending.add(Signal::Int as u8);
    hot.pending = hot.pending.add(Signal::Term as u8);
    hot.blocked = hot.blocked.add(Signal::Int as u8);
    b.iter(|| {
        test::black_box(hot.has_deliverable());
    });
}

#[bench]
fn bench_next_deliverable(b: &mut Bencher) {
    let mut hot = SignalHot::new();
    hot.pending = hot.pending.add(Signal::Int as u8);
    hot.pending = hot.pending.add(Signal::Term as u8);
    hot.pending = hot.pending.add(Signal::Alrm as u8);
    b.iter(|| {
        test::black_box(hot.next_deliverable());
    });
}

#[bench]
fn bench_send_standard(b: &mut Bencher) {
    let mut cold = Box::new(SignalCold::new());
    let mut hot = SignalHot::new();
    let info = make_siginfo(Signal::Int as u8);
    b.iter(|| {
        cold.send_standard(&mut hot, Signal::Int, &info).unwrap();
        test::black_box(hot.pending);
    });
}

#[bench]
fn bench_dequeue_signal(b: &mut Bencher) {
    let mut cold = Box::new(SignalCold::new());
    let mut hot = SignalHot::new();
    b.iter(|| {
        // Set up a pending signal then dequeue it
        hot.pending = hot.pending.add(Signal::Int as u8);
        let result = cold.dequeue_signal(&mut hot);
        test::black_box(result);
    });
}

// ── Credential benchmarks ──────────────────────────────────────────────

#[bench]
fn bench_can_signal(b: &mut Bencher) {
    let sender = Credentials::user(Uid(1000), Gid(1000));
    let target = Credentials::user(Uid(1000), Gid(2000));
    b.iter(|| {
        test::black_box(sender.can_signal(&target));
    });
}

#[bench]
fn bench_can_access_owner(b: &mut Bencher) {
    let user = Credentials::user(Uid(1000), Gid(1000));
    b.iter(|| {
        test::black_box(user.can_access(Uid(1000), Gid(9999), 0o644, 4));
    });
}

#[bench]
fn bench_can_access_supplementary_scan(b: &mut Bencher) {
    let mut user = Credentials::user(Uid(1000), Gid(1000));
    // Fill all 32 supplementary groups — worst case scan (no match)
    for i in 0..32 {
        user.add_group(Gid(2000 + i)).unwrap();
    }
    b.iter(|| {
        // Check against a group NOT in the list — forces full scan
        test::black_box(user.can_access(Uid(9999), Gid(9999), 0o070, 4));
    });
}

#[bench]
fn bench_has_cap(b: &mut Bencher) {
    let creds = Credentials::ROOT;
    b.iter(|| {
        test::black_box(creds.has_cap(21)); // CAP_SYS_ADMIN
    });
}

// ── ResourceLimits benchmarks ──────────────────────────────────────────

#[bench]
fn bench_rlimit_check(b: &mut Bencher) {
    let rl = ResourceLimits::DEFAULT;
    b.iter(|| {
        test::black_box(rl.check(RlimitResource::Nofile, 100));
    });
}

// ── Task benchmarks ────────────────────────────────────────────────────

#[bench]
fn bench_task_new(b: &mut Bencher) {
    b.iter(|| {
        let task = Task::new(Pid(1), Tgid(1));
        test::black_box(&task);
    });
}
