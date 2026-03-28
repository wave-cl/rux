#![feature(test)]
extern crate test;

use rux_sched::entity::SchedEntity;
use rux_sched::fair::cfs::CfsClass;
use rux_sched::fair::eevdf::EevdfClass;
use rux_sched::fair::rbtree::FairTimeline;
use rux_sched::fair::constants::WF_FORK;
use rux_sched::{SchedClassOps, TaskState};
use test::Bencher;

fn make_entity(id: u64, vruntime: u64, vdeadline: u64) -> SchedEntity {
    let mut se = SchedEntity::new(id);
    se.vruntime = vruntime;
    se.vdeadline = vdeadline;
    se.rb_min_vdeadline = vdeadline;
    se
}

// ── RB-tree benchmarks ──────────────────────────────────────────────────

#[bench]
fn bench_rbtree_insert_1000(b: &mut Bencher) {
    b.iter(|| {
        let mut tree = FairTimeline::new();
        let mut entities: Vec<SchedEntity> = (0..1000)
            .map(|i| make_entity(i, i * 100, i * 200 + 50))
            .collect();
        for e in entities.iter_mut() {
            unsafe { tree.insert(e); }
        }
        // Prevent optimization
        test::black_box(&tree);
        // Cleanup: remove all to avoid dangling pointers
        for e in entities.iter_mut() {
            unsafe { tree.remove(e); }
        }
    });
}

#[bench]
fn bench_rbtree_remove_1000(b: &mut Bencher) {
    let mut entities: Vec<SchedEntity> = (0..1000)
        .map(|i| make_entity(i, i * 100, i * 200 + 50))
        .collect();
    b.iter(|| {
        let mut tree = FairTimeline::new();
        for e in entities.iter_mut() {
            unsafe { tree.insert(e); }
        }
        for e in entities.iter_mut() {
            unsafe { tree.remove(e); }
        }
        test::black_box(&tree);
    });
}

#[bench]
fn bench_rbtree_pick_eevdf_100(b: &mut Bencher) {
    let mut entities: Vec<SchedEntity> = (0..100)
        .map(|i| make_entity(i, i * 100, (100 - i) * 50 + 10))
        .collect();
    let mut tree = FairTimeline::new();
    for e in entities.iter_mut() {
        unsafe { tree.insert(e); }
    }
    let avg_vrt = 5000; // ~half eligible

    b.iter(|| {
        test::black_box(tree.pick_eevdf(avg_vrt));
    });

    for e in entities.iter_mut() {
        unsafe { tree.remove(e); }
    }
}

#[bench]
fn bench_rbtree_leftmost_100(b: &mut Bencher) {
    let mut entities: Vec<SchedEntity> = (0..100)
        .map(|i| make_entity(i, i * 100 + 1, i * 200))
        .collect();
    let mut tree = FairTimeline::new();
    for e in entities.iter_mut() {
        unsafe { tree.insert(e); }
    }

    b.iter(|| {
        test::black_box(tree.leftmost());
    });

    for e in entities.iter_mut() {
        unsafe { tree.remove(e); }
    }
}

// ── CFS benchmarks ──────────────────────────────────────────────────────

#[bench]
fn bench_cfs_enqueue_dequeue_100(b: &mut Bencher) {
    b.iter(|| {
        let mut cfs = CfsClass::new();
        cfs.set_clock(0, 0);
        let mut entities: Vec<SchedEntity> = (0..100)
            .map(|i| SchedEntity::new(i))
            .collect();
        for e in entities.iter_mut() {
            cfs.enqueue(0, e, WF_FORK);
        }
        for e in entities.iter_mut() {
            cfs.dequeue(0, e, 0);
        }
        test::black_box(&cfs);
    });
}

#[bench]
fn bench_cfs_pick_next_100(b: &mut Bencher) {
    let mut cfs = CfsClass::new();
    cfs.set_clock(0, 0);
    let mut entities: Vec<SchedEntity> = (0..100)
        .map(|i| SchedEntity::new(i))
        .collect();
    for e in entities.iter_mut() {
        cfs.enqueue(0, e, WF_FORK);
    }
    let mut prev = SchedEntity::new(999);
    prev.state = TaskState::Interruptible;

    b.iter(|| {
        test::black_box(cfs.pick_next(0, &mut prev));
    });

    for e in entities.iter_mut() {
        cfs.dequeue(0, e, 0);
    }
}

// ── EEVDF benchmarks ────────────────────────────────────────────────────

#[bench]
fn bench_eevdf_enqueue_dequeue_100(b: &mut Bencher) {
    b.iter(|| {
        let mut eevdf = EevdfClass::new();
        eevdf.set_clock(0, 0);
        let mut entities: Vec<SchedEntity> = (0..100)
            .map(|i| SchedEntity::new(i))
            .collect();
        for e in entities.iter_mut() {
            eevdf.enqueue(0, e, WF_FORK);
        }
        for e in entities.iter_mut() {
            eevdf.dequeue(0, e, 0);
        }
        test::black_box(&eevdf);
    });
}

#[bench]
fn bench_eevdf_pick_next_100(b: &mut Bencher) {
    let mut eevdf = EevdfClass::new();
    eevdf.set_clock(0, 0);
    let mut entities: Vec<SchedEntity> = (0..100)
        .map(|i| SchedEntity::new(i))
        .collect();
    for e in entities.iter_mut() {
        eevdf.enqueue(0, e, WF_FORK);
    }
    let mut prev = SchedEntity::new(999);
    prev.state = TaskState::Interruptible;

    b.iter(|| {
        test::black_box(eevdf.pick_next(0, &mut prev));
    });

    for e in entities.iter_mut() {
        eevdf.dequeue(0, e, 0);
    }
}

// ── update_curr hot path ────────────────────────────────────────────────

#[bench]
fn bench_update_curr(b: &mut Bencher) {
    use rux_sched::fair::runqueue::FairRunQueue;
    let mut rq = FairRunQueue::new();
    let mut se = SchedEntity::new(1);
    se.exec_start = 0;
    se.weight = 1024;
    rq.set_curr(&mut se);
    let mut clock = 1_000_000u64;

    b.iter(|| {
        rq.set_clock(clock);
        unsafe { rq.update_curr(); }
        clock += 1_000_000;
        test::black_box(se.vruntime);
    });
}
