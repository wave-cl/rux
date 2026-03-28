#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_sched::entity::SchedEntity;
use rux_sched::fair::cfs::CfsClass;
use rux_sched::fair::constants::WF_FORK;
use rux_sched::fair::rbtree::verify;
use rux_sched::{SchedClassOps, TaskState};

const MAX_ENTITIES: usize = 16;
const CPU: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq)]
enum EntityState {
    Unborn,
    Forked,
    Enqueued,
    Running,
    Dead,
}

#[derive(Debug, Arbitrary)]
enum SchedOp {
    Fork { id: u8, nice: i8 },
    Enqueue { id: u8, flags: u8 },
    Dequeue { id: u8 },
    PickNext,
    SetNext { id: u8 },
    PutPrev { id: u8 },
    Tick { clock_delta: u16 },
    PrioChanged { id: u8, new_nice: i8 },
    Dead { id: u8 },
    AdvanceClock { delta_ns: u16 },
}

fuzz_target!(|ops: Vec<SchedOp>| {
    if ops.len() > 256 {
        return;
    }

    let mut cfs = CfsClass::new();
    let mut entities: [SchedEntity; MAX_ENTITIES] = core::array::from_fn(|i| {
        SchedEntity::new(i as u64)
    });
    let mut states = [EntityState::Unborn; MAX_ENTITIES];
    let mut clock: u64 = 0;
    let mut prev_min_vruntime: u64 = 0;

    cfs.set_clock(CPU, clock);

    for op in &ops {
        match op {
            SchedOp::Fork { id, nice } => {
                let idx = (*id as usize) % MAX_ENTITIES;
                if states[idx] != EntityState::Unborn {
                    continue;
                }
                entities[idx].nice = (*nice).clamp(-20, 19);
                entities[idx].cpu = CPU;
                cfs.task_fork(&mut entities[idx]);
                states[idx] = EntityState::Forked;
            }
            SchedOp::Enqueue { id, flags } => {
                let idx = (*id as usize) % MAX_ENTITIES;
                if states[idx] != EntityState::Forked {
                    continue;
                }
                let wake_flags = if *flags & 1 != 0 { WF_FORK } else { 0 };
                cfs.enqueue(CPU, &mut entities[idx], wake_flags);
                states[idx] = EntityState::Enqueued;
            }
            SchedOp::Dequeue { id } => {
                let idx = (*id as usize) % MAX_ENTITIES;
                if states[idx] != EntityState::Enqueued {
                    continue;
                }
                cfs.dequeue(CPU, &mut entities[idx], 0);
                states[idx] = EntityState::Forked; // can re-enqueue
            }
            SchedOp::PickNext => {
                // Need a prev entity
                let mut prev = SchedEntity::new(999);
                prev.state = TaskState::Interruptible;
                let _ = cfs.pick_next(CPU, &mut prev);
            }
            SchedOp::SetNext { id } => {
                let idx = (*id as usize) % MAX_ENTITIES;
                if states[idx] != EntityState::Enqueued {
                    continue;
                }
                // Only one entity can be Running at a time
                if states.iter().any(|s| *s == EntityState::Running) {
                    continue;
                }
                cfs.set_next(CPU, &mut entities[idx]);
                states[idx] = EntityState::Running;
            }
            SchedOp::PutPrev { id } => {
                let idx = (*id as usize) % MAX_ENTITIES;
                if states[idx] != EntityState::Running {
                    continue;
                }
                cfs.put_prev(CPU, &mut entities[idx]);
                states[idx] = if entities[idx].on_rq != 0 {
                    EntityState::Enqueued
                } else {
                    EntityState::Forked
                };
            }
            SchedOp::Tick { clock_delta } => {
                let delta = (*clock_delta as u64).saturating_add(1) * 100_000; // 0.1ms-6.5ms
                clock = clock.saturating_add(delta);
                cfs.set_clock(CPU, clock);
                // Find the running entity
                if let Some(idx) = states.iter().position(|s| *s == EntityState::Running) {
                    let _ = cfs.task_tick(CPU, &mut entities[idx]);
                }
            }
            SchedOp::PrioChanged { id, new_nice } => {
                let idx = (*id as usize) % MAX_ENTITIES;
                if states[idx] != EntityState::Enqueued && states[idx] != EntityState::Running {
                    continue;
                }
                let old_nice = entities[idx].nice as i32;
                entities[idx].nice = (*new_nice).clamp(-20, 19);
                cfs.prio_changed(CPU, &mut entities[idx], old_nice);
            }
            SchedOp::Dead { id } => {
                let idx = (*id as usize) % MAX_ENTITIES;
                if states[idx] == EntityState::Unborn || states[idx] == EntityState::Dead {
                    continue;
                }
                if states[idx] == EntityState::Running {
                    continue; // must put_prev first
                }
                cfs.task_dead(&mut entities[idx]);
                states[idx] = EntityState::Dead;
            }
            SchedOp::AdvanceClock { delta_ns } => {
                let delta = *delta_ns as u64 * 1000; // 0-65ms
                clock = clock.saturating_add(delta);
                cfs.set_clock(CPU, clock);
            }
        }

        // ── Invariant checks after every operation ──
        let rq = &cfs.rqs[CPU as usize];

        // 1. nr_running matches actual on_rq count (excluding curr)
        let on_rq_count: u32 = entities[..MAX_ENTITIES]
            .iter()
            .filter(|e| e.on_rq != 0)
            .count() as u32;
        assert_eq!(
            rq.nr_running, on_rq_count,
            "nr_running {} != on_rq count {}",
            rq.nr_running, on_rq_count
        );

        // 2. total_weight matches sum of on_rq weights
        let weight_sum: u64 = entities[..MAX_ENTITIES]
            .iter()
            .filter(|e| e.on_rq != 0)
            .map(|e| e.weight as u64)
            .sum();
        assert_eq!(
            rq.total_weight, weight_sum,
            "total_weight {} != weight sum {}",
            rq.total_weight, weight_sum
        );

        // 3. min_vruntime never decreases
        let current_min = rq.min_vruntime;
        assert!(
            current_min >= prev_min_vruntime,
            "min_vruntime went backwards: {} < {}",
            current_min, prev_min_vruntime
        );
        prev_min_vruntime = current_min;

        // 4. No dead entity is on_rq
        for i in 0..MAX_ENTITIES {
            if states[i] == EntityState::Dead {
                assert_eq!(entities[i].on_rq, 0, "dead entity {} still on_rq", i);
            }
        }

        // 5. RB-tree structural validity
        unsafe {
            assert!(verify::check_all(rq.timeline.root), "tree invariant violated");
        }
    }
});
