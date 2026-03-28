/// Generic tests that exercise the `SchedClassOps<SchedEntity>` interface.
/// Each test is parameterized: run once for CfsClass, once for EevdfClass.
use crate::class::SchedClassOps;
use crate::entity::SchedEntity;
use crate::{SchedPolicy, TaskState, CpuMask};
use super::cfs::CfsClass;
use super::eevdf::EevdfClass;
use super::constants::WF_FORK;

// ── Test helpers ─────────────────────────────────────────────────────────

fn make_entity(id: u64) -> SchedEntity {
    SchedEntity::new(id)
}

fn test_enqueue_dequeue<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut e1 = make_entity(1);
    let mut e2 = make_entity(2);
    class.enqueue(0, &mut e1, WF_FORK);
    class.enqueue(0, &mut e2, WF_FORK);
    assert_eq!(e1.on_rq, 1);
    assert_eq!(e2.on_rq, 1);
    assert_eq!(e1.state, TaskState::Ready);
    class.dequeue(0, &mut e1, 0);
    assert_eq!(e1.on_rq, 0);
}

fn test_pick_next_returns_something<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut e1 = make_entity(1);
    let mut e2 = make_entity(2);
    class.enqueue(0, &mut e1, WF_FORK);
    class.enqueue(0, &mut e2, WF_FORK);
    let mut prev = make_entity(99);
    prev.state = TaskState::Interruptible; // not runnable
    let picked = class.pick_next(0, &mut prev);
    assert!(picked.is_some());
}

fn test_pick_next_empty<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut prev = make_entity(99);
    prev.state = TaskState::Interruptible;
    let picked = class.pick_next(0, &mut prev);
    assert!(picked.is_none());
}

fn test_task_fork_initializes<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut task = make_entity(1);
    task.cpu = 0;
    class.task_fork(&mut task);
    assert_eq!(task.vlag, 0);
    assert!(task.slice > 0);
    assert!(task.vdeadline > 0 || task.vruntime == 0);
    assert!(task.rb_left.is_null());
    assert!(task.rb_right.is_null());
    assert_eq!(task.on_rq, 0);
}

fn test_task_dead_cleans_up<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut task = make_entity(1);
    class.enqueue(0, &mut task, WF_FORK);
    assert_eq!(task.on_rq, 1);
    class.task_dead(&mut task);
    assert_eq!(task.on_rq, 0);
    assert_eq!(task.state, TaskState::Dead);
}

fn test_select_cpu_respects_affinity<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut task = make_entity(1);
    task.cpus_allowed = CpuMask::single(3).0; // only CPU 3
    task.nr_cpus_allowed = 1;
    let cpu = class.select_cpu(&task, 0, 0);
    assert_eq!(cpu, 3);
}

fn test_task_is_migratable<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut task = make_entity(1);
    task.cpus_allowed = CpuMask::single(0).0;
    task.nr_cpus_allowed = 1;
    assert!(!class.task_is_migratable(&task, 1));

    task.cpus_allowed = CpuMask::ALL.0;
    task.nr_cpus_allowed = 64;
    assert!(class.task_is_migratable(&task, 5));
}

fn test_check_preempt_batch_never<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut curr = make_entity(1);
    curr.policy = SchedPolicy::Normal;
    curr.vruntime = 1000;
    curr.vdeadline = 2000;
    curr.exec_start = 0;
    let mut new = make_entity(2);
    new.policy = SchedPolicy::Batch;
    new.vruntime = 100;
    new.vdeadline = 200;
    assert!(!class.check_preempt(0, &curr, &new));
}

fn test_set_next_put_prev_cycle<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut task = make_entity(1);
    class.enqueue(0, &mut task, WF_FORK);

    let mut prev = make_entity(99);
    prev.state = TaskState::Interruptible;
    let picked = class.pick_next(0, &mut prev);
    assert!(picked.is_some());

    class.set_next(0, &mut task);
    assert_eq!(task.state, TaskState::Running);
    assert_eq!(task.on_rq, 0); // removed from tree

    class.put_prev(0, &mut task);
    assert_eq!(task.state, TaskState::Ready);
    assert_eq!(task.on_rq, 1); // back in tree
}

fn test_full_lifecycle<C: SchedClassOps<SchedEntity>>(class: &mut C) {
    let mut task = make_entity(1);
    task.cpu = 0;

    // Fork
    class.task_fork(&mut task);
    assert_eq!(task.on_rq, 0);

    // Enqueue
    class.enqueue(0, &mut task, WF_FORK);
    assert_eq!(task.on_rq, 1);

    // Pick + set_next
    let mut prev = make_entity(99);
    prev.state = TaskState::Interruptible;
    let _ = class.pick_next(0, &mut prev);
    class.set_next(0, &mut task);
    assert_eq!(task.state, TaskState::Running);

    // Put_prev
    class.put_prev(0, &mut task);
    assert_eq!(task.state, TaskState::Ready);

    // Dequeue
    class.dequeue(0, &mut task, 0);
    assert_eq!(task.on_rq, 0);

    // Dead
    class.task_dead(&mut task);
    assert_eq!(task.state, TaskState::Dead);
}

// ── Instantiate for both CFS and EEVDF ──────────────────────────────────

#[test] fn cfs_enqueue_dequeue() { test_enqueue_dequeue(&mut CfsClass::new()); }
#[test] fn eevdf_enqueue_dequeue() { test_enqueue_dequeue(&mut EevdfClass::new()); }

#[test] fn cfs_pick_next_returns_something() { test_pick_next_returns_something(&mut CfsClass::new()); }
#[test] fn eevdf_pick_next_returns_something() { test_pick_next_returns_something(&mut EevdfClass::new()); }

#[test] fn cfs_pick_next_empty() { test_pick_next_empty(&mut CfsClass::new()); }
#[test] fn eevdf_pick_next_empty() { test_pick_next_empty(&mut EevdfClass::new()); }

#[test] fn cfs_task_fork_initializes() { test_task_fork_initializes(&mut CfsClass::new()); }
#[test] fn eevdf_task_fork_initializes() { test_task_fork_initializes(&mut EevdfClass::new()); }

#[test] fn cfs_task_dead_cleans_up() { test_task_dead_cleans_up(&mut CfsClass::new()); }
#[test] fn eevdf_task_dead_cleans_up() { test_task_dead_cleans_up(&mut EevdfClass::new()); }

#[test] fn cfs_select_cpu_affinity() { test_select_cpu_respects_affinity(&mut CfsClass::new()); }
#[test] fn eevdf_select_cpu_affinity() { test_select_cpu_respects_affinity(&mut EevdfClass::new()); }

#[test] fn cfs_task_is_migratable() { test_task_is_migratable(&mut CfsClass::new()); }
#[test] fn eevdf_task_is_migratable() { test_task_is_migratable(&mut EevdfClass::new()); }

#[test] fn cfs_check_preempt_batch() { test_check_preempt_batch_never(&mut CfsClass::new()); }
#[test] fn eevdf_check_preempt_batch() { test_check_preempt_batch_never(&mut EevdfClass::new()); }

#[test] fn cfs_set_next_put_prev() { test_set_next_put_prev_cycle(&mut CfsClass::new()); }
#[test] fn eevdf_set_next_put_prev() { test_set_next_put_prev_cycle(&mut EevdfClass::new()); }

#[test] fn cfs_full_lifecycle() { test_full_lifecycle(&mut CfsClass::new()); }
#[test] fn eevdf_full_lifecycle() { test_full_lifecycle(&mut EevdfClass::new()); }
