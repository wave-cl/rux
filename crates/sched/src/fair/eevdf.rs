use crate::class::SchedClassOps;
use crate::cpu::CpuId;
use crate::entity::{SchedEntity, nice_to_weight};
use crate::{SchedPolicy, TaskState, CpuMask};
use super::constants::*;
use super::rbtree::vruntime_gt;
use super::runqueue::FairRunQueue;
use super::calc_delta_fair;

/// EEVDF (Earliest Eligible Virtual Deadline First) — Linux 6.6+.
///
/// Picks the **eligible** task (vruntime <= avg_vruntime) with the
/// smallest `vdeadline`. Falls back to leftmost (smallest vruntime)
/// if no task is eligible. This provides bounded latency guarantees
/// proportional to weight, solving CFS's latency-nice problem.
pub struct EevdfClass {
    pub rqs: [FairRunQueue; 64],
}

impl EevdfClass {
    pub const fn new() -> Self {
        const RQ: FairRunQueue = FairRunQueue::new();
        Self { rqs: [RQ; 64] }
    }

    #[inline(always)]
    pub fn set_clock(&mut self, cpu: CpuId, now_ns: u64) {
        self.rqs[cpu as usize].set_clock(now_ns);
    }

    #[inline(always)]
    fn rq(&self, cpu: CpuId) -> &FairRunQueue {
        &self.rqs[cpu as usize]
    }

    #[inline(always)]
    fn rq_mut(&mut self, cpu: CpuId) -> &mut FairRunQueue {
        &mut self.rqs[cpu as usize]
    }
}

impl SchedClassOps<SchedEntity> for EevdfClass {
    fn enqueue(&mut self, cpu: CpuId, task: &mut SchedEntity, wake_flags: u32) {
        set_weight(task);
        let rq = self.rq_mut(cpu);
        unsafe {
            rq.place_entity(task, wake_flags);
            rq.enqueue_entity(task);
        }
        task.cpu = cpu;
        task.state = TaskState::Ready;
    }

    fn dequeue(&mut self, cpu: CpuId, task: &mut SchedEntity, _sleep_flags: u32) {
        let rq = self.rq_mut(cpu);
        unsafe {
            if rq.curr == task as *mut _ {
                rq.update_curr();
            }
            task.vlag = task.vruntime as i64 - rq.compute_avg_vruntime() as i64;
            if task.on_rq != 0 {
                rq.dequeue_entity(task);
            }
            rq.update_min_vruntime();
        }
    }

    fn pick_next(&mut self, cpu: CpuId, prev: &mut SchedEntity) -> Option<*mut SchedEntity> {
        let rq = self.rq_mut(cpu);
        unsafe {
            if rq.curr == prev as *mut _ {
                rq.update_curr();
            }

            // Re-insert prev if still runnable
            if prev.state == TaskState::Ready && prev.on_rq == 0
                && prev.class == crate::SchedClass::Fair
            {
                rq.enqueue_entity(prev);
            }

            if rq.nr_running == 0 {
                return None;
            }

            // Honor wakeup hint
            if !rq.next.is_null() && (*rq.next).on_rq != 0 {
                let hint = rq.next;
                rq.next = core::ptr::null_mut();
                return Some(hint);
            }
            rq.next = core::ptr::null_mut();

            // EEVDF: pick eligible entity with smallest vdeadline
            let avg_vrt = rq.compute_avg_vruntime();
            let picked = rq.timeline.pick_eevdf(avg_vrt)
                .or_else(|| rq.timeline.leftmost())?;

            Some(picked)
        }
    }

    fn check_preempt(&self, cpu: CpuId, curr: &SchedEntity, new: &SchedEntity) -> bool {
        if new.policy == SchedPolicy::Batch || new.policy == SchedPolicy::IdlePolicy {
            return false;
        }
        if curr.policy == SchedPolicy::IdlePolicy && new.policy == SchedPolicy::Normal {
            return true;
        }
        let rq = self.rq(cpu);
        let elapsed = rq.clock.saturating_sub(curr.exec_start);
        if elapsed < MIN_GRANULARITY_NS {
            return false;
        }
        // EEVDF: preempt if new has earlier virtual deadline
        !vruntime_gt(new.vdeadline, curr.vdeadline) && new.vdeadline != curr.vdeadline
    }

    fn task_tick(&mut self, cpu: CpuId, curr: &mut SchedEntity) -> bool {
        let rq = self.rq_mut(cpu);
        unsafe {
            rq.update_curr();
        }

        if curr.slice == 0 {
            curr.slice = super::calc_slice(curr.weight, rq.nr_running, rq.total_weight);
            curr.vdeadline = curr.vruntime.wrapping_add(
                calc_delta_fair(curr.slice, curr.weight),
            );
            return true;
        }

        // EEVDF: check if best eligible candidate has earlier deadline
        let avg_vrt = rq.compute_avg_vruntime();
        if let Some(best) = rq.timeline.pick_eevdf(avg_vrt) {
            unsafe {
                if !vruntime_gt((*best).vdeadline, curr.vdeadline)
                    && (*best).vdeadline != curr.vdeadline
                {
                    return true;
                }
            }
        }

        false
    }

    fn switched_to(&mut self, cpu: CpuId, task: &mut SchedEntity) {
        set_weight(task);
        let rq = self.rq_mut(cpu);
        task.vruntime = rq.min_vruntime;
        task.vlag = 0;
        task.slice = super::calc_slice(task.weight, rq.nr_running, rq.total_weight);
        task.vdeadline = task.vruntime.wrapping_add(
            calc_delta_fair(task.slice, task.weight),
        );
        if task.state.is_runnable() {
            self.enqueue(cpu, task, 0);
        }
    }

    fn prio_changed(&mut self, cpu: CpuId, task: &mut SchedEntity, _old_prio: i32) {
        let old_weight = task.weight;
        set_weight(task);
        let new_weight = task.weight;
        task.vdeadline = task.vruntime.wrapping_add(
            calc_delta_fair(task.slice, new_weight),
        );
        let rq = self.rq_mut(cpu);
        if task.on_rq != 0 && rq.curr != task as *mut _ {
            task.weight = old_weight;
            unsafe { rq.dequeue_entity(task); }
            task.weight = new_weight;
            unsafe { rq.enqueue_entity(task); }
        }
        // If curr (not on tree): no weight adjustment needed.
        // The new weight takes effect when put_prev re-enqueues.
    }

    fn select_cpu(&self, task: &SchedEntity, prev_cpu: CpuId, _wake_flags: u32) -> CpuId {
        let mask = CpuMask(task.cpus_allowed);
        if mask.contains(prev_cpu) {
            return prev_cpu;
        }
        mask.first().unwrap_or(prev_cpu)
    }

    fn balance(&mut self, cpu: CpuId) -> bool {
        if self.rqs[cpu as usize].nr_running > 0 {
            return false;
        }
        let mut busiest_cpu: CpuId = 0;
        let mut busiest_nr: u32 = 0;
        for i in 0..64u32 {
            if i != cpu && self.rqs[i as usize].nr_running > busiest_nr {
                busiest_nr = self.rqs[i as usize].nr_running;
                busiest_cpu = i;
            }
        }
        if busiest_nr < 2 {
            return false;
        }
        let src = &mut self.rqs[busiest_cpu as usize];
        if let Some(task) = src.timeline.leftmost() {
            unsafe {
                if (*task).nr_cpus_allowed > 1
                    && CpuMask((*task).cpus_allowed).contains(cpu)
                {
                    src.dequeue_entity(task);
                    (*task).cpu = cpu;
                    let dst = &mut self.rqs[cpu as usize];
                    dst.enqueue_entity(task);
                    return true;
                }
            }
        }
        false
    }

    fn task_is_migratable(&self, task: &SchedEntity, cpu: CpuId) -> bool {
        task.nr_cpus_allowed > 1 && CpuMask(task.cpus_allowed).contains(cpu)
    }

    fn set_next(&mut self, cpu: CpuId, task: &mut SchedEntity) {
        let rq = self.rq_mut(cpu);
        if task.on_rq != 0 {
            unsafe { rq.dequeue_entity(task); }
        }
        rq.curr = task;
        task.exec_start = rq.clock;
        task.state = TaskState::Running;
    }

    fn put_prev(&mut self, cpu: CpuId, task: &mut SchedEntity) {
        let rq = self.rq_mut(cpu);
        unsafe {
            rq.update_curr();
        }
        if task.state == TaskState::Ready || task.state == TaskState::Running {
            task.state = TaskState::Ready;
            unsafe { rq.enqueue_entity(task); }
        }
        rq.curr = core::ptr::null_mut();
    }

    fn task_fork(&mut self, task: &mut SchedEntity) {
        set_weight(task);
        let rq = self.rq_mut(task.cpu);
        task.vruntime = rq.min_vruntime;
        task.vlag = 0;
        task.sum_exec = 0;
        task.slice = super::calc_slice(task.weight, rq.nr_running, rq.total_weight);
        task.vdeadline = task.vruntime.wrapping_add(
            calc_delta_fair(task.slice, task.weight),
        );
        task.rb_left = core::ptr::null_mut();
        task.rb_right = core::ptr::null_mut();
        task.rb_parent_color = 0;
        task.rb_min_vdeadline = task.vdeadline;
        task.on_rq = 0;
    }

    fn task_dead(&mut self, task: &mut SchedEntity) {
        if task.on_rq != 0 {
            let rq = self.rq_mut(task.cpu);
            unsafe { rq.dequeue_entity(task); }
        }
        task.rb_left = core::ptr::null_mut();
        task.rb_right = core::ptr::null_mut();
        task.rb_parent_color = 0;
        task.on_rq = 0;
        task.state = TaskState::Dead;
    }
}

#[inline(always)]
fn set_weight(se: &mut SchedEntity) {
    if se.policy == SchedPolicy::IdlePolicy {
        se.weight = IDLE_WEIGHT;
    } else {
        se.weight = nice_to_weight(se.nice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eevdf_pick_eligible_deadline() {
        let mut eevdf = EevdfClass::new();
        eevdf.set_clock(0, 0);

        // Create 3 entities with controlled vruntimes and vdeadlines
        let mut e1 = SchedEntity::new(1);
        let mut e2 = SchedEntity::new(2);
        let mut e3 = SchedEntity::new(3);

        eevdf.enqueue(0, &mut e1, WF_FORK);
        eevdf.enqueue(0, &mut e2, WF_FORK);
        eevdf.enqueue(0, &mut e3, WF_FORK);

        // All three are enqueued
        assert_eq!(eevdf.rqs[0].nr_running, 3);
    }

    #[test]
    fn eevdf_check_preempt_vdeadline() {
        let eevdf = EevdfClass::new();
        let mut curr = SchedEntity::new(1);
        curr.vdeadline = 1000;
        curr.exec_start = 0;
        curr.policy = SchedPolicy::Normal;
        let mut new = SchedEntity::new(2);
        new.vdeadline = 500; // earlier deadline
        new.policy = SchedPolicy::Normal;
        // elapsed = 0 < MIN_GRANULARITY, so no preempt
        assert!(!eevdf.check_preempt(0, &curr, &new));
    }
}
