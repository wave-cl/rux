use crate::entity::SchedEntity;
use crate::SchedPolicy;
use super::constants::*;
use super::rbtree::FairTimeline;
use super::{calc_delta_fair, calc_slice};

/// Per-CPU fair scheduler runqueue state.
///
/// Shared by both `CfsClass` and `EevdfClass`. Contains the RB-tree
/// timeline, accounting state, and per-CPU hints. The caller is
/// responsible for updating `clock` before invoking any method.
#[repr(C)]
pub struct FairRunQueue {
    /// RB-tree of runnable entities, ordered by vruntime.
    pub timeline: FairTimeline,
    /// Number of runnable entities on this queue.
    pub nr_running: u32,
    _pad_nr: u32,
    /// Sum of weights of all runnable entities.
    pub total_weight: u64,
    /// Monotonically increasing vruntime floor.
    pub min_vruntime: u64,
    /// Weighted vruntime accumulator: sum of (se.vruntime * se.weight).
    /// Used by EEVDF to compute avg_vruntime for eligibility.
    /// u128 for precision: u64 * u32 summed across many entities.
    pub(crate) avg_vruntime_sum: u128,
    /// Currently running fair-class entity (null if no fair task on CPU).
    pub(crate) curr: *mut SchedEntity,
    /// Wakeup hint: preferred next entity (set by wakeup path).
    pub(crate) next: *mut SchedEntity,
    /// Yield hint: entity to skip in pick_next.
    pub(crate) skip: *mut SchedEntity,
    /// Per-runqueue nanosecond clock. Must be updated by the caller
    /// (via `set_clock`) before invoking any method.
    pub(crate) clock: u64,
}

impl FairRunQueue {
    pub const fn new() -> Self {
        Self {
            timeline: FairTimeline::new(),
            nr_running: 0,
            _pad_nr: 0,
            total_weight: 0,
            min_vruntime: 0,
            avg_vruntime_sum: 0,
            curr: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            skip: core::ptr::null_mut(),
            clock: 0,
        }
    }

    /// Update the runqueue clock. Must be called before any scheduling
    /// operation to provide the current time.
    #[inline(always)]
    pub fn set_clock(&mut self, now_ns: u64) {
        self.clock = now_ns;
    }

    /// Set the currently running entity. Used by benchmarks and tests.
    #[inline(always)]
    pub fn set_curr(&mut self, entity: *mut SchedEntity) {
        self.curr = entity;
    }

    /// Update accounting for the currently running entity.
    /// Advances vruntime, decrements slice, updates avg_vruntime_sum.
    ///
    /// # Safety
    /// `self.curr` must be either null or a valid pointer.
    pub unsafe fn update_curr(&mut self) {
        if self.curr.is_null() {
            return;
        }
        let se = self.curr;
        let delta_ns = self.clock.saturating_sub((*se).exec_start);
        if delta_ns == 0 {
            return;
        }

        // Advance vruntime (weighted: higher weight = slower advance)
        let vdelta = calc_delta_fair(delta_ns, (*se).weight);
        (*se).vruntime = (*se).vruntime.wrapping_add(vdelta);

        // Incremental avg_vruntime_sum update
        self.avg_vruntime_sum = self.avg_vruntime_sum
            .wrapping_add(vdelta as u128 * (*se).weight as u128);

        // Wall-clock accounting
        (*se).sum_exec = (*se).sum_exec.wrapping_add(delta_ns);
        (*se).exec_start = self.clock;

        // Decrement remaining slice
        (*se).slice = (*se).slice.saturating_sub(delta_ns);

        self.update_min_vruntime();
    }

    /// Advance `min_vruntime` monotonically.
    /// Takes the minimum of curr and leftmost vruntimes, but never goes backward.
    pub unsafe fn update_min_vruntime(&mut self) {
        let mut vruntime = self.min_vruntime;

        if !self.curr.is_null() {
            let curr_vrt = (*self.curr).vruntime;
            if super::rbtree::vruntime_gt(curr_vrt, vruntime) {
                vruntime = curr_vrt;
            }
        }

        if let Some(leftmost) = self.timeline.leftmost() {
            let lm_vrt = (*leftmost).vruntime;
            if self.curr.is_null() {
                vruntime = lm_vrt;
            } else if !super::rbtree::vruntime_gt(lm_vrt, vruntime) {
                vruntime = lm_vrt;
            }
        }

        // Monotonic: never go backward
        if super::rbtree::vruntime_gt(vruntime, self.min_vruntime) {
            self.min_vruntime = vruntime;
        }
    }

    /// Set initial vruntime and slice for an entity being enqueued.
    ///
    /// # Safety
    /// `se` must be a valid pointer.
    pub unsafe fn place_entity(&mut self, se: *mut SchedEntity, wake_flags: u32) {
        if wake_flags & WF_FORK != 0 {
            // New task: start at min_vruntime
            (*se).vruntime = self.min_vruntime;
            (*se).vlag = 0;
        } else {
            // Waking task: restore relative position from saved vlag
            let avg = self.compute_avg_vruntime();
            let restored = (avg as i64).wrapping_add((*se).vlag);
            (*se).vruntime = if restored < 0 { 0u64 } else { restored as u64 };

            // Wakeup credit for Normal tasks only
            if (*se).policy == SchedPolicy::Normal {
                let credit = calc_delta_fair(WAKEUP_CREDIT_NS, (*se).weight);
                (*se).vruntime = (*se).vruntime.saturating_sub(credit);
            }

            // Don't let a task go too far behind min_vruntime
            let floor = self.min_vruntime.saturating_sub(
                calc_delta_fair(SCHED_LATENCY_NS, (*se).weight),
            );
            if super::rbtree::vruntime_gt(floor, (*se).vruntime) {
                (*se).vruntime = floor;
            }
        }

        // Compute slice and vdeadline
        (*se).slice = calc_slice((*se).weight, self.nr_running.saturating_add(1), self.total_weight + (*se).weight as u64);
        (*se).vdeadline = (*se).vruntime.wrapping_add(
            calc_delta_fair((*se).slice, (*se).weight),
        );
        (*se).rb_min_vdeadline = (*se).vdeadline;
    }

    /// Add an entity to the timeline tree and accounting.
    ///
    /// # Safety
    /// `se` must be a valid pointer not currently in any tree.
    pub unsafe fn enqueue_entity(&mut self, se: *mut SchedEntity) {
        self.avg_vruntime_sum = self.avg_vruntime_sum
            .wrapping_add((*se).vruntime as u128 * (*se).weight as u128);
        self.timeline.insert(se);
        (*se).on_rq = 1;
        self.nr_running += 1;
        self.total_weight += (*se).weight as u64;
    }

    /// Remove an entity from the timeline tree and accounting.
    ///
    /// # Safety
    /// `se` must be a valid pointer currently in this tree.
    pub unsafe fn dequeue_entity(&mut self, se: *mut SchedEntity) {
        self.avg_vruntime_sum = self.avg_vruntime_sum
            .wrapping_sub((*se).vruntime as u128 * (*se).weight as u128);
        self.timeline.remove(se);
        (*se).on_rq = 0;
        debug_assert!(self.nr_running > 0, "nr_running underflow");
        debug_assert!(self.total_weight >= (*se).weight as u64,
            "total_weight underflow: {} < {}", self.total_weight, (*se).weight);
        self.nr_running -= 1;
        self.total_weight -= (*se).weight as u64;

        // Clear hints pointing to this entity
        if self.next == se {
            self.next = core::ptr::null_mut();
        }
        if self.skip == se {
            self.skip = core::ptr::null_mut();
        }
    }

    /// Compute the weighted average vruntime across all runnable entities.
    /// Used by EEVDF for the eligibility threshold.
    #[inline(always)]
    pub fn compute_avg_vruntime(&self) -> u64 {
        if self.total_weight == 0 {
            return self.min_vruntime;
        }
        (self.avg_vruntime_sum / self.total_weight as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::SchedEntity;

    fn make_entity(id: u64, nice: i8) -> SchedEntity {
        let mut se = SchedEntity::new(id);
        se.nice = nice;
        se.weight = crate::entity::nice_to_weight(nice);
        se
    }

    #[test]
    fn update_curr_advances_vruntime() {
        let mut rq = FairRunQueue::new();
        let mut se = make_entity(1, 0); // nice 0, weight 1024
        se.exec_start = 0;
        rq.curr = &mut se;
        rq.set_clock(1_000_000); // 1ms
        unsafe { rq.update_curr(); }
        // nice 0: vdelta == delta_ns == 1_000_000
        assert_eq!(se.vruntime, 1_000_000);
        assert_eq!(se.sum_exec, 1_000_000);
    }

    #[test]
    fn update_curr_weighted() {
        let mut rq = FairRunQueue::new();
        // nice -5 (weight 3121): vruntime advances slower
        let mut se = make_entity(1, -5);
        se.exec_start = 0;
        rq.curr = &mut se;
        rq.set_clock(1_000_000); // 1ms
        unsafe { rq.update_curr(); }
        // vdelta = 1_000_000 * 1024 / 3121 ≈ 328_100
        let expected = (1_000_000u128 * 1024 / 3121) as u64;
        assert_eq!(se.vruntime, expected);
    }

    #[test]
    fn min_vruntime_monotonic() {
        let mut rq = FairRunQueue::new();
        rq.min_vruntime = 1000;
        unsafe { rq.update_min_vruntime(); }
        assert!(rq.min_vruntime >= 1000);
    }

    #[test]
    fn place_entity_fork() {
        let mut rq = FairRunQueue::new();
        rq.min_vruntime = 5000;
        let mut se = make_entity(1, 0);
        unsafe {
            rq.place_entity(&mut se, WF_FORK);
        }
        assert_eq!(se.vruntime, 5000);
        assert!(se.slice > 0);
        assert!(se.vdeadline > se.vruntime);
    }

    #[test]
    fn enqueue_dequeue_accounting() {
        let mut rq = FairRunQueue::new();
        let mut e1 = make_entity(1, 0);
        let mut e2 = make_entity(2, 0);
        unsafe {
            rq.place_entity(&mut e1, WF_FORK);
            rq.enqueue_entity(&mut e1);
            rq.place_entity(&mut e2, WF_FORK);
            rq.enqueue_entity(&mut e2);
        }
        assert_eq!(rq.nr_running, 2);
        assert_eq!(rq.total_weight, 2048);
        assert_eq!(e1.on_rq, 1);
        unsafe { rq.dequeue_entity(&mut e1); }
        assert_eq!(rq.nr_running, 1);
        assert_eq!(rq.total_weight, 1024);
        assert_eq!(e1.on_rq, 0);
    }

    #[test]
    fn slice_proportional_to_weight() {
        // Nice -5 (weight 3121) should get a larger slice than nice +5 (weight 335)
        let rq_weight = 3121u64 + 335;
        let slice_high = calc_slice(3121, 2, rq_weight);
        let slice_low = calc_slice(335, 2, rq_weight);
        assert!(slice_high > slice_low);
    }
}
