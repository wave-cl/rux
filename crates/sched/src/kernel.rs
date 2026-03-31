/// Kernel scheduler — manages kernel tasks with CFS and timer-driven preemption.
///
/// This is the glue between the CFS implementation and the actual
/// context switch. The timer ISR calls `tick()`, which advances vruntime
/// and context-switches if needed.
///
/// Architecture-specific context switching is injected via function pointers
/// set at init time, so this module has no arch dependencies.

use crate::entity::SchedEntity;
use crate::fair::cfs::CfsClass;
use crate::fair::constants::WF_FORK;
use crate::SchedClassOps;
use crate::TaskState;

/// Maximum kernel tasks.
pub const MAX_TASKS: usize = 16;

/// Per-task kernel state: the scheduling entity + kernel stack SP.
#[repr(C)]
pub struct KernelTask {
    pub entity: SchedEntity,
    /// Saved SP for context_switch (callee-saved regs + return address on stack).
    pub saved_sp: usize,
    /// Whether this slot is in use.
    pub active: bool,
}

/// Context switch function pointers — set once at kernel init.
pub struct ContextFns {
    /// Architecture-specific context switch: saves SP to *old_sp, loads new_sp.
    pub context_switch: unsafe fn(*mut usize, usize),
    /// Initialize a task stack so context_switch "returns" to entry(arg).
    pub init_task_stack: unsafe fn(usize, usize, usize) -> usize,
    /// Stop the periodic timer (enter tickless idle).
    pub stop_timer: unsafe fn(),
    /// Restart the periodic timer (exit tickless idle).
    pub start_timer: unsafe fn(),
    /// Called before context_switch to swap process state (page tables, globals, etc.).
    pub pre_switch: Option<unsafe fn(old_idx: usize, new_idx: usize)>,
}

/// Global scheduler state.
pub struct Scheduler {
    pub cfs: CfsClass,
    pub tasks: [KernelTask; MAX_TASKS],
    /// Index of the currently running task (into `tasks` array).
    pub current: usize,
    /// Clock in nanoseconds (advanced by timer ISR).
    pub clock_ns: u64,
    /// Whether a reschedule is pending.
    pub need_resched: bool,
    /// Architecture-specific context switch functions.
    ctx: Option<ContextFns>,
}

impl Scheduler {
    pub const fn new() -> Self {
        const EMPTY_TASK: KernelTask = KernelTask {
            entity: SchedEntity::new(0),
            saved_sp: 0,
            active: false,
        };
        let mut s = Self {
            cfs: CfsClass::new(),
            tasks: [EMPTY_TASK; MAX_TASKS],
            current: 0,
            clock_ns: 0,
            need_resched: false,
            ctx: None,
        };
        // Slot 0 is the idle/main task — always active, not on the runqueue.
        // schedule() saves kernel_main's SP here when switching to a real task,
        // and restores it when no runnable tasks remain.
        s.tasks[0].active = true;
        s
    }

    /// Set the context switch function pointers. Must be called before
    /// `create_task` or `schedule`.
    pub fn set_context_fns(&mut self, fns: ContextFns) {
        self.ctx = Some(fns);
    }

    /// Create a new kernel task. Returns the task index.
    /// `entry` is the function to run. `stack_top` is the top of the pre-allocated stack.
    pub unsafe fn create_task(
        &mut self,
        entry: extern "C" fn(),
        stack_top: usize,
        nice: i8,
    ) -> usize {
        // Find a free slot
        let idx = self.tasks.iter().position(|t| !t.active)
            .expect("no free task slots");

        let task = &mut self.tasks[idx];
        task.entity = SchedEntity::new(idx as u64);
        task.entity.nice = nice;
        task.entity.cpu = 0;
        task.entity.state = TaskState::Ready;
        task.active = true;

        // Initialize the kernel stack so context_switch "returns" to entry
        let ctx = self.ctx.as_ref().expect("context fns not set");
        task.saved_sp = (ctx.init_task_stack)(stack_top, entry as usize, 0);

        // Enqueue into CFS
        self.cfs.set_clock(0, self.clock_ns);
        self.cfs.enqueue(0, &mut task.entity, WF_FORK);

        idx
    }

    /// Called from the timer ISR. Advances the clock, ticks the current task,
    /// and sets `need_resched` if a context switch is needed.
    pub fn tick(&mut self, elapsed_ns: u64) {
        self.clock_ns += elapsed_ns;
        self.cfs.set_clock(0, self.clock_ns);

        let current = self.current;
        if current < MAX_TASKS && self.tasks[current].active {
            let entity = &mut self.tasks[current].entity;
            if self.cfs.task_tick(0, entity) {
                self.need_resched = true;
            }
        }
    }

    /// Perform a context switch if one is pending.
    /// Called after returning from the timer ISR (or voluntarily).
    ///
    /// # Safety
    /// Manipulates stack pointers and switches execution context.
    pub unsafe fn schedule(&mut self) {
        if !self.need_resched {
            return;
        }
        self.need_resched = false;

        let old_idx = self.current;

        // Put the current task back on the runqueue (skip slot 0 = idle/main)
        if old_idx > 0 && old_idx < MAX_TASKS && self.tasks[old_idx].active {
            let entity = &mut self.tasks[old_idx].entity;
            self.cfs.put_prev(0, entity);
        }

        // Pick the next task
        let mut dummy = SchedEntity::new(999);
        dummy.state = TaskState::Interruptible;

        let new_idx = if let Some(picked) = self.cfs.pick_next(0, &mut dummy) {
            let idx = (*picked).id as usize;
            self.cfs.set_next(0, &mut *picked);
            idx
        } else {
            0 // No runnable tasks — go back to idle/main (slot 0)
        };

        self.current = new_idx;

        // Tickless idle: stop timer when going idle, restart when leaving idle
        let ctx = self.ctx.as_ref().expect("context fns not set");
        if new_idx == 0 && old_idx != 0 {
            (ctx.stop_timer)();
        } else if new_idx != 0 && old_idx == 0 {
            (ctx.start_timer)();
        }

        if new_idx != old_idx {
            // Swap per-process state (page tables, FD tables, globals) before switching
            if let Some(pre) = ctx.pre_switch {
                (pre)(old_idx, new_idx);
            }

            let old_rsp_ptr = &mut self.tasks[old_idx].saved_sp as *mut usize;
            let new_rsp = self.tasks[new_idx].saved_sp;

            (ctx.context_switch)(old_rsp_ptr, new_rsp);
        }
    }
}
