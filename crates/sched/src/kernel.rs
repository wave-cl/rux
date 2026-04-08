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
/// Global scheduler shared across all CPUs.
///
/// # SMP race warning
/// On QEMU TCG (software emulation), CPUs are serialized — only one
/// executes at a time, so concurrent access doesn't occur. On real SMP
/// hardware (KVM, bare metal), the following races exist:
/// - `tick()` called from timer ISRs on multiple CPUs simultaneously
///   (modifies `clock_ns`, `need_resched`, CFS tree)
/// - `schedule()` called from syscall return on multiple CPUs
///   (modifies `current`, picks from shared CFS queue)
/// - `dequeue_current()` / `wake_task()` from syscall paths
///
/// Fix: per-CPU scheduler instances with per-CPU CFS runqueues,
/// or a spinlock around all scheduler operations (with interrupt disable).
pub struct Scheduler {
    pub cfs: CfsClass,
    pub tasks: [KernelTask; MAX_TASKS],
    /// Index of the currently running task (into `tasks` array).
    pub current: usize,
    /// Clock in nanoseconds (advanced by timer ISR).
    pub clock_ns: u64,
    /// Whether a reschedule is pending.
    pub need_resched: bool,
    /// CPU ID this scheduler instance runs on (for per-CPU runqueues).
    pub cpu_id: u32,
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
            cpu_id: 0,
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
        self.cfs.set_clock(self.cpu_id, self.clock_ns);
        self.cfs.enqueue(self.cpu_id, &mut task.entity, WF_FORK);

        idx
    }

    /// Called from the timer ISR. Advances the clock, ticks the current task,
    /// and sets `need_resched` if a context switch is needed.
    pub fn tick(&mut self, elapsed_ns: u64) {
        self.clock_ns += elapsed_ns;
        self.cfs.set_clock(self.cpu_id, self.clock_ns);

        let current = self.current;
        // Idle task (slot 0) is never on the CFS runqueue — skip task_tick
        // but check if any tasks became runnable (via wake_task or enqueue)
        if current == 0 {
            if self.cfs.rqs[self.cpu_id as usize].nr_running > 0 {
                self.need_resched = true;
            }
            return;
        }
        if current < MAX_TASKS && self.tasks[current].active {
            let entity = &mut self.tasks[current].entity;
            if self.cfs.task_tick(self.cpu_id, entity) {
                self.need_resched = true;
            }
            // Force reschedule when other tasks are waiting.
            // Without preemptive ISR scheduling, this ensures the
            // post_syscall check catches pending tasks promptly.
            if self.cfs.rqs[self.cpu_id as usize].nr_running > 0 {
                self.need_resched = true;
            }
        }
    }

    /// Remove the current task from the runqueue (it's going to sleep/wait/exit).
    /// Sets need_resched so the next schedule() call picks another task.
    pub fn dequeue_current(&mut self) {
        self.need_resched = true;
        // Task won't be put_prev'd in schedule() because we mark it non-active
        // by setting its state to Interruptible. Actually, schedule() only
        // put_prev's if the task is active. We need to ensure it's not
        // re-enqueued. The simplest approach: just don't call put_prev for it.
        // We'll handle this by checking state in schedule().
    }

    /// Wake a sleeping/waiting task by re-enqueuing it in CFS.
    pub fn wake_task(&mut self, idx: usize) {
        if idx >= MAX_TASKS || !self.tasks[idx].active { return; }
        self.tasks[idx].entity.state = TaskState::Ready;
        self.cfs.set_clock(self.cpu_id, self.clock_ns);
        self.cfs.enqueue(self.cpu_id, &mut self.tasks[idx].entity, 0);
        self.need_resched = true; // trigger reschedule (especially from idle)
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

        // Put the current task back on the runqueue (skip slot 0 = idle/main,
        // skip sleeping/waiting/zombie tasks that called dequeue_current)
        if old_idx > 0 && old_idx < MAX_TASKS && self.tasks[old_idx].active
            && self.tasks[old_idx].entity.state == TaskState::Running
        {
            let entity = &mut self.tasks[old_idx].entity;
            self.cfs.put_prev(self.cpu_id, entity);
        }

        // Pick the next task
        let mut dummy = SchedEntity::new(999);
        dummy.state = TaskState::Interruptible;

        let new_idx = if let Some(picked) = self.cfs.pick_next(self.cpu_id, &mut dummy) {
            let idx = (*picked).id as usize;
            self.cfs.set_next(self.cpu_id, &mut *picked);
            idx
        } else {
            0 // No runnable tasks — go back to idle/main (slot 0)
        };

        self.current = new_idx;

        // If more tasks are queued, set need_resched so the next syscall
        // return (post_syscall) triggers another switch. This ensures rapid
        // interleaving during pipeline startup without ISR preemption.
        if self.cfs.rqs[self.cpu_id as usize].nr_running > 0 {
            self.need_resched = true;
        }

        // Keep timer always running — slot 0 is the init/shell process which
        // uses timer interrupts to poll UART input; stopping the timer would
        // cause console reads to hang forever.
        let ctx = self.ctx.as_ref().expect("context fns not set");

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
