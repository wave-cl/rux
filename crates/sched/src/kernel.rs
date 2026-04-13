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
    /// Get the current CPU ID (reads per-CPU register — GS-base or TPIDR_EL1).
    pub get_cpu: Option<fn() -> u32>,
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
    /// Per-CPU current task index. Indexed by cpu_id.
    pub current_per_cpu: [usize; 64],
    /// Per-CPU clocks in nanoseconds (each CPU advances independently).
    pub clock_per_cpu: [u64; 64],
    /// Per-CPU reschedule bitmask. Bit N set = CPU N needs to reschedule.
    /// Replaces the global `need_resched: bool` for proper SMP support.
    pub need_resched: u64,
    /// CPU ID this scheduler instance runs on (updated by set_running_cpu).
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
            current_per_cpu: [0; 64],
            clock_per_cpu: [0; 64],
            need_resched: 0,
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

    /// Get the current running CPU ID from the per-CPU register.
    #[inline(always)]
    fn this_cpu(&self) -> u32 {
        if let Some(ref ctx) = self.ctx {
            if let Some(get) = ctx.get_cpu {
                return get();
            }
        }
        self.cpu_id // fallback to stored value
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
        self.cfs.set_clock(self.cpu_id, self.clock_per_cpu[self.cpu_id as usize]);
        self.cfs.enqueue(self.cpu_id, &mut task.entity, WF_FORK);

        idx
    }

    /// Called from the timer ISR. Advances the clock, ticks the current task,
    /// and sets `need_resched` if a context switch is needed.
    pub fn tick(&mut self, elapsed_ns: u64) {
        let cpu = self.this_cpu();
        self.clock_per_cpu[cpu as usize] += elapsed_ns;
        self.cfs.set_clock(cpu, self.clock_per_cpu[cpu as usize]);

        let current = self.current_per_cpu[cpu as usize];
        if current == 0 {
            if self.cfs.rqs[cpu as usize].nr_running > 0 {
                self.need_resched |= 1u64 << cpu;
            }
            return;
        }
        if current < MAX_TASKS && self.tasks[current].active {
            let entity = &mut self.tasks[current].entity;
            if self.cfs.task_tick(cpu, entity) {
                self.need_resched |= 1u64 << cpu;
            }
            if self.cfs.rqs[cpu as usize].nr_running > 0 {
                self.need_resched |= 1u64 << cpu;
            }
        }
    }

    /// Remove the current task from the runqueue (it's going to sleep/wait/exit).
    /// Sets need_resched so the next schedule() call picks another task.
    pub fn dequeue_current(&mut self) {
        self.need_resched |= 1u64 << self.this_cpu();
        // Task won't be put_prev'd in schedule() because we mark it non-active
        // by setting its state to Interruptible. Actually, schedule() only
        // put_prev's if the task is active. We need to ensure it's not
        // re-enqueued. The simplest approach: just don't call put_prev for it.
        // We'll handle this by checking state in schedule().
    }

    /// Wake a sleeping/waiting task by re-enqueuing it in CFS.
    pub fn wake_task(&mut self, idx: usize) {
        if idx >= MAX_TASKS || !self.tasks[idx].active { return; }
        let target_cpu = self.tasks[idx].entity.cpu;
        self.wake_task_on(idx, target_cpu);
    }

    /// Wake a task on a specific CPU's runqueue.
    /// Sets need_resched if target is the local CPU.
    /// Returns the target CPU (caller sends IPI if remote).
    pub fn wake_task_on(&mut self, idx: usize, target_cpu: u32) -> u32 {
        if idx >= MAX_TASKS || !self.tasks[idx].active { return self.cpu_id; }
        self.tasks[idx].entity.state = TaskState::Ready;
        self.tasks[idx].entity.cpu = target_cpu;
        self.cfs.set_clock(target_cpu, self.clock_per_cpu[target_cpu as usize]);
        self.cfs.enqueue(target_cpu, &mut self.tasks[idx].entity, 0);
        self.need_resched |= 1u64 << target_cpu;
        target_cpu
    }

    /// Perform a context switch if one is pending.
    /// Called after returning from the timer ISR (or voluntarily).
    ///
    /// # Safety
    /// Manipulates stack pointers and switches execution context.
    /// Set the CPU ID for the current caller (updated on each tick).
    #[inline(always)]
    pub fn set_running_cpu(&mut self, cpu: u32) {
        self.cpu_id = cpu;
    }

    pub unsafe fn schedule(&mut self) {
        let cpu = self.this_cpu();
        self.schedule_on(cpu);
    }

    /// Schedule on a specific CPU's runqueue.
    /// Called with the actual running CPU's ID (may differ from self.cpu_id on APs).
    pub unsafe fn schedule_on(&mut self, cpu: u32) {
        let cpu_bit = 1u64 << cpu;
        if self.need_resched & cpu_bit == 0 {
            return;
        }
        self.need_resched &= !cpu_bit;

        let old_idx = self.current_per_cpu[cpu as usize];

        // Put the current task back on the runqueue (skip slot 0 = idle/main,
        // skip sleeping/waiting/zombie tasks that called dequeue_current)
        if old_idx > 0 && old_idx < MAX_TASKS && self.tasks[old_idx].active
            && self.tasks[old_idx].entity.state == TaskState::Running
        {
            let entity = &mut self.tasks[old_idx].entity;
            self.cfs.put_prev(cpu, entity);
        }

        // Pick the next task from THIS CPU's runqueue
        let mut dummy = SchedEntity::new(999);
        dummy.state = TaskState::Interruptible;

        let new_idx = if let Some(picked) = self.cfs.pick_next(cpu, &mut dummy) {
            let idx = (*picked).id as usize;
            self.cfs.set_next(cpu, &mut *picked);
            idx
        } else {
            0 // No runnable tasks — go back to idle/main (slot 0)
        };

        self.current_per_cpu[cpu as usize] = new_idx;

        // If more tasks are queued, set need_resched so the next syscall
        // return (post_syscall) triggers another switch. This ensures rapid
        // interleaving during pipeline startup without ISR preemption.
        if self.cfs.rqs[cpu as usize].nr_running > 0 {
            self.need_resched |= 1u64 << cpu;
        }

        let ctx = match self.ctx.as_ref() {
            Some(c) => c,
            None => return, // Early boot: scheduler context not yet initialized
        };

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
