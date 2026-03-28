use crate::id::{Pid, Tgid, Pgid, Sid};
use crate::error::ProcError;
use crate::signal::{Signal, SignalHot, SignalCold, SigInfo, SigCode};
use crate::task::{Task, TaskFlags};
use crate::lifecycle::{ExitStatus, CloneFlags, WaitOptions, ProcessOps};
use crate::pid::PidBitmap;
use crate::fd::{FdTable, FdOps};
use crate::rlimit::ResourceLimits;
use rux_sched::TaskState;

/// Maximum concurrent tasks.
pub const MAX_TASKS: usize = 1024;

/// Process manager — owns the task table, PID allocator, and slab caches.
/// Implements `ProcessOps` for the kernel's fork/exec/exit/wait/kill.
///
/// The task table is a flat array of pointers. `*mut Task` entries are
/// non-null for active tasks, null for free slots. Tasks are allocated
/// externally (from a slab or static array) and registered here.
#[repr(C)]
pub struct ProcessManager {
    /// PID allocator.
    pub pids: PidBitmap,
    /// Task table indexed by PID (sparse — only populated PIDs are non-null).
    /// For PIDs > MAX_TASKS, use the PidBitmap for existence checks.
    tasks: [*mut Task; MAX_TASKS],
    /// PID of the currently running task.
    pub current_pid: Pid,
}

// SAFETY: Raw pointers in tasks array, accessed under kernel locks.
unsafe impl Send for ProcessManager {}
unsafe impl Sync for ProcessManager {}

impl ProcessManager {
    /// Create a new process manager.
    pub const fn new() -> Self {
        Self {
            pids: PidBitmap::new(),
            tasks: [core::ptr::null_mut(); MAX_TASKS],
            current_pid: Pid::new(0),
        }
    }

    /// Register a task in the task table.
    pub fn register(&mut self, task: *mut Task) {
        unsafe {
            let pid = (*task).pid.as_u32() as usize;
            if pid < MAX_TASKS {
                self.tasks[pid] = task;
            }
        }
    }

    /// Unregister a task from the task table.
    pub fn unregister(&mut self, pid: Pid) {
        let n = pid.as_u32() as usize;
        if n < MAX_TASKS {
            self.tasks[n] = core::ptr::null_mut();
        }
    }

    /// Look up a task by PID.
    #[inline(always)]
    pub fn get_task(&self, pid: Pid) -> Option<*mut Task> {
        let n = pid.as_u32() as usize;
        if n < MAX_TASKS {
            let ptr = self.tasks[n];
            if !ptr.is_null() { Some(ptr) } else { None }
        } else {
            None
        }
    }

    /// Get the currently running task.
    #[inline(always)]
    pub fn current(&self) -> Option<*mut Task> {
        self.get_task(self.current_pid)
    }

    /// Find a zombie child of `parent_pid` matching the wait criteria.
    /// Returns the child's PID if found, None otherwise.
    fn find_zombie_child(&self, parent_pid: Pid, wait_pid: i32) -> Option<Pid> {
        for i in 1..MAX_TASKS {
            let ptr = self.tasks[i];
            if ptr.is_null() { continue; }
            unsafe {
                let task = &*ptr;
                // Must be a child of parent
                if task.ppid != parent_pid { continue; }
                // Must be a zombie
                if task.sched.state != TaskState::Zombie { continue; }
                // Match wait criteria
                match wait_pid {
                    -1 => return Some(task.pid),              // any child
                    0 => {
                        // Same process group as caller
                        if let Some(parent) = self.get_task(parent_pid) {
                            if task.pgid == (*parent).pgid {
                                return Some(task.pid);
                            }
                        }
                    }
                    pid if pid > 0 => {
                        if task.pid.as_u32() == pid as u32 {
                            return Some(task.pid);
                        }
                    }
                    neg_pgid => {
                        // Process group = abs(pid)
                        if task.pgid.as_u32() == (-neg_pgid) as u32 {
                            return Some(task.pid);
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if the parent has any children at all.
    fn has_children(&self, parent_pid: Pid) -> bool {
        for i in 1..MAX_TASKS {
            let ptr = self.tasks[i];
            if ptr.is_null() { continue; }
            unsafe {
                if (*ptr).ppid == parent_pid { return true; }
            }
        }
        false
    }

    /// Reparent all children of `old_parent` to `new_parent` (PID 1 = init).
    fn reparent_children(&mut self, old_parent: Pid, new_parent: Pid) {
        for i in 1..MAX_TASKS {
            let ptr = self.tasks[i];
            if ptr.is_null() { continue; }
            unsafe {
                if (*ptr).ppid == old_parent {
                    (*ptr).ppid = new_parent;
                    // Also update parent pointer if we have the new parent
                    if let Some(new_ptr) = self.get_task(new_parent) {
                        (*ptr).parent = new_ptr;
                    }
                }
            }
        }
    }

    /// Send a signal to a specific task by PID.
    fn signal_task(&mut self, target_pid: Pid, sig: Signal, sender: &Task) -> Result<(), ProcError> {
        let target_ptr = self.get_task(target_pid).ok_or(ProcError::NotFound)?;
        unsafe {
            let target = &mut *target_ptr;

            // Permission check
            if !sender.creds.can_signal(&target.creds) {
                return Err(ProcError::PermissionDenied);
            }

            // Build siginfo
            let info = SigInfo {
                signo: sig as u8,
                code: SigCode::User,
                _pad0: [0; 2],
                pid: sender.pid,
                uid: sender.creds.uid,
                _pad1: [0; 4],
                addr: 0,
                status: 0,
                _pad2: [0; 4],
            };

            // Deliver signal
            if !target.sig_cold.is_null() {
                (*target.sig_cold).send_standard(&mut target.sig_hot, sig, &info)?;
            } else {
                // No sig_cold allocated — just set pending bit
                target.sig_hot.pending = target.sig_hot.pending.add(sig as u8);
            }

            // Wake if in interruptible sleep
            if target.sched.state == TaskState::Interruptible {
                target.sched.state = TaskState::Ready;
            }
        }
        Ok(())
    }
}

unsafe impl ProcessOps for ProcessManager {
    type Error = ProcError;

    fn fork(&mut self, flags: u32) -> Result<Pid, ProcError> {
        let parent_ptr = self.current().ok_or(ProcError::NotFound)?;
        let child_pid = self.pids.alloc()?;

        unsafe {
            let parent = &*parent_ptr;

            // In a real kernel, we'd allocate Task from a slab.
            // For now, the caller must pre-allocate and register.
            // This implementation sets up the child's metadata assuming
            // the child Task is already allocated at the registered slot.

            // Check if a task is registered at this PID (pre-allocated by caller)
            let child_ptr = match self.get_task(child_pid) {
                Some(ptr) => ptr,
                None => {
                    self.pids.free(child_pid);
                    return Err(ProcError::ResourceLimit);
                }
            };

            let child = &mut *child_ptr;

            // Copy identity
            child.pid = child_pid;
            child.tgid = if flags & CloneFlags::Thread as u32 != 0 {
                parent.tgid // same thread group
            } else {
                Tgid::new(child_pid.as_u32()) // new thread group
            };
            child.ppid = Pid::new(parent.tgid.as_u32());
            child.pgid = parent.pgid;
            child.sid = parent.sid;
            child.exit_code = 0;
            child.clone_flags = flags;
            child.task_flags = TaskFlags::ForkNoExec as u32;

            // Family tree
            child.parent = parent_ptr as *mut Task;
            child.real_parent = parent_ptr as *mut Task;
            child.group_leader = if flags & CloneFlags::Thread as u32 != 0 {
                parent.group_leader
            } else {
                child_ptr
            };

            // Copy credentials
            child.creds = parent.creds;

            // Copy filesystem context
            child.fs = parent.fs;

            // Zero child times
            child.times = crate::times::ProcessTimes::ZERO;

            // Signal state: empty pending, copy blocked mask
            child.sig_hot = SignalHot::new();
            child.sig_hot.blocked = parent.sig_hot.blocked;

            // Scheduler: mark as ready
            child.sched.state = TaskState::Ready;
            child.sched.class = parent.sched.class;
            child.sched.policy = parent.sched.policy;
            child.sched.nice = parent.sched.nice;
            child.sched.cpu = parent.sched.cpu;
        }

        Ok(child_pid)
    }

    fn exec(&mut self, _path: &[u8], _argv: &[&[u8]], _envp: &[&[u8]]) -> Result<(), ProcError> {
        let task_ptr = self.current().ok_or(ProcError::NotFound)?;
        unsafe {
            let task = &mut *task_ptr;

            // Close FD_CLOEXEC file descriptors
            if !task.fd_table.is_null() {
                (*task.fd_table).close_on_exec();
            }

            // Reset signal handlers to default (except SIG_IGN)
            if !task.sig_cold.is_null() {
                let cold = &mut *task.sig_cold;
                for i in 1..32u8 {
                    if let Some(sig) = Signal::from_raw(i) {
                        let action = cold.get_action(sig);
                        if action.handler_type != crate::signal::SignalHandler::Ignore {
                            let _ = cold.set_action(sig, crate::signal::SignalAction::DEFAULT);
                        }
                    }
                }
            }

            // Clear ForkNoExec
            task.task_flags &= !(TaskFlags::ForkNoExec as u32);

            // In a real kernel:
            // 1. Destroy old address space (mm)
            // 2. Load ELF segments into new address space
            // 3. Set up user stack with argv/envp
            // 4. Set entry point
            // 5. Call UserModeEntry::enter_user()
            // These require concrete arch + mm implementations.
        }

        Ok(())
    }

    fn exit(&mut self, status: i32) -> ! {
        if let Some(task_ptr) = self.current() {
            unsafe {
                let task = &mut *task_ptr;

                // Set exit code
                task.exit_code = (status & 0xFF) << 8;
                task.task_flags |= TaskFlags::Exiting as u32;

                // Reparent children to init (PID 1)
                self.reparent_children(task.pid, Pid::new(1));

                // Set zombie state
                task.sched.state = TaskState::Zombie;

                // Send SIGCHLD to parent
                if let Some(parent_ptr) = self.get_task(task.ppid) {
                    let parent = &mut *parent_ptr;
                    let info = SigInfo {
                        signo: Signal::Chld as u8,
                        code: SigCode::Kernel,
                        _pad0: [0; 2],
                        pid: task.pid,
                        uid: task.creds.uid,
                        _pad1: [0; 4],
                        addr: 0,
                        status: task.exit_code,
                        _pad2: [0; 4],
                    };
                    task.sig_hot.pending = task.sig_hot.pending.add(Signal::Chld as u8);
                    if !parent.sig_cold.is_null() {
                        let _ = (*parent.sig_cold).send_standard(
                            &mut parent.sig_hot,
                            Signal::Chld,
                            &info,
                        );
                    }

                    // Wake parent if waiting
                    if parent.sched.state == TaskState::Interruptible {
                        parent.sched.state = TaskState::Ready;
                    }
                }

                // In a real kernel: release mm, dequeue from scheduler, switch context
            }
        }

        // In a real kernel this would context switch and never return.
        // For testing, we loop (this function is ! return type).
        loop {
            core::hint::spin_loop();
        }
    }

    fn wait(&mut self, pid: i32, options: u32) -> Result<(Pid, ExitStatus), ProcError> {
        let current_pid = self.current_pid;

        if !self.has_children(current_pid) {
            return Err(ProcError::NoChildren);
        }

        // Find a zombie child matching criteria
        if let Some(child_pid) = self.find_zombie_child(current_pid, pid) {
            let child_ptr = self.get_task(child_pid).ok_or(ProcError::NotFound)?;
            unsafe {
                let child = &*child_ptr;
                let exit_code = child.exit_code;

                // Accumulate child times into parent
                if let Some(parent_ptr) = self.current() {
                    let parent = &mut *parent_ptr;
                    parent.times.cutime += child.times.utime;
                    parent.times.cstime += child.times.stime;
                }

                // Determine exit status
                let status = if exit_code & 0x7F == 0 {
                    ExitStatus::Code((exit_code >> 8) & 0xFF)
                } else {
                    let sig_num = (exit_code & 0x7F) as u8;
                    match Signal::from_raw(sig_num) {
                        Some(sig) => ExitStatus::Signaled(sig),
                        None => ExitStatus::Code(exit_code),
                    }
                };

                // Clean up child: set Dead, free PID, unregister
                // (In a real kernel: also free kernel stack, Task slab, etc.)
                let child_mut = &mut *child_ptr;
                child_mut.sched.state = TaskState::Dead;
                self.pids.free(child_pid);
                self.unregister(child_pid);

                return Ok((child_pid, status));
            }
        }

        // No zombie found
        if options & WaitOptions::NoHang as u32 != 0 {
            return Err(ProcError::TryAgain);
        }

        // In a real kernel: set current to Interruptible, schedule(), retry on wake
        Err(ProcError::Interrupted)
    }

    fn kill(&mut self, pid: i32, sig: Signal) -> Result<(), ProcError> {
        let sender_ptr = self.current().ok_or(ProcError::NotFound)?;
        let sender = unsafe { &*sender_ptr };

        if pid > 0 {
            // Specific process
            let target_pid = Pid::new(pid as u32);
            self.signal_task(target_pid, sig, sender)
        } else if pid == 0 {
            // All in caller's process group
            let pgid = sender.pgid;
            let mut sent = false;
            for i in 1..MAX_TASKS {
                let ptr = self.tasks[i];
                if ptr.is_null() { continue; }
                unsafe {
                    if (*ptr).pgid == pgid {
                        let _ = self.signal_task(Pid::new(i as u32), sig, sender);
                        sent = true;
                    }
                }
            }
            if sent { Ok(()) } else { Err(ProcError::NotFound) }
        } else if pid == -1 {
            // All processes (except PID 0 and self)
            for i in 1..MAX_TASKS {
                if i as u32 == sender.pid.as_u32() { continue; }
                let ptr = self.tasks[i];
                if ptr.is_null() { continue; }
                let _ = self.signal_task(Pid::new(i as u32), sig, sender);
            }
            Ok(())
        } else {
            // Process group = abs(pid)
            let target_pgid = Pgid::new((-pid) as u32);
            let mut sent = false;
            for i in 1..MAX_TASKS {
                let ptr = self.tasks[i];
                if ptr.is_null() { continue; }
                unsafe {
                    if (*ptr).pgid == target_pgid {
                        let _ = self.signal_task(Pid::new(i as u32), sig, sender);
                        sent = true;
                    }
                }
            }
            if sent { Ok(()) } else { Err(ProcError::NotFound) }
        }
    }

    fn getpid(&self) -> Pid {
        if let Some(ptr) = self.current() {
            unsafe { (*ptr).tgid.into() }
        } else {
            Pid::new(0)
        }
    }

    fn getppid(&self) -> Pid {
        if let Some(ptr) = self.current() {
            unsafe { (*ptr).ppid }
        } else {
            Pid::new(0)
        }
    }

    fn setpgid(&mut self, pid: Pid, pgid: Pgid) -> Result<(), ProcError> {
        let target_pid = if pid.as_u32() == 0 { self.current_pid } else { pid };
        let target_ptr = self.get_task(target_pid).ok_or(ProcError::NotFound)?;
        unsafe {
            let target = &mut *target_ptr;
            target.pgid = if pgid.as_u32() == 0 {
                Pgid::new(target_pid.as_u32())
            } else {
                pgid
            };
        }
        Ok(())
    }

    fn setsid(&mut self) -> Result<Sid, ProcError> {
        let task_ptr = self.current().ok_or(ProcError::NotFound)?;
        unsafe {
            let task = &mut *task_ptr;
            let new_sid = Sid::new(task.pid.as_u32());
            task.sid = new_sid;
            task.pgid = Pgid::new(task.pid.as_u32());
            Ok(new_sid)
        }
    }
}

// Tgid → Pid conversion (same underlying u32)
impl From<Tgid> for Pid {
    #[inline(always)]
    fn from(tgid: Tgid) -> Pid { Pid::new(tgid.as_u32()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Pid, Tgid, Pgid, Sid, Uid, Gid};
    use crate::signal::{Signal, SignalCold, SignalHandler, SignalAction, SignalSet};
    use crate::task::{Task, TaskFlags};
    use crate::lifecycle::{ExitStatus, CloneFlags, WaitOptions, ProcessOps};
    use crate::fd::{FdTable, FdOps, FD_CLOEXEC};
    use crate::error::ProcError;
    use crate::creds::Credentials;
    use rux_sched::TaskState;

    extern crate alloc;
    use alloc::boxed::Box;

    /// Allocate a ProcessManager on the heap (it's ~12KB).
    fn make_manager() -> Box<ProcessManager> {
        Box::new(ProcessManager::new())
    }

    /// Allocate a Task on the heap (1024 bytes) with pid == tgid.
    fn make_task(pid: u32) -> Box<Task> {
        let mut t = Box::new(Task::new(Pid::new(pid), Tgid::new(pid)));
        t.pgid = Pgid::new(pid);
        t.sid = Sid::new(pid);
        t
    }

    /// Set up a manager with PID 1 (init) registered and a parent task.
    /// Returns (manager, init_task, parent_task).
    /// parent_pid is allocated in the PidBitmap and registered.
    fn setup_with_parent(parent_pid: u32) -> (Box<ProcessManager>, Box<Task>, Box<Task>) {
        let mut mgr = make_manager();
        // Register init (PID 1)
        let mut init_task = make_task(1);
        mgr.pids.alloc_specific(Pid::new(1)).unwrap();
        mgr.register(&mut *init_task as *mut Task);
        // Register parent
        let mut parent = make_task(parent_pid);
        parent.ppid = Pid::new(1);
        mgr.pids.alloc_specific(Pid::new(parent_pid)).unwrap();
        mgr.register(&mut *parent as *mut Task);
        mgr.current_pid = Pid::new(parent_pid);
        (mgr, init_task, parent)
    }

    // ── fork tests ──────────────────────────────────────────────────────

    #[test]
    fn fork_creates_child() {
        let (mut mgr, _init, mut parent) = setup_with_parent(10);
        parent.pgid = Pgid::new(10);
        parent.sid = Sid::new(10);
        // Re-register parent after mutation (pointer is stable since it's boxed)
        mgr.register(&mut *parent as *mut Task);

        // Pre-allocate child at PID 11 (next alloc after 10)
        // We need to know what PID alloc() will return. Since PIDs 0,1,10 are taken,
        // alloc() will return 2. Pre-register at 2.
        let mut child = make_task(2);
        mgr.register(&mut *child as *mut Task);
        // PID 2 is already in the bitmap from alloc_specific in make_task... no,
        // we used alloc_specific for 1 and 10 only. PID 2 is free. alloc() will get it.

        let child_pid = mgr.fork(0).expect("fork should succeed");
        assert_eq!(child_pid, Pid::new(2), "child should get PID 2");

        // Read back child state
        let child_ptr = mgr.get_task(child_pid).expect("child should be registered");
        unsafe {
            let c = &*child_ptr;
            assert_eq!(c.pid, Pid::new(2));
            assert_eq!(c.tgid, Tgid::new(2), "new process gets tgid == pid");
            assert_eq!(c.ppid, Pid::new(10), "ppid should be parent's tgid");
            assert_eq!(c.pgid, Pgid::new(10), "child inherits parent pgid");
            assert_eq!(c.sid, Sid::new(10), "child inherits parent sid");
            assert_eq!(c.sched.state, TaskState::Ready, "child should be Ready");
        }
    }

    #[test]
    fn fork_thread_shares_tgid() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);
        let mut child = make_task(2);
        mgr.register(&mut *child as *mut Task);

        let child_pid = mgr.fork(CloneFlags::Thread as u32)
            .expect("fork with CLONE_THREAD should succeed");

        let child_ptr = mgr.get_task(child_pid).unwrap();
        unsafe {
            let c = &*child_ptr;
            assert_eq!(c.tgid, Tgid::new(10), "CLONE_THREAD child should share parent's tgid");
        }
    }

    // ── exit tests ──────────────────────────────────────────────────────

    #[test]
    fn exit_sets_zombie() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);
        // Create a child process
        let mut child = make_task(2);
        child.ppid = Pid::new(10);
        mgr.register(&mut *child as *mut Task);
        mgr.pids.alloc_specific(Pid::new(2)).unwrap();

        // Switch to child as current and exit
        mgr.current_pid = Pid::new(2);

        // exit() diverges (loop), so we replicate its logic instead of calling it
        // Directly test the zombie state by doing what exit does without the loop.
        let task_ptr = mgr.current().unwrap();
        unsafe {
            let task = &mut *task_ptr;
            task.exit_code = (42 & 0xFF) << 8;
            task.task_flags |= TaskFlags::Exiting as u32;
            mgr.reparent_children(task.pid, Pid::new(1));
            task.sched.state = TaskState::Zombie;
        }

        // Verify zombie state
        let task_ptr = mgr.get_task(Pid::new(2)).unwrap();
        unsafe {
            assert_eq!((*task_ptr).sched.state, TaskState::Zombie);
            assert_eq!((*task_ptr).exit_code, 42 << 8);
            assert!((*task_ptr).task_flags & TaskFlags::Exiting as u32 != 0);
        }
    }

    #[test]
    fn exit_reparents_children() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Create a child of parent (PID 2) and a grandchild (PID 3)
        let mut child = make_task(2);
        child.ppid = Pid::new(10);
        mgr.pids.alloc_specific(Pid::new(2)).unwrap();
        mgr.register(&mut *child as *mut Task);

        let mut grandchild = make_task(3);
        grandchild.ppid = Pid::new(2);
        mgr.pids.alloc_specific(Pid::new(3)).unwrap();
        mgr.register(&mut *grandchild as *mut Task);

        // "exit" the child (PID 2) — reparent grandchild to init
        mgr.current_pid = Pid::new(2);
        let task_ptr = mgr.current().unwrap();
        unsafe {
            let task = &mut *task_ptr;
            task.exit_code = 0;
            task.task_flags |= TaskFlags::Exiting as u32;
            mgr.reparent_children(task.pid, Pid::new(1));
            task.sched.state = TaskState::Zombie;
        }

        // Verify grandchild is now parented to PID 1
        let gc_ptr = mgr.get_task(Pid::new(3)).unwrap();
        unsafe {
            assert_eq!((*gc_ptr).ppid, Pid::new(1), "grandchild should be reparented to init");
        }
    }

    #[test]
    fn exit_sends_sigchld() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Attach a SignalCold to parent so SIGCHLD can be delivered
        let mut parent_sig_cold = Box::new(SignalCold::new());
        unsafe {
            let p = &mut *mgr.get_task(Pid::new(10)).unwrap();
            p.sig_cold = &mut *parent_sig_cold as *mut SignalCold;
        }

        // Create child
        let mut child = make_task(2);
        child.ppid = Pid::new(10);
        mgr.pids.alloc_specific(Pid::new(2)).unwrap();
        mgr.register(&mut *child as *mut Task);

        // Simulate exit of child — replicate the SIGCHLD sending logic from exit()
        mgr.current_pid = Pid::new(2);
        let task_ptr = mgr.current().unwrap();
        unsafe {
            let task = &mut *task_ptr;
            task.exit_code = 0;
            task.task_flags |= TaskFlags::Exiting as u32;
            mgr.reparent_children(task.pid, Pid::new(1));
            task.sched.state = TaskState::Zombie;

            // Send SIGCHLD to parent (replicating exit logic)
            if let Some(parent_ptr) = mgr.get_task(task.ppid) {
                let parent = &mut *parent_ptr;
                let info = crate::signal::SigInfo {
                    signo: Signal::Chld as u8,
                    code: crate::signal::SigCode::Kernel,
                    _pad0: [0; 2],
                    pid: task.pid,
                    uid: task.creds.uid,
                    _pad1: [0; 4],
                    addr: 0,
                    status: task.exit_code,
                    _pad2: [0; 4],
                };
                if !parent.sig_cold.is_null() {
                    let _ = (*parent.sig_cold).send_standard(
                        &mut parent.sig_hot,
                        Signal::Chld,
                        &info,
                    );
                }
            }
        }

        // Verify parent has SIGCHLD pending
        let parent_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            assert!(
                (*parent_ptr).sig_hot.pending.contains(Signal::Chld as u8),
                "parent should have SIGCHLD pending after child exit"
            );
        }
    }

    // ── wait tests ──────────────────────────────────────────────────────

    #[test]
    fn wait_reaps_zombie() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Fork a child: pre-register at PID 2
        let mut child = make_task(2);
        mgr.register(&mut *child as *mut Task);
        let child_pid = mgr.fork(0).expect("fork");
        assert_eq!(child_pid, Pid::new(2));

        // Make the child a zombie with exit code 7
        let child_ptr = mgr.get_task(child_pid).unwrap();
        unsafe {
            let c = &mut *child_ptr;
            c.exit_code = (7 & 0xFF) << 8;
            c.sched.state = TaskState::Zombie;
        }

        // Parent waits
        mgr.current_pid = Pid::new(10);
        let (reaped_pid, status) = mgr.wait(-1, 0).expect("wait should succeed");
        assert_eq!(reaped_pid, Pid::new(2));
        assert_eq!(status, ExitStatus::Code(7), "exit code should be 7");

        // Child should be unregistered
        assert!(mgr.get_task(Pid::new(2)).is_none(), "reaped child should be unregistered");
    }

    #[test]
    fn wait_no_children_error() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);
        // Parent has no children
        let err = mgr.wait(-1, 0).unwrap_err();
        assert_eq!(err, ProcError::NoChildren);
    }

    #[test]
    fn wait_nohang_no_zombie() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Fork a child
        let mut child = make_task(2);
        mgr.register(&mut *child as *mut Task);
        let _child_pid = mgr.fork(0).expect("fork");

        // Child is Ready (not Zombie) — WNOHANG should return TryAgain
        mgr.current_pid = Pid::new(10);
        let err = mgr.wait(-1, WaitOptions::NoHang as u32).unwrap_err();
        assert_eq!(err, ProcError::TryAgain);
    }

    // ── kill tests ──────────────────────────────────────────────────────

    #[test]
    fn kill_delivers_signal() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Create target task at PID 2
        let mut target = make_task(2);
        target.ppid = Pid::new(1);
        mgr.pids.alloc_specific(Pid::new(2)).unwrap();
        mgr.register(&mut *target as *mut Task);

        // Parent (PID 10, root creds) kills PID 2 with SIGUSR1
        let result = mgr.kill(2, Signal::Usr1);
        assert!(result.is_ok(), "kill should succeed");

        let target_ptr = mgr.get_task(Pid::new(2)).unwrap();
        unsafe {
            assert!(
                (*target_ptr).sig_hot.pending.contains(Signal::Usr1 as u8),
                "SIGUSR1 should be pending on target"
            );
        }
    }

    #[test]
    fn kill_permission_denied() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Make parent non-root with uid 1000
        let parent_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            (*parent_ptr).creds = Credentials::user(Uid::new(1000), Gid::new(1000));
        }

        // Create target with different uid 2000
        let mut target = make_task(2);
        target.creds = Credentials::user(Uid::new(2000), Gid::new(2000));
        mgr.pids.alloc_specific(Pid::new(2)).unwrap();
        mgr.register(&mut *target as *mut Task);

        let err = mgr.kill(2, Signal::Term).unwrap_err();
        assert_eq!(err, ProcError::PermissionDenied);
    }

    #[test]
    fn kill_wakes_interruptible() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Create sleeping target
        let mut target = make_task(2);
        target.sched.state = TaskState::Interruptible;
        mgr.pids.alloc_specific(Pid::new(2)).unwrap();
        mgr.register(&mut *target as *mut Task);

        mgr.kill(2, Signal::Usr1).expect("kill should succeed");

        let target_ptr = mgr.get_task(Pid::new(2)).unwrap();
        unsafe {
            assert_eq!(
                (*target_ptr).sched.state,
                TaskState::Ready,
                "interruptible task should be woken to Ready"
            );
        }
    }

    // ── getpid / getppid tests ──────────────────────────────────────────

    #[test]
    fn getpid_returns_tgid() {
        let (mgr, _init, _parent) = setup_with_parent(10);
        // Set a different tgid on the parent (simulate a thread)
        let parent_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            (*parent_ptr).tgid = Tgid::new(5);
        }
        let reported = mgr.getpid();
        assert_eq!(reported, Pid::new(5), "getpid should return tgid, not raw pid");
    }

    #[test]
    fn getppid_returns_parent() {
        let (mgr, _init, _parent) = setup_with_parent(10);
        let parent_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            (*parent_ptr).ppid = Pid::new(1);
        }
        let ppid = mgr.getppid();
        assert_eq!(ppid, Pid::new(1));
    }

    // ── setpgid / setsid tests ──────────────────────────────────────────

    #[test]
    fn setpgid_changes_group() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);
        mgr.setpgid(Pid::new(10), Pgid::new(99)).expect("setpgid should succeed");

        let task_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            assert_eq!((*task_ptr).pgid, Pgid::new(99), "pgid should be changed to 99");
        }
    }

    #[test]
    fn setsid_creates_session() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);
        let sid = mgr.setsid().expect("setsid should succeed");

        assert_eq!(sid, Sid::new(10), "setsid should return new sid == pid");

        let task_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            assert_eq!((*task_ptr).sid, Sid::new(10), "sid should be set to pid");
            assert_eq!((*task_ptr).pgid, Pgid::new(10), "pgid should be set to pid");
        }
    }

    // ── exec tests ──────────────────────────────────────────────────────

    #[test]
    fn exec_closes_cloexec() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Set up an FdTable with some fds, some CLOEXEC
        let mut fd_table = Box::new(FdTable::new());
        let fd0 = fd_table.open(100, 0).unwrap(); // no CLOEXEC
        let fd1 = fd_table.open(200, 0).unwrap();
        fd_table.get_mut(fd1).unwrap().fd_flags = FD_CLOEXEC;
        let fd2 = fd_table.open(300, 0).unwrap();
        fd_table.get_mut(fd2).unwrap().fd_flags = FD_CLOEXEC;
        assert_eq!(fd_table.count, 3);

        // Attach fd_table to current task
        let task_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            (*task_ptr).fd_table = &mut *fd_table as *mut FdTable;
        }

        // exec
        mgr.exec(b"/bin/test", &[], &[]).expect("exec should succeed");

        // Verify: fd0 should remain, fd1 and fd2 (CLOEXEC) should be closed
        assert!(fd_table.entries[fd0 as usize].is_open(), "fd0 without CLOEXEC should remain open");
        assert!(!fd_table.entries[fd1 as usize].is_open(), "fd1 with CLOEXEC should be closed");
        assert!(!fd_table.entries[fd2 as usize].is_open(), "fd2 with CLOEXEC should be closed");
        assert_eq!(fd_table.count, 1, "only 1 fd should remain");
    }

    #[test]
    fn exec_resets_signal_handlers() {
        let (mut mgr, _init, _parent) = setup_with_parent(10);

        // Set up SignalCold with a User handler on SIGUSR1
        let mut sig_cold = Box::new(SignalCold::new());
        let user_action = SignalAction {
            handler_type: SignalHandler::User,
            _pad0: [0; 7],
            handler: 0xCAFE,
            mask: SignalSet::EMPTY,
            flags: 0,
            _pad1: [0; 4],
        };
        sig_cold.set_action(Signal::Usr1, user_action).unwrap();

        // Also set an Ignore handler on SIGPIPE — this should survive exec
        sig_cold.set_action(Signal::Pipe, SignalAction::IGNORE).unwrap();

        // Attach sig_cold to current task
        let task_ptr = mgr.get_task(Pid::new(10)).unwrap();
        unsafe {
            (*task_ptr).sig_cold = &mut *sig_cold as *mut SignalCold;
        }

        // exec
        mgr.exec(b"/bin/test", &[], &[]).expect("exec should succeed");

        // Verify: User handler should be reset to Default
        let usr1_action = sig_cold.get_action(Signal::Usr1);
        assert_eq!(
            usr1_action.handler_type,
            SignalHandler::Default,
            "User handler should be reset to Default after exec"
        );

        // Verify: Ignore handler should survive exec
        let pipe_action = sig_cold.get_action(Signal::Pipe);
        assert_eq!(
            pipe_action.handler_type,
            SignalHandler::Ignore,
            "Ignore handler should survive exec"
        );
    }
}
