//! fork() and clone() syscall implementations.
//!
//! Creates child processes/threads. fork() creates a full COW copy;
//! clone() shares the address space (threads). Common setup is in
//! `init_child_slot()` and `enqueue_child()`.

use crate::task_table::*;
use rux_fs::fdtable::{OpenFile, MAX_FDS};
use rux_klib::PhysAddr;

use crate::errno::{CLONE_THREAD, CLONE_CHILD_CLEARTID};

// ── Shared helpers ───────────────────────────────────────────────────

/// Copy a parent's FD table to a child, bumping pipe reference counts.
#[inline]
unsafe fn copy_fds_with_pipe_refs(src: &[OpenFile; MAX_FDS], dst: &mut [OpenFile; MAX_FDS]) {
    for i in 0..MAX_FDS {
        dst[i] = src[i];
        if dst[i].active && dst[i].is_pipe {
            (crate::pipe::PIPE.dup_ref)(dst[i].pipe_id, dst[i].pipe_write);
        }
    }
}

/// Initialize common child task fields shared by fork() and clone().
#[inline]
unsafe fn init_child_slot(
    parent_idx: usize,
    child_idx: usize,
    child_pid: u32,
    inherit_signals: bool,
    clone_flags: u32,
    clear_child_tid: usize,
) {
    let parent = &TASK_TABLE[parent_idx];
    let child = &mut TASK_TABLE[child_idx];

    child.active = true;
    child.pid = child_pid;
    child.ppid = parent.pid;
    child.pgid = parent.pgid;
    child.state = TaskState::Ready;
    child.program_brk = parent.program_brk;
    child.mmap_base = parent.mmap_base;
    child.fs_ctx = parent.fs_ctx;

    // fork inherits parent's pending signals; clone starts fresh
    child.signal_hot = if inherit_signals {
        parent.signal_hot
    } else {
        rux_proc::signal::SignalHot::new()
    };
    // Signal handlers (cold) and restorer table always inherited
    core::ptr::copy_nonoverlapping(
        signal_cold_mut(parent_idx) as *const _ as *const u8,
        signal_cold_mut(child_idx) as *mut _ as *mut u8,
        core::mem::size_of::<rux_proc::signal::SignalCold>(),
    );
    child.signal_restorer = parent.signal_restorer;

    child.last_child_exit = 0;
    child.child_available = false;
    child.exit_code = 0;
    child.wake_at = 0;
    child.clone_flags = clone_flags;
    child.clear_child_tid = clear_child_tid;

    // Copy parent's TLS and user SP (caller may override for clone)
    child.saved_user_sp = parent.saved_user_sp;
    child.tls = parent.tls;

    // Copy parent's FPU/SIMD state
    child.fpu_state = parent.fpu_state;

    // Set up child kernel stack
    child.kstack_top = KSTACKS.0[child_idx].as_ptr() as usize + KSTACK_SIZE;
    {
        use rux_arch::ForkOps;
        child.saved_ksp = crate::arch::Arch::setup_child_kstack(child.kstack_top);
    }
}

/// Enqueue a newly created child task in the CFS scheduler.
#[inline]
unsafe fn enqueue_child(child_idx: usize) {
    use rux_sched::SchedClassOps;
    let sched = crate::scheduler::get();
    let task = &mut sched.tasks[child_idx];
    task.active = true;
    task.saved_sp = TASK_TABLE[child_idx].saved_ksp;
    task.entity = rux_sched::entity::SchedEntity::new(child_idx as u64);
    task.entity.state = rux_sched::TaskState::Ready;
    task.entity.nice = 0;
    sched.cfs.set_clock(0, sched.clock_ns);
    sched.cfs.enqueue(0, &mut task.entity, rux_sched::fair::constants::WF_FORK);
}

// ── fork() ───────────────────────────────────────────────────────────

/// fork() syscall entry point.
///
/// # Safety
/// Manipulates page tables, kernel stacks, and scheduler state.
pub unsafe fn sys_fork() -> isize {
    // Per-parent fork limit to prevent fork bombs (exclude zombies waiting for reap)
    let my_pid = TASK_TABLE[current_task_idx()].pid;
    let live_children = (0..MAX_PROCS).filter(|&i| {
        TASK_TABLE[i].active && TASK_TABLE[i].ppid == my_pid
            && TASK_TABLE[i].state != TaskState::Zombie
    }).count();
    if live_children >= 32 { return crate::errno::EAGAIN; }

    // Auto-reap zombie children to free task slots + page tables
    for i in 0..MAX_PROCS {
        if TASK_TABLE[i].active && TASK_TABLE[i].ppid == my_pid
            && TASK_TABLE[i].state == TaskState::Zombie
        {
            // Free child's page table (COW-aware)
            let child_pt_root = TASK_TABLE[i].pt_root;
            if child_pt_root != 0 {
                let alloc = crate::kstate::alloc();
                let child_pt = crate::arch::PageTable::from_root(
                    rux_klib::PhysAddr::new(child_pt_root as usize)
                );
                child_pt.free_user_address_space_cow(alloc, &mut |pa| crate::cow::dec_ref(pa));
                TASK_TABLE[i].pt_root = 0;
            }
            TASK_TABLE[i].active = false;
            TASK_TABLE[i].state = TaskState::Free;
        }
    }

    let child_idx = match alloc_task_slot() {
        Some(idx) => idx,
        None => return crate::errno::EAGAIN,
    };
    let child_pid = alloc_pid();
    let parent_idx = current_task_idx();

    sync_globals_to_slot(parent_idx);
    init_child_slot(parent_idx, child_idx, child_pid, true, 0, 0);

    // Copy FDs + COW fork address space
    copy_fds_with_pipe_refs(&TASK_TABLE[parent_idx].fds, &mut TASK_TABLE[child_idx].fds);
    let alloc = crate::kstate::alloc();
    TASK_TABLE[child_idx].pt_root = cow_fork_address_space(TASK_TABLE[parent_idx].pt_root, alloc);
    TASK_TABLE[child_idx].asid = (child_idx as u16) + 1;
    TASK_TABLE[child_idx].tgid = child_pid;

    enqueue_child(child_idx);

    // Notify parent
    TASK_TABLE[parent_idx].child_available = true;
    crate::syscall::PROCESS.child_available = true;

    child_pid as isize
}

// ── clone() ──────────────────────────────────────────────────────────

/// clone() syscall for threads (CLONE_VM set).
///
/// Creates a new task sharing the parent's address space. The child uses
/// `child_stack` as its user stack pointer. With CLONE_THREAD, the child
/// shares the parent's thread group (getpid returns the same tgid).
///
/// # Safety
/// Manipulates page tables, kernel stacks, and scheduler state.
pub unsafe fn sys_clone(flags: usize, child_stack: usize, child_tid_ptr: usize) -> isize {
    let child_idx = match alloc_task_slot() {
        Some(idx) => idx,
        None => return crate::errno::EAGAIN,
    };
    let child_pid = alloc_pid();
    let parent_idx = current_task_idx();

    sync_globals_to_slot(parent_idx);
    init_child_slot(
        parent_idx, child_idx, child_pid, false,
        flags as u32,
        if flags & CLONE_CHILD_CLEARTID != 0 { child_tid_ptr } else { 0 },
    );

    // CLONE_THREAD: same thread group
    let parent = &TASK_TABLE[parent_idx];
    TASK_TABLE[child_idx].tgid = if flags & CLONE_THREAD != 0 { parent.tgid } else { child_pid };

    // CLONE_VM: share address space (same page table, no COW)
    TASK_TABLE[child_idx].pt_root = parent.pt_root;
    TASK_TABLE[child_idx].asid = parent.asid;

    // Copy FDs (both fork and clone copy — threads start with same view)
    copy_fds_with_pipe_refs(&parent.fds, &mut TASK_TABLE[child_idx].fds);

    // Override user stack if provided
    if child_stack != 0 {
        TASK_TABLE[child_idx].saved_user_sp = child_stack;
    }

    enqueue_child(child_idx);

    // Write child tid to user space if requested
    if child_tid_ptr != 0 {
        crate::uaccess::put_user(child_tid_ptr, child_pid as u32);
    }

    child_pid as isize
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Sync current PROCESS/FD_TABLE globals into the given task slot.
#[inline]
unsafe fn sync_globals_to_slot(idx: usize) {
    let slot = &mut TASK_TABLE[idx];
    slot.program_brk = crate::syscall::PROCESS.program_brk;
    slot.mmap_base = crate::syscall::PROCESS.mmap_base;
    slot.fs_ctx = crate::syscall::PROCESS.fs_ctx;
    slot.signal_hot = crate::syscall::PROCESS.signal_hot;
    slot.signal_restorer = crate::syscall::PROCESS.signal_restorer;
    slot.last_child_exit = crate::syscall::PROCESS.last_child_exit;
    slot.child_available = crate::syscall::PROCESS.child_available;

    use rux_arch::ForkOps;
    crate::arch::Arch::snapshot_hw_state(
        &mut slot.saved_user_sp,
        &mut slot.tls,
        &mut slot.pt_root,
    );
}

/// Fork the parent's user address space using copy-on-write.
///
/// Both parent and child share the same physical frames initially.
/// All shared pages are marked read-only + COW bit in both page tables.
/// On the first write, a page fault fires and `handle_cow_fault` allocates a
/// private copy for the faulting process.
///
/// Each shared frame gets its refcount incremented twice (once per sharer).
/// Returns the child's new page table root physical address.
unsafe fn cow_fork_address_space(parent_pt_root: u64, alloc: &mut dyn rux_mm::FrameAllocator) -> u64 {
    let parent_pt = crate::arch::PageTable::from_root(PhysAddr::new(parent_pt_root as usize));

    // Create child page table with kernel identity map
    let mut child_pt = crate::arch::PageTable::new(alloc).expect("child PT alloc");
    {
        use crate::arch::KernelMapOps;
        crate::arch::Arch::map_kernel_pages(&mut child_pt, alloc);
    }

    let user_rx = rux_mm::MappingFlags::USER
        .or(rux_mm::MappingFlags::READ)
        .or(rux_mm::MappingFlags::EXECUTE);
    let cow = crate::arch::PageTable::cow_bit();
    let cow_child_flags = crate::arch::PageTable::pte_flags(user_rx) | cow;

    // Walk parent's user pages: mark parent COW inline + map child in one walk
    parent_pt.walk_user_pages_mut(|va, pa, parent_pte| {
        use rux_arch::pte::PageTableEntryOps;
        crate::arch::ArchPte::set_writable(parent_pte, false);
        parent_pte.0 |= cow;
        let _ = child_pt.map_4k_raw(va, pa, cow_child_flags, alloc);
        crate::cow::inc_ref(pa);
        crate::cow::inc_ref(pa);
    });

    crate::arch::PageTable::flush_tlb_all();
    child_pt.root_phys().as_usize() as u64
}
