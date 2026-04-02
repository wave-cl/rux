//! fork() syscall implementation.
//!
//! Creates a child process with a full copy of the parent's address space,
//! file descriptors, and signal state. The child returns 0 from fork();
//! the parent returns the child's PID.

use crate::task_table::*;
use rux_klib::{PhysAddr, VirtAddr};

/// fork() syscall entry point.
///
/// # Safety
/// Manipulates page tables, kernel stacks, and scheduler state.
pub unsafe fn sys_fork() -> isize {
    // 1. Allocate child task slot
    let child_idx = match alloc_task_slot() {
        Some(idx) => idx,
        None => return -11, // -EAGAIN (no free slots)
    };
    let child_pid = alloc_pid();
    let parent_idx = current_task_idx();

    // 2. Sync current globals to parent slot (may be stale)
    sync_globals_to_slot(parent_idx);

    // 3. Copy parent state to child
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

    child.signal_hot = parent.signal_hot;
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
    child.tgid = child_pid; // new process = new thread group
    child.clone_flags = 0;

    // 4. Copy FD table + bump pipe refcounts
    for i in 0..64 {
        child.fds[i] = parent.fds[i];
        if child.fds[i].active && child.fds[i].is_pipe {
            (crate::pipe::PIPE.dup_ref)(child.fds[i].pipe_id, child.fds[i].pipe_write);
        }
    }

    // 5. Share address space with COW (mark all user pages read-only + COW bit)
    let alloc = crate::kstate::alloc();
    child.pt_root = cow_fork_address_space(parent.pt_root, alloc);

    // 6. Set up child kernel stack + ASID
    child.kstack_top = KSTACKS[child_idx].as_ptr() as usize + KSTACK_SIZE;
    child.saved_user_sp = parent.saved_user_sp;
    child.tls = parent.tls;
    child.asid = (child_idx as u16) + 1; // ASID 0 = kernel, 1..N = processes

    #[cfg(not(feature = "native"))]
    {
        use rux_arch::ForkOps;
        child.saved_ksp = crate::arch::Arch::setup_child_kstack(child.kstack_top);
    }
    #[cfg(feature = "native")]
    {
        child.saved_ksp = 0; // no actual context switch in native mode
    }

    // 7. Enqueue child in scheduler
    use rux_sched::SchedClassOps;
    let sched = crate::scheduler::get();
    let task = &mut sched.tasks[child_idx];
    task.active = true;
    task.saved_sp = TASK_TABLE[child_idx].saved_ksp; // context_switch reads this
    task.entity = rux_sched::entity::SchedEntity::new(child_idx as u64);
    task.entity.state = rux_sched::TaskState::Ready;
    task.entity.nice = 0;
    sched.cfs.set_clock(0, sched.clock_ns);
    sched.cfs.enqueue(0, &mut task.entity, rux_sched::fair::constants::WF_FORK);

    // 8. Mark parent as having a child available (for wait)
    TASK_TABLE[parent_idx].child_available = true;
    crate::syscall::PROCESS.child_available = true;

    child_pid as isize
}

// ── Clone flags ──────────────────────────────────────────────────────

const CLONE_VM: usize = 0x100;
const CLONE_FS: usize = 0x200;
const CLONE_FILES: usize = 0x400;
const CLONE_SIGHAND: usize = 0x800;
const CLONE_THREAD: usize = 0x10000;
const CLONE_CHILD_CLEARTID: usize = 0x200000;

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
        None => return -11,
    };
    let child_pid = alloc_pid();
    let parent_idx = current_task_idx();

    sync_globals_to_slot(parent_idx);

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

    child.signal_hot = rux_proc::signal::SignalHot::new(); // threads start with no pending signals
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
    child.clone_flags = flags as u32;
    child.clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 { child_tid_ptr } else { 0 };

    // CLONE_THREAD: same thread group (getpid returns parent's tgid)
    child.tgid = if flags & CLONE_THREAD != 0 { parent.tgid } else { child_pid };

    // CLONE_VM: share address space (same page table, no COW)
    child.pt_root = parent.pt_root;
    child.asid = parent.asid; // same ASID since same address space

    // CLONE_FILES: share FD table (copy parent's FDs to child slot)
    // In the pointer-swap model, each task has its own fds array.
    // For threads, we copy the parent's FDs so both start with the same view.
    for i in 0..64 {
        child.fds[i] = parent.fds[i];
        if child.fds[i].active && child.fds[i].is_pipe {
            (crate::pipe::PIPE.dup_ref)(child.fds[i].pipe_id, child.fds[i].pipe_write);
        }
    }

    // Set up child kernel stack with user stack from clone argument
    child.kstack_top = KSTACKS[child_idx].as_ptr() as usize + KSTACK_SIZE;
    child.saved_user_sp = if child_stack != 0 { child_stack } else { parent.saved_user_sp };
    child.tls = parent.tls;

    #[cfg(not(feature = "native"))]
    {
        use rux_arch::ForkOps;
        child.saved_ksp = crate::arch::Arch::setup_child_kstack(child.kstack_top);
    }
    #[cfg(feature = "native")]
    {
        child.saved_ksp = 0;
    }

    // Enqueue child
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

    // Write child tid to user space if requested
    if child_tid_ptr != 0 {
        *(child_tid_ptr as *mut u32) = child_pid;
    }

    child_pid as isize
}

/// Sync current PROCESS/FD_TABLE globals into the given task slot.
unsafe fn sync_globals_to_slot(idx: usize) {
    let slot = &mut TASK_TABLE[idx];
    slot.program_brk = crate::syscall::PROCESS.program_brk;
    slot.mmap_base = crate::syscall::PROCESS.mmap_base;
    slot.fs_ctx = crate::syscall::PROCESS.fs_ctx;
    slot.signal_hot = crate::syscall::PROCESS.signal_hot;
    slot.signal_restorer = crate::syscall::PROCESS.signal_restorer;
    slot.last_child_exit = crate::syscall::PROCESS.last_child_exit;
    slot.child_available = crate::syscall::PROCESS.child_available;
    // FD_TABLE is a pointer into slot.fds — no copy needed.

    #[cfg(not(feature = "native"))]
    {
        use rux_arch::ForkOps;
        crate::arch::Arch::snapshot_hw_state(
            &mut slot.saved_user_sp,
            &mut slot.tls,
            &mut slot.pt_root,
        );
    }
    #[cfg(feature = "native")]
    {
        slot.saved_user_sp = 0;
        slot.tls = 0;
        slot.pt_root = 0;
    }
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
    use rux_mm::FrameAllocator;

    let parent_pt = crate::arch::PageTable::from_root(PhysAddr::new(parent_pt_root as usize));

    // Create child page table with kernel identity map
    let mut child_pt = crate::arch::PageTable::new(alloc).expect("child PT alloc");
    {
        use crate::arch::KernelMapOps;
        crate::arch::Arch::map_kernel_pages(&mut child_pt, alloc);
    }

    // Initial mapping for shared pages: user-readable + executable, no write.
    let user_rx = rux_mm::MappingFlags::USER
        .or(rux_mm::MappingFlags::READ)
        .or(rux_mm::MappingFlags::EXECUTE);

    let cow = crate::arch::PageTable::cow_bit();

    // Precompute raw PTE flags for child COW pages (user, read-only, COW bit set).
    let cow_child_flags = crate::arch::PageTable::pte_flags(user_rx) | cow;

    // Walk parent's user pages with mutable PTE access. For each page:
    // 1. Mark parent COW inline (no re-walk)
    // 2. Map child with pre-computed COW flags in a single walk (map_4k_raw)
    parent_pt.walk_user_pages_mut(|va, pa, parent_pte| {
        use rux_arch::pte::PageTableEntryOps;
        crate::arch::ArchPte::set_writable(parent_pte, false);
        parent_pte.0 |= cow;

        let _ = child_pt.map_4k_raw(va, pa, cow_child_flags, alloc);

        crate::cow::inc_ref(pa);
        crate::cow::inc_ref(pa);
    });

    // Single full TLB flush after all parent pages are marked COW.
    crate::arch::PageTable::flush_tlb_all();

    child_pt.root_phys().as_usize() as u64
}
