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
    let parent_idx = CURRENT_TASK_IDX;

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
    // TODO: per-process signal_cold (adding to TaskSlot breaks aarch64)
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

    #[cfg(all(target_arch = "x86_64", not(feature = "native")))]
    {
        child.saved_ksp = setup_child_kstack_x86(child.kstack_top);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "native")))]
    {
        child.saved_ksp = setup_child_kstack_aarch64(child.kstack_top);
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
    let parent_idx = CURRENT_TASK_IDX;

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
    // TODO: per-process signal_cold (adding to TaskSlot breaks aarch64)
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

    #[cfg(all(target_arch = "x86_64", not(feature = "native")))]
    {
        child.saved_ksp = setup_child_kstack_x86(child.kstack_top);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "native")))]
    {
        child.saved_ksp = setup_child_kstack_aarch64(child.kstack_top);
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

    #[cfg(all(target_arch = "x86_64", not(feature = "native")))]
    {
        slot.saved_user_sp = crate::arch::x86_64::syscall::SAVED_USER_RSP as usize;
        let lo: u32; let hi: u32;
        core::arch::asm!("rdmsr", in("ecx") 0xC0000100u32, out("eax") lo, out("edx") hi, options(nostack));
        slot.tls = (hi as u64) << 32 | lo as u64;
        slot.pt_root = {
            let cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
            cr3
        };
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "native")))]
    {
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        slot.saved_user_sp = sp as usize;
        let tls: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls, options(nostack));
        slot.tls = tls;
        let ttbr: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nostack));
        slot.pt_root = ttbr & 0x0000_FFFF_FFFF_FFFF; // mask out ASID bits [63:48]
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
    // Computed once, used for every page in the walk.
    let cow_child_flags = crate::arch::PageTable::pte_flags(user_rx) | cow;

    // Walk parent's user pages with mutable PTE access. For each page:
    // 1. Mark parent COW inline (no re-walk)
    // 2. Map child with pre-computed COW flags in a single walk (map_4k_raw)
    // Previous: 3 child walks/page (unmap + map + leaf_pte_and_pa).
    // Now: 1 child walk/page (map_4k_raw).
    parent_pt.walk_user_pages_mut(|va, pa, parent_pte| {
        use rux_arch::pte::PageTableEntryOps;
        crate::arch::ArchPte::set_writable(parent_pte, false);
        parent_pte.0 |= cow;

        let _ = child_pt.map_4k_raw(va, pa, cow_child_flags, alloc);

        crate::cow::inc_ref(pa);
        crate::cow::inc_ref(pa);
    });

    // Single full TLB flush after all parent pages are marked COW.
    // This replaces N individual invlpg/tlbi calls with one batch flush.
    crate::arch::PageTable::flush_tlb_all();

    child_pt.root_phys().as_usize() as u64
}

// ── x86_64 child kernel stack setup ──────────────────────────────────

#[cfg(all(target_arch = "x86_64", not(feature = "native")))]
unsafe fn setup_child_kstack_x86(kstack_top: usize) -> usize {
    let w = core::mem::size_of::<u64>();
    let mut sp = kstack_top;

    // Read parent's saved registers from the current kernel stack.
    // CURRENT_KSTACK_TOP points to the top; the SYSCALL entry pushed
    // 15 values below it: rcx, r11, rbx, rbp, r12, r13, r14, r15,
    // rax, rdi, rsi, rdx, r10, r8, r9
    let parent_top = crate::arch::x86_64::syscall::CURRENT_KSTACK_TOP as *const u64;

    // Push syscall frame (same layout as syscall_entry pushes)
    // Positions: sub(1)=rcx, sub(2)=r11, ..., sub(15)=r9
    // We push bottom-first (r9 at lowest address, rcx at highest)
    // Push syscall frame so fork_child_sysret can pop it correctly.
    // fork_child_sysret pops: r9, r8, r10, rdx, rsi, rdi, rax, r15, r14, r13, r12, rbp, rbx, r11, rcx
    // The stack grows DOWN; fork_child_sysret pops UP (from low addr to high addr).
    // So we push in order rcx→r11→...→r9 (i=1→15), putting rcx at HIGH addr and r9 at LOW addr.
    // syscall_entry push order: rcx(sub(1)), r11(sub(2)), ..., r9(sub(15)).
    for i in 1..=15u64 {
        sp -= w;
        let val = *parent_top.sub(i as usize);
        if i == 9 {
            // rax slot (sub(9)): set to 0 for child fork return value
            *(sp as *mut u64) = 0;
        } else {
            *(sp as *mut u64) = val;
        }
    }

    // Push context_switch frame: r15, r14, r13, r12, rbx, rbp, rip
    sp -= w; *(sp as *mut usize) = crate::arch::x86_64::syscall::fork_child_sysret as usize; // rip
    sp -= w; *(sp as *mut usize) = 0; // rbp
    sp -= w; *(sp as *mut usize) = 0; // rbx
    sp -= w; *(sp as *mut usize) = 0; // r12
    sp -= w; *(sp as *mut usize) = 0; // r13
    sp -= w; *(sp as *mut usize) = 0; // r14
    sp -= w; *(sp as *mut usize) = 0; // r15

    sp
}

// ── aarch64 child kernel stack setup ─────────────────────────────────

#[cfg(all(target_arch = "aarch64", not(feature = "native")))]
unsafe fn setup_child_kstack_aarch64(kstack_top: usize) -> usize {
    // The parent's exception frame (34 u64s = 272 bytes) is on the current
    // kernel stack. CURRENT_REGS_PTR points to the base of this frame.
    let parent_regs = crate::arch::aarch64::syscall::CURRENT_REGS_PTR;

    let mut sp = kstack_top & !0xF; // 16-byte align

    // Push exception frame (272 bytes)
    sp -= 272;
    let frame = sp as *mut u64;
    for i in 0..34 {
        *frame.add(i) = *parent_regs.add(i);
    }
    // x0 = 0 (fork return value for child)
    *frame.add(0) = 0;

    // Push context_switch callee-saved frame (6 pairs = 96 bytes)
    sp -= 96;
    let ctx = sp as *mut usize;
    *ctx.add(0) = 0;  // x29 (FP)
    *ctx.add(1) = crate::arch::aarch64::context::fork_child_eret as usize; // x30 (LR)
    for i in 2..12 { *ctx.add(i) = 0; } // x27-x20, x19

    sp
}
