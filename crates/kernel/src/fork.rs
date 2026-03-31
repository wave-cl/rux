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
    use rux_arch::ConsoleOps;
    crate::arch::Arch::write_str("rux: fork()\n");

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
    child.in_vfork_child = false;
    child.signal_hot = parent.signal_hot;
    // Don't copy signal_cold (handlers) — child inherits via PROCESS global
    child.signal_restorer = parent.signal_restorer;
    child.last_child_exit = 0;
    child.child_available = false;
    child.exit_code = 0;
    child.wake_at = 0;

    // 4. Copy FD table + bump pipe refcounts
    for i in 0..64 {
        child.fds[i] = parent.fds[i];
        if child.fds[i].active && child.fds[i].is_pipe {
            (crate::pipe::PIPE.dup_ref)(child.fds[i].pipe_id, child.fds[i].pipe_write);
        }
    }

    // 5. Copy address space (full page copy, no COW)
    let alloc = crate::kstate::alloc();
    child.pt_root = copy_address_space(parent.pt_root, alloc);

    // 6. Set up child kernel stack
    child.kstack_top = KSTACKS[child_idx].as_ptr() as usize + KSTACK_SIZE;
    child.saved_user_sp = parent.saved_user_sp;
    child.tls = parent.tls;

    #[cfg(target_arch = "x86_64")]
    {
        child.saved_ksp = setup_child_kstack_x86(child.kstack_top);
    }
    #[cfg(target_arch = "aarch64")]
    {
        child.saved_ksp = setup_child_kstack_aarch64(child.kstack_top);
    }

    // 7. Enqueue child in scheduler
    use rux_sched::SchedClassOps;
    let sched = crate::scheduler::get();
    let task = &mut sched.tasks[child_idx];
    task.active = true;
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

/// Sync current PROCESS/FD_TABLE globals into the given task slot.
unsafe fn sync_globals_to_slot(idx: usize) {
    let slot = &mut TASK_TABLE[idx];
    slot.program_brk = crate::syscall::PROCESS.program_brk;
    slot.mmap_base = crate::syscall::PROCESS.mmap_base;
    slot.fs_ctx = crate::syscall::PROCESS.fs_ctx;
    slot.in_vfork_child = crate::syscall::PROCESS.in_vfork_child;
    slot.signal_hot = crate::syscall::PROCESS.signal_hot;
    slot.signal_restorer = crate::syscall::PROCESS.signal_restorer;
    slot.last_child_exit = crate::syscall::PROCESS.last_child_exit;
    slot.child_available = crate::syscall::PROCESS.child_available;
    for i in 0..64 { slot.fds[i] = rux_fs::fdtable::FD_TABLE[i]; }

    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "aarch64")]
    {
        let sp: u64;
        core::arch::asm!("mrs {}, sp_el0", out(reg) sp, options(nostack));
        slot.saved_user_sp = sp as usize;
        let tls: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls, options(nostack));
        slot.tls = tls;
        let ttbr: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr, options(nostack));
        slot.pt_root = ttbr;
    }
}

/// Copy the parent's user address space into a fresh page table.
/// Returns the new page table root physical address.
unsafe fn copy_address_space(parent_pt_root: u64, alloc: &mut dyn rux_mm::FrameAllocator) -> u64 {
    use rux_mm::FrameAllocator;

    let parent_pt = crate::arch::PageTable::from_root(PhysAddr::new(parent_pt_root as usize));

    // Create child page table with kernel identity map
    let mut child_pt = crate::arch::PageTable::new(alloc).expect("child PT alloc");
    {
        use crate::arch::KernelMapOps;
        crate::arch::Arch::map_kernel_pages(&mut child_pt, alloc);
    }

    // Full user page permissions for the copy
    let user_rwx = rux_mm::MappingFlags::USER
        .or(rux_mm::MappingFlags::READ)
        .or(rux_mm::MappingFlags::WRITE)
        .or(rux_mm::MappingFlags::EXECUTE);

    // Walk parent's user pages, copy each frame, map in child
    parent_pt.walk_user_pages(|va, pa, _flags| {
        let new_frame = alloc.alloc(rux_mm::PageSize::FourK).expect("fork frame");
        core::ptr::copy_nonoverlapping(
            pa.as_usize() as *const u8,
            new_frame.as_usize() as *mut u8,
            4096,
        );
        let _ = child_pt.map_4k(va, new_frame, user_rwx, alloc);
    });

    child_pt.root_phys().as_usize() as u64
}

// ── x86_64 child kernel stack setup ──────────────────────────────────

#[cfg(target_arch = "x86_64")]
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
    for i in (1..=15u64).rev() {
        sp -= w;
        let val = *parent_top.sub(i as usize);
        if i == 9 {
            // rax slot (sub(9)): set to 0 for child fork return
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

#[cfg(target_arch = "aarch64")]
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
