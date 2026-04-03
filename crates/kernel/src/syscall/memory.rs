//! Memory mapping and poll syscalls.

use rux_fs::fdtable as fdt;

/// mmap(addr, len, prot, flags, fd, offset) — POSIX.1
///
/// Supports MAP_ANONYMOUS (zeroed pages) and MAP_PRIVATE file-backed
/// (reads file data into private pages). MAP_SHARED is not yet supported.
pub fn mmap(addr: usize, len: usize, prot: usize, mmap_flags: usize, fd: usize, offset: usize) -> isize {
    const MAP_FIXED: usize = 0x10;
    const MAP_ANONYMOUS: usize = 0x20;
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    if len == 0 { return crate::errno::EINVAL; }

    unsafe {
        let aligned_len = (len + 0xFFF) & !0xFFF;

        // Trace mmap calls (temporary debug)
        let result = if mmap_flags & MAP_FIXED != 0 && addr != 0 {
            let fixed_addr = addr & !0xFFF;
            // Unmap existing pages to avoid double-mapping (ld.so uses MAP_FIXED
            // to replace segments at exact addresses).
            munmap(fixed_addr, aligned_len);
            fixed_addr
        } else {
            let r = super::PROCESS.mmap_base;
            super::PROCESS.mmap_base += aligned_len;
            r
        };

        // Build page flags from prot
        let mut pg_flags = rux_mm::MappingFlags::USER;
        if prot & PROT_READ != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::READ); }
        if prot & PROT_WRITE != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::WRITE); }
        if prot & PROT_EXEC != 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::EXECUTE); }
        if prot == 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::READ); }

        // Allocate zeroed pages
        super::map_user_pages(result, result + aligned_len, pg_flags);

        // File-backed MAP_PRIVATE: read file data at the specified offset
        if mmap_flags & MAP_ANONYMOUS == 0 && fd < 64 {
            use rux_fs::FileSystem;
            let fs = crate::kstate::fs();
            let ino = (*rux_fs::fdtable::FD_TABLE)[fd].ino;
            if (*rux_fs::fdtable::FD_TABLE)[fd].active && ino != 0 {
                let file_offset = offset as u64;
                let dst = core::slice::from_raw_parts_mut(result as *mut u8, len);
                let _ = fs.read(ino, file_offset, dst);
            }
        }

        result as isize
    }
}

/// munmap(addr, length) — POSIX.1: unmap pages from address space.
/// COW-aware: only frees frames whose refcount reaches zero.
pub fn munmap(addr: usize, len: usize) -> isize {
    if addr & 0xFFF != 0 { return crate::errno::EINVAL; } // must be page-aligned
    unsafe {
        let alloc = crate::kstate::alloc();
        let mut upt = super::current_user_page_table();

        let aligned_len = (len + 0xFFF) & !0xFFF;
        let mut va = addr;
        while va < addr + aligned_len {
            if let Ok(pa) = upt.translate(rux_klib::VirtAddr::new(va)) {
                let _ = upt.unmap_4k(rux_klib::VirtAddr::new(va));
                let page_pa = rux_klib::PhysAddr::new(pa.as_usize() & !0xFFF);
                use rux_mm::FrameAllocator;
                // COW-aware: only free if refcount drops to zero
                if page_pa.as_usize() >= alloc.alloc_base().as_usize() {
                    if crate::cow::dec_ref(page_pa) {
                        alloc.dealloc(page_pa, rux_mm::PageSize::FourK);
                    }
                }
            }
            va += 4096;
        }
    }
    0
}

// ── Futex ──────────────────────────────────────────────────────────────

/// futex(uaddr, op, val, ...) — Linux: fast userspace mutex.
/// Supports FUTEX_WAIT (block if *uaddr == val) and FUTEX_WAKE (wake N waiters).
pub fn futex(uaddr: usize, op: usize, val: usize) -> isize {
    const FUTEX_WAIT: usize = 0;
    const FUTEX_WAKE: usize = 1;

    match op & 0x7F { // mask off FUTEX_PRIVATE_FLAG
        FUTEX_WAIT => futex_wait(uaddr, val as u32),
        FUTEX_WAKE => futex_wake(uaddr, val),
        _ => 0, // unsupported ops succeed silently
    }
}

fn futex_wait(uaddr: usize, expected: u32) -> isize {
    unsafe {
        use crate::task_table::*;

        // Validate user pointer
        if uaddr < 0x1000 || uaddr >= 0x8000_0000_0000 {
            return crate::errno::EAGAIN;
        }

        // Check if the page is mapped before reading. If not, return EAGAIN
        // (the caller will retry after the page is faulted in).
        let upt = crate::syscall::current_user_page_table();
        if upt.translate(rux_klib::VirtAddr::new(uaddr & !0xFFF)).is_err() {
            return crate::errno::EAGAIN;
        }

        // Atomic check: if value changed since caller checked, return EAGAIN
        let p = uaddr as *const u8;
        let val: u32 = (*p.add(0) as u32) | ((*p.add(1) as u32) << 8)
                      | ((*p.add(2) as u32) << 16) | ((*p.add(3) as u32) << 24);
        if val != expected {
            return crate::errno::EAGAIN;
        }

        // Block until woken by FUTEX_WAKE
        let idx = current_task_idx();
        TASK_TABLE[idx].state = TaskState::WaitingForFutex;
        TASK_TABLE[idx].futex_addr = uaddr;
        let sched = crate::scheduler::get();
        sched.tasks[idx].entity.state = rux_sched::TaskState::Interruptible;
        sched.dequeue_current();
        sched.schedule();
        0
    }
}

/// Wake up to `max_wake` tasks waiting on the futex at `uaddr`.
/// Returns the number of tasks woken.
pub fn futex_wake(uaddr: usize, max_wake: usize) -> isize {
    unsafe {
        use crate::task_table::*;

        let sched = crate::scheduler::get();
        let mut woken = 0usize;
        for i in 0..MAX_PROCS {
            if woken >= max_wake { break; }
            if TASK_TABLE[i].active
                && TASK_TABLE[i].state == TaskState::WaitingForFutex
                && TASK_TABLE[i].futex_addr == uaddr
            {
                TASK_TABLE[i].state = TaskState::Ready;
                sched.wake_task(i);
                woken += 1;
            }
        }
        woken as isize
    }
}

/// pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask) — POSIX.1
/// Minimal implementation: checks socket FDs for readiness.
pub fn pselect6(nfds: usize, readfds_ptr: usize, writefds_ptr: usize, _exceptfds_ptr: usize, timeout_ptr: usize) -> isize {
    let nfds = nfds.min(64);

    // Parse timeout
    let timeout_ms = if timeout_ptr >= 0x10000 && timeout_ptr < 0x8000_0000_0000 {
        unsafe {
            let sec: u64 = crate::uaccess::get_user(timeout_ptr);
            let nsec: u64 = crate::uaccess::get_user(timeout_ptr + 8);
            let ms = sec * 1000 + nsec / 1_000_000;
            if ms > 30_000 { 30_000 } else { ms as usize }
        }
    } else { 5_000 };

    let read_set = if readfds_ptr != 0 { unsafe { *(readfds_ptr as *const u64) } } else { 0 };
    let write_set = if writefds_ptr != 0 { unsafe { *(writefds_ptr as *const u64) } } else { 0 };

    let has_sockets = unsafe {
        (0..nfds).any(|fd| {
            ((read_set | write_set) & (1u64 << fd)) != 0
                && fd < 64
                && super::socket::is_socket(fd)
        })
    };

    let max_iters = if has_sockets && timeout_ms > 0 { timeout_ms.min(30_000) } else { 1 };

    for _ in 0..max_iters {
        #[cfg(feature = "net")]
        if has_sockets {
            unsafe {
                use rux_arch::TimerOps;
                rux_net::poll(crate::arch::Arch::ticks());
            }
        }

        let mut ready = 0i32;
        let mut out_read: u64 = 0;
        let mut out_write: u64 = 0;

        for fd in 0..nfds {
            let bit = 1u64 << fd;
            if read_set & bit != 0 {
                if fd <= 2 || !super::socket::is_socket(fd) {
                    // Console/file FDs are always ready
                    out_read |= bit;
                    ready += 1;
                } else if super::socket::socket_has_data(fd) {
                    out_read |= bit;
                    ready += 1;
                }
            }
            if write_set & bit != 0 {
                if !super::socket::is_socket(fd) || super::socket::socket_can_write(fd) {
                    out_write |= bit;
                    ready += 1;
                }
            }
        }

        if ready > 0 {
            if readfds_ptr != 0 { unsafe { *(readfds_ptr as *mut u64) = out_read; } }
            if writefds_ptr != 0 { unsafe { *(writefds_ptr as *mut u64) = out_write; } }
            return ready as isize;
        }

        unsafe { use rux_arch::HaltOps; crate::arch::Arch::halt_until_interrupt(); }
    }

    // Timeout: clear all sets
    if readfds_ptr != 0 { unsafe { *(readfds_ptr as *mut u64) = 0; } }
    if writefds_ptr != 0 { unsafe { *(writefds_ptr as *mut u64) = 0; } }
    0
}

/// mprotect(addr, len, prot) — POSIX.1: change page protection.
pub fn mprotect(addr: usize, len: usize, prot: usize) -> isize {
    if addr & 0xFFF != 0 { return crate::errno::EINVAL; }
    unsafe {
        let upt = super::current_user_page_table();
        let aligned_len = (len + 0xFFF) & !0xFFF;

        let mut flags = rux_mm::MappingFlags::USER.or(rux_mm::MappingFlags::READ);
        if prot & 2 != 0 { flags = flags.or(rux_mm::MappingFlags::WRITE); }
        if prot & 4 != 0 { flags = flags.or(rux_mm::MappingFlags::EXECUTE); }

        let pte_flags = crate::arch::PageTable::pte_flags(flags);

        let mut va = addr;
        while va < addr + aligned_len {
            let virt = rux_klib::VirtAddr::new(va);
            if let Ok(pa) = upt.translate(virt) {
                let pa_page = rux_klib::PhysAddr::new(pa.as_usize() & !0xFFF);
                upt.remap(virt, pa_page, pte_flags);
            }
            va += 4096;
        }
    }
    0
}

/// poll(fds, nfds, timeout) — POSIX.1: check fd readiness.
/// Returns number of fds with events, or 0 on timeout.
/// ppoll wrapper: reads timeout from timespec pointer
pub fn ppoll(fds_ptr: usize, nfds: usize, timeout_ptr: usize, _sigmask: usize) -> isize {
    // timeout_ptr: NULL = wait forever, valid pointer = read timespec
    // Guard against invalid pointers (0xFFFFFFFF, low addresses in null guard)
    let timeout_ms = if timeout_ptr >= 0x10000 && timeout_ptr < 0x8000_0000_0000 {
        unsafe {
            let sec: u64 = crate::uaccess::get_user(timeout_ptr);
            let nsec: u64 = crate::uaccess::get_user(timeout_ptr + 8);
            let ms = sec * 1000 + nsec / 1_000_000;
            if ms > 30_000 { 30_000 } else { ms as usize }
        }
    } else { 5_000 }; // no timeout / invalid → 5s default (responsive enough for DNS)
    poll(fds_ptr, nfds, timeout_ms)
}

pub fn poll(fds_ptr: usize, nfds: usize, timeout_ms: usize) -> isize {
    if fds_ptr == 0 || nfds == 0 { return 0; }

    // For socket FDs: poll network and retry until data arrives or timeout
    let has_sockets = unsafe {
        (0..nfds.min(64)).any(|i| {
            let entry = (fds_ptr + i * 8) as *const u8;
            let fd = *(entry as *const i32) as usize;
            fd < 64 && super::socket::is_socket(fd)
        })
    };

    let max_iters = if has_sockets && timeout_ms > 0 {
        // Use actual timeout in ms. Each iteration with halt_until_interrupt ~1ms.
        timeout_ms.min(30_000) // cap at 30 seconds
    } else { 1 };

    for _attempt in 0..max_iters {
        // Poll smoltcp (drains all available frames in one call)
        #[cfg(feature = "net")]
        if has_sockets {
            unsafe {
                use rux_arch::TimerOps;
                rux_net::poll(crate::arch::Arch::ticks());
            }
        }

        unsafe {
            let mut ready = 0i32;
            for i in 0..nfds.min(64) {
            let entry = (fds_ptr + i * 8) as *mut u8;
            let fd = *(entry as *const i32) as usize;
            let events = *((entry as usize + 4) as *const i16);
            let revents_ptr = (entry as usize + 6) as *mut i16;

            if fd >= 64 { *revents_ptr = 0; continue; }

            let f = &(*fdt::FD_TABLE)[fd];
            let mut revents: i16 = 0;
            if f.active && f.is_socket {
                // Socket: check actual readiness
                if events & 4 != 0 {
                    // POLLOUT: ready if connected (not still in SYN_SENT)
                    if super::socket::socket_can_write(fd) {
                        revents |= 4;
                    }
                }
                if events & 1 != 0 {
                    // POLLIN: check if data is available
                    if super::socket::socket_has_data(fd) {
                        revents |= 1;
                    }
                }
            } else if f.active || fd <= 2 {
                // Console fds and regular file fds are always ready
                if events & 1 != 0 { revents |= 1; }   // POLLIN
                if events & 4 != 0 { revents |= 4; }   // POLLOUT
            } else {
                revents = 0x20; // POLLNVAL
            }

            *revents_ptr = revents;
            if revents != 0 { ready += 1; }
        }
        if ready > 0 { return ready as isize; }
        } // unsafe

        // Wait for next timer tick (yields CPU, allows timer ISR to process packets)
        unsafe { use rux_arch::HaltOps; crate::arch::Arch::halt_until_interrupt(); }
    }
    0 // timeout
}
