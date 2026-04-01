//! Memory mapping and poll syscalls.

use rux_fs::fdtable as fdt;

/// mmap(addr, len, prot, flags, fd, offset) — POSIX.1
///
/// Supports MAP_ANONYMOUS (zeroed pages) and MAP_PRIVATE file-backed
/// (reads file data into private pages). MAP_SHARED is not yet supported.
pub fn mmap(addr: usize, len: usize, prot: usize, mmap_flags: usize, fd: usize) -> isize {
    const MAP_FIXED: usize = 0x10;
    const MAP_ANONYMOUS: usize = 0x20;
    const PROT_READ: usize = 1;
    const PROT_WRITE: usize = 2;
    const PROT_EXEC: usize = 4;

    if len == 0 { return -22; }

    unsafe {
        let aligned_len = (len + 0xFFF) & !0xFFF;
        let result = if mmap_flags & MAP_FIXED != 0 && addr != 0 {
            addr & !0xFFF
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
        // Default: at least readable
        if prot == 0 { pg_flags = pg_flags.or(rux_mm::MappingFlags::READ); }

        // Allocate zeroed pages
        super::map_user_pages(result, result + aligned_len, pg_flags);

        // File-backed MAP_PRIVATE: read file data into the freshly mapped pages
        if mmap_flags & MAP_ANONYMOUS == 0 && fd < 64 {
            use rux_fs::FileSystem;
            let fs = crate::kstate::fs();
            let ino = (*rux_fs::fdtable::FD_TABLE)[fd].ino;
            if (*rux_fs::fdtable::FD_TABLE)[fd].active && ino != 0 {
                let offset = (*rux_fs::fdtable::FD_TABLE)[fd].offset as u64;
                let dst = core::slice::from_raw_parts_mut(result as *mut u8, len);
                let _ = fs.read(ino, offset, dst);
            }
        }

        result as isize
    }
}

/// munmap(addr, length) — POSIX.1: unmap pages from address space.
/// COW-aware: only frees frames whose refcount reaches zero.
pub fn munmap(addr: usize, len: usize) -> isize {
    if addr & 0xFFF != 0 { return -22; } // must be page-aligned
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

/// poll(fds, nfds, timeout) — POSIX.1: check fd readiness.
/// Returns number of fds with events, or 0 on timeout.
pub fn poll(fds_ptr: usize, nfds: usize, _timeout: usize) -> isize {
    if fds_ptr == 0 || nfds == 0 { return 0; }
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
            if f.active || fd <= 2 {
                // Console fds and active fds are always ready for I/O
                if events & 1 != 0 { revents |= 1; }   // POLLIN
                if events & 4 != 0 { revents |= 4; }   // POLLOUT
            } else {
                revents = 0x20; // POLLNVAL
            }

            *revents_ptr = revents;
            if revents != 0 { ready += 1; }
        }
        ready as isize
    }
}
