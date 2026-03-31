//! Memory mapping and poll syscalls.

pub fn mmap(addr: usize, len: usize, _prot: usize, mmap_flags: usize, _fd: usize) -> isize {
    unsafe {
        if mmap_flags & 0x20 == 0 { return -12; } // MAP_ANONYMOUS only

        let aligned_len = (len + 0xFFF) & !0xFFF;
        let result = if mmap_flags & 0x10 != 0 && addr != 0 {
            addr & !0xFFF // MAP_FIXED
        } else {
            let r = super::PROCESS.mmap_base;
            super::PROCESS.mmap_base += aligned_len;
            r
        };

        let pg_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::USER);
        super::map_user_pages(result, result + aligned_len, pg_flags);

        result as isize
    }
}

/// munmap(addr, length) — POSIX.1: unmap pages from address space.
pub fn munmap(addr: usize, len: usize) -> isize {
    if addr & 0xFFF != 0 { return -22; } // must be page-aligned
    unsafe {
        use rux_arch::PageTableRootOps;
        let alloc = crate::kstate::alloc();
        let root = crate::arch::Arch::read();
        let mut upt = crate::arch::PageTable::from_root(
            rux_klib::PhysAddr::new(root as usize));

        let aligned_len = (len + 0xFFF) & !0xFFF;
        let mut va = addr;
        while va < addr + aligned_len {
            if let Ok(pa) = upt.translate(rux_klib::VirtAddr::new(va)) {
                let _ = upt.unmap_4k(rux_klib::VirtAddr::new(va));
                let page_pa = pa.as_usize() & !0xFFF;
                if page_pa >= alloc.base.as_usize() {
                    use rux_mm::FrameAllocator;
                    alloc.dealloc(rux_klib::PhysAddr::new(page_pa), rux_mm::PageSize::FourK);
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

            let f = &fdt::FD_TABLE[fd];
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
