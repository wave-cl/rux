/// Linux-specific syscall extensions.
///
/// These syscalls are Linux kernel extensions not defined by POSIX.
/// They provide Linux-specific functionality like brk heap management,
/// getdents64 directory format, exit_group, set_tid_address, etc.
///
/// Programs compiled for Linux (like busybox/musl) depend on these.

use super::arch;

// ── Pipes (Linux extension) ──────────────────────────────────────────

/// pipe2(pipefd, flags) — create a pipe.
pub fn pipe2(pipefd_ptr: u64, _flags: u64) -> i64 {
    if pipefd_ptr == 0 { return -14; } // -EFAULT
    match crate::pipe::create() {
        Ok((_pipe_id, read_fd, write_fd)) => {
            unsafe {
                let p = pipefd_ptr as *mut i32;
                *p = read_fd as i32;
                *p.add(1) = write_fd as i32;
            }
            0
        }
        Err(e) => e,
    }
}

// ── Memory: brk (Linux historical, not POSIX) ──────────────────────

/// brk(addr) — Linux-specific heap management.
/// POSIX does not define brk; portable programs use mmap instead.
pub fn brk(addr: u64) -> i64 {
    unsafe {
        if super::PROGRAM_BRK == 0 { super::PROGRAM_BRK = 0x800000; }
        if addr == 0 { return super::PROGRAM_BRK as i64; }
        if addr >= super::PROGRAM_BRK {
            use rux_mm::FrameAllocator;
            let old_page = (super::PROGRAM_BRK + 0xFFF) & !0xFFF;
            let new_page = (addr + 0xFFF) & !0xFFF;
            let alloc = crate::kstate::alloc();
            let cr3 = arch::page_table_root();
            let flags = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::USER);

            #[cfg(target_arch = "x86_64")]
            {
                let mut upt = crate::x86_64::paging::PageTable4Level::from_cr3(
                    rux_klib::PhysAddr::new(cr3 as usize));
                for pa in (old_page..new_page).step_by(4096) {
                    let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("brk page");
                    let ptr = frame.as_usize() as *mut u8;
                    for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
                    let va = rux_klib::VirtAddr::new(pa as usize);
                    let _ = upt.unmap_4k(va);
                    let _ = upt.map_4k(va, frame, flags, alloc);
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                let mut upt = crate::aarch64::paging::PageTable4Level::from_cr3(
                    rux_klib::PhysAddr::new(cr3 as usize));
                for pa in (old_page..new_page).step_by(4096) {
                    let frame = alloc.alloc(rux_mm::PageSize::FourK).expect("brk page");
                    let ptr = frame.as_usize() as *mut u8;
                    for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
                    let va = rux_klib::VirtAddr::new(pa as usize);
                    let _ = upt.unmap_4k(va);
                    let _ = upt.map_4k(va, frame, flags, alloc);
                }
            }

            super::PROGRAM_BRK = addr;
        }
        super::PROGRAM_BRK as i64
    }
}

// ── Directory listing (Linux-specific format) ───────────────────────

/// getdents64(fd, dirp, count) — Linux-specific.
///
/// POSIX uses readdir(3) which is a libc function, not a syscall.
/// Linux exposes the raw getdents64 syscall with its own struct format:
///   struct linux_dirent64 { u64 d_ino, d_off; u16 d_reclen; u8 d_type; char d_name[]; }
pub fn getdents64(fd: u64, buf_ptr: u64, bufsize: u64) -> i64 {
    unsafe {
        use rux_vfs::{FileSystem, DirEntry, InodeType};
        let fs = crate::kstate::fs();
        let out = buf_ptr as *mut u8;
        let limit = bufsize as usize;
        let mut pos = 0usize;

        let dir_ino = if fd >= 3 {
            match crate::fdtable::get_fd_inode(fd as usize) {
                Some(ino) => ino,
                None => return -9,
            }
        } else {
            0 // root
        };

        static mut DIR_OFFSET: [usize; 16] = [0; 16];
        let off_idx = (fd as usize).min(15);
        let mut offset = DIR_OFFSET[off_idx];
        let start_pos = pos;

        loop {
            let mut entry = core::mem::zeroed::<DirEntry>();
            match fs.readdir(dir_ino, offset, &mut entry) {
                Ok(true) => {
                    let nlen = entry.name_len as usize;
                    let reclen = ((19 + nlen + 1) + 7) & !7;
                    if pos + reclen > limit { break; }
                    *((out.add(pos)) as *mut u64) = entry.ino;
                    *((out.add(pos + 8)) as *mut u64) = (offset + 1) as u64;
                    *((out.add(pos + 16)) as *mut u16) = reclen as u16;
                    let dtype: u8 = match entry.kind {
                        InodeType::File => 8,       // DT_REG
                        InodeType::Directory => 4,  // DT_DIR
                        InodeType::Symlink => 10,   // DT_LNK
                        _ => 0,
                    };
                    *out.add(pos + 18) = dtype;
                    for i in 0..nlen { *out.add(pos + 19 + i) = entry.name[i]; }
                    *out.add(pos + 19 + nlen) = 0;
                    pos += reclen;
                    offset += 1;
                }
                _ => break,
            }
        }
        DIR_OFFSET[off_idx] = offset;
        if pos == start_pos { return 0; }
        pos as i64
    }
}

// ── Process extensions (Linux-specific) ─────────────────────────────

/// exit_group(status) — Linux-specific.
/// Exits all threads in the thread group. POSIX _exit only exits the calling thread.
pub fn exit_group(status: i32) -> ! {
    super::posix::exit(status) // same behavior for single-threaded
}

/// wait4(pid, wstatus, options, rusage) — Linux extension of POSIX waitpid.
/// Adds rusage parameter (which we ignore).
pub fn wait4(pid: u64, wstatus_ptr: u64, options: u64, _rusage: u64) -> i64 {
    super::posix::waitpid(pid, wstatus_ptr, options)
}

/// set_tid_address(tidptr) — Linux-specific TLS.
/// Stores the address for the clear_child_tid futex. Returns the caller's TID.
pub fn set_tid_address(_tidptr: u64) -> i64 {
    1 // TID = 1
}
