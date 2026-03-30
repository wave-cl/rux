/// Linux-specific syscall extensions.
///
/// These syscalls are Linux kernel extensions not defined by POSIX.
/// All arguments use native-width types (usize/isize).

// ── Pipes (Linux extension) ──────────────────────────────────────────

/// pipe2(pipefd, flags) — create a pipe.
pub fn pipe2(pipefd_ptr: usize, _flags: usize) -> isize {
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
pub fn brk(addr: usize) -> isize {
    unsafe {
        if super::PROGRAM_BRK == 0 { super::PROGRAM_BRK = 0x800000; }
        if addr == 0 { return super::PROGRAM_BRK as isize; }
        if addr >= super::PROGRAM_BRK {
            let old_page = (super::PROGRAM_BRK + 0xFFF) & !0xFFF;
            let new_page = (addr + 0xFFF) & !0xFFF;
            let flags = rux_mm::MappingFlags::READ
                .or(rux_mm::MappingFlags::WRITE)
                .or(rux_mm::MappingFlags::USER);
            super::map_user_pages(old_page, new_page, flags);
            super::PROGRAM_BRK = addr;
        }
        super::PROGRAM_BRK as isize
    }
}

// ── Directory listing (Linux-specific format) ───────────────────────

/// getdents64(fd, dirp, count) — Linux-specific.
pub fn getdents64(fd: usize, buf_ptr: usize, bufsize: usize) -> isize {
    unsafe {
        use rux_vfs::{FileSystem, DirEntry, InodeType};
        let fs = crate::kstate::fs();
        let out = buf_ptr as *mut u8;
        let limit = bufsize;
        let mut pos = 0usize;

        let dir_ino = if fd >= 3 {
            match rux_vfs::fdtable::get_fd_inode(fd) {
                Some(ino) => ino,
                None => return -9,
            }
        } else {
            0 // root
        };

        let mut offset = if fd < 64 {
            rux_vfs::fdtable::FD_TABLE[fd].offset
        } else {
            0
        };
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
                        InodeType::File => 8,
                        InodeType::Directory => 4,
                        InodeType::Symlink => 10,
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
        if fd < 64 {
            rux_vfs::fdtable::FD_TABLE[fd].offset = offset;
        }
        if pos == start_pos { return 0; }
        pos as isize
    }
}

// ── Process extensions (Linux-specific) ─────────────────────────────

/// exit_group(status) — Linux-specific.
pub fn exit_group(status: i32) -> ! {
    super::posix::exit(status)
}

/// wait4(pid, wstatus, options, rusage) — Linux extension of POSIX waitpid.
pub fn wait4(pid: usize, wstatus_ptr: usize, options: usize, _rusage: usize) -> isize {
    super::posix::waitpid(pid, wstatus_ptr, options)
}

/// set_tid_address(tidptr) — Linux-specific TLS.
pub fn set_tid_address(_tidptr: usize) -> isize {
    1 // TID = 1
}
