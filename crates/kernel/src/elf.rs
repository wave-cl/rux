/// ELF loading: builds user page tables and enters user mode.
///
/// ELF parsing and segment loading are handled by the `rux_elf` crate.
/// This module handles the kernel-specific parts: page table construction,
/// VFS reader adapter, and the transition to user mode.

pub use rux_elf::parse_elf;


/// VFS-backed ELF reader — adapts a VFS inode to the `ElfReader` trait.
struct VfsReader {
    ino: u64,
}

impl rux_elf::ElfReader for VfsReader {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize {
        unsafe {
            use rux_fs::FileSystem;
            let fs = crate::kstate::fs();
            fs.read(self.ino, offset, buf).unwrap_or(0)
        }
    }
}

/// Page table adapter — wraps the kernel's PageTable4Level for ElfPageTable.
struct PtAdapter<'a> {
    pt: &'a mut crate::arch::PageTable,
}

unsafe impl<'a> rux_elf::ElfPageTable for PtAdapter<'a> {
    fn map_4k(
        &mut self,
        va: rux_klib::VirtAddr,
        phys: rux_klib::PhysAddr,
        flags: rux_mm::MappingFlags,
        alloc: &mut dyn rux_mm::FrameAllocator,
    ) {
        self.pt.map_4k(va, phys, flags, alloc).expect("map seg");
    }
    fn unmap_4k(&mut self, va: rux_klib::VirtAddr) {
        let _ = self.pt.unmap_4k(va);
    }
}

/// Load an ELF binary from a VFS inode into a fresh user page table.
///
/// This is the core of exec(): parse the ELF, build a user page table
/// with the kernel identity-mapped, load segments, map a user stack,
/// activate, and jump to user mode.
pub unsafe fn load_elf_from_inode(
    ino: u64,
    alloc: &mut dyn rux_mm::FrameAllocator,
) -> ! {
    use rux_fs::FileSystem;
    let mut talloc = crate::pgtrack::TrackingAllocator::new(alloc);
    let alloc: &mut dyn rux_mm::FrameAllocator = &mut talloc;

    let fs = crate::kstate::fs();

    // Read file header (first 4KB)
    let mut hdr_buf = [0u8; 4096];
    let n = fs.read(ino, 0, &mut hdr_buf).unwrap_or(0);

    // Shebang support: #! /path/to/interpreter [arg]
    if n >= 2 && hdr_buf[0] == b'#' && hdr_buf[1] == b'!' {
        // Parse interpreter path from the first line
        let line_end = hdr_buf[2..n.min(256)].iter().position(|&b| b == b'\n').unwrap_or(n.min(256) - 2);
        let line = &hdr_buf[2..2 + line_end];
        // Skip leading spaces
        let start = line.iter().position(|&b| b != b' ').unwrap_or(0);
        let interp = &line[start..];
        // Find end of interpreter path (space or end of line)
        let interp_end = interp.iter().position(|&b| b == b' ' || b == b'\t').unwrap_or(interp.len());
        let interp_path = &interp[..interp_end];

        if !interp_path.is_empty() {
            // Resolve the interpreter and exec it
            let interp_ino = match rux_fs::path::resolve_path(fs, interp_path) {
                Ok(ino) => ino,
                Err(_) => {
                    use rux_arch::ConsoleOps;
                    crate::arch::Arch::write_str("rux: shebang interp not found\n");
                    crate::syscall::posix::exit(127);
                }
            };
            // Re-exec with the interpreter (it will load the script as argv[1])
            load_elf_from_inode(interp_ino as u64, alloc);
        }
    }

    let elf_info = match parse_elf(&hdr_buf) {
        Some(info) => info,
        None => {
            use rux_arch::ConsoleOps;
            crate::arch::Arch::write_str("rux: exec: bad ELF\n");
            crate::syscall::posix::exit(1);
        }
    };

    // Build user page table with kernel identity map
    let mut upt = {
        use crate::arch::KernelMapOps;
        let mut upt = match crate::arch::PageTable::new(alloc) {
            Ok(pt) => pt,
            Err(_) => {
                use rux_arch::ConsoleOps;
                crate::arch::Arch::write_str("rux: exec: out of memory\n");
                crate::syscall::posix::exit(1);
            }
        };
        crate::arch::Arch::map_kernel_pages(&mut upt, alloc);
        upt
    };

    // Load segments + map stack via rux-elf generic loader
    let mut reader = VfsReader { ino };
    let mut pt_adapter = PtAdapter { pt: &mut upt };

    // PIE (ET_DYN with first segment at VA 0): load at a base address
    // so it doesn't collide with the null guard page at VA 0.
    let is_pie = elf_info.e_type == 3 && elf_info.segments.iter()
        .any(|s| s.vaddr == 0);
    // PIE base: above identity map, below mmap_base/INTERP_BASE.
    // x86_64: identity maps 0-128MB, kernel BSS reaches ~0x400000. Use 128MB.
    // aarch64: MMIO at 0x08000000, RAM at 0x40000000. Use 4MB (safe gap).
    #[cfg(target_arch = "x86_64")]
    let pie_base: u64 = if is_pie { 0x8000000 } else { 0 };
    #[cfg(target_arch = "aarch64")]
    let pie_base: u64 = if is_pie { 0x400000 } else { 0 };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let pie_base: u64 = if is_pie { 0x400000 } else { 0 };

    let (stack_top, max_end) = if is_pie {
        let end = rux_elf::load_elf_to_pt_at_base(
            &elf_info, &mut reader, &mut pt_adapter, alloc, pie_base,
        );
        // Map user stack separately (load_elf_to_pt_at_base doesn't map stack)
        let stack_pages = 32u64;
        let stack_flags = rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::USER);
        let stack_base = 0x80000000u64 - stack_pages * 4096;
        for p in 0..stack_pages {
            let sp_frame = alloc.alloc(rux_mm::PageSize::FourK).expect("stack page");
            // Zero the frame — Linux guarantees zero-filled pages for user processes
            // (prevents information leaks and satisfies programs that assume zero stack)
            core::ptr::write_bytes(sp_frame.as_usize() as *mut u8, 0, 4096);
            let _ = upt.map_4k(
                rux_klib::VirtAddr::new((stack_base + p * 4096) as usize),
                sp_frame, stack_flags, alloc,
            );
        }
        // Unmap guard page below stack
        let _ = upt.unmap_4k(rux_klib::VirtAddr::new((stack_base - 4096) as usize));
        // Unmap page 0
        let _ = upt.unmap_4k(rux_klib::VirtAddr::new(0));
        (stack_base + stack_pages * 4096, end.max(stack_base + stack_pages * 4096))
    } else {
        rux_elf::load_elf_to_pt(
            &elf_info, &mut reader, &mut pt_adapter, alloc, 32,
        )
    };

    // Set program break and mmap base for brk/mmap syscalls
    crate::syscall::process().program_brk = max_end as usize;
    // Randomize mmap_base for basic ASLR (0x10000000 + random 0-16MB offset)
    {
        use rux_arch::TimerOps;
        let entropy = crate::arch::Arch::ticks() as usize;
        let random_offset = (entropy & 0xFFF) << 12;
        crate::syscall::process().mmap_base = 0x10000000 + random_offset;
    }
    {
        let closed = rux_fs::fdtable::close_on_exec(
            Some(&crate::pipe::PIPE),
            Some(crate::syscall::socket::close_socket_for_exec),
        );
        for &pid in &closed {
            if pid != 0xFF { crate::pipe::wake_pipe_waiters(pid); }
        }
    }

    // Dynamic linking: if PT_INTERP exists, load the interpreter alongside
    let entry_point;
    if elf_info.is_dynamic {
        entry_point = load_dynamic_interp(
            &elf_info, &mut upt, alloc, fs, ino, &hdr_buf, pie_base,
        );
    } else {
        rux_proc::execargs::clear_dynamic_auxv();
        entry_point = (elf_info.entry as u64 + pie_base) as usize;
    }

    // Activate page table + flush TLB (exec replaces the entire address space)
    {
        use rux_arch::PageTableRootOps;
        let new_root = upt.root_phys().as_usize() as u64;
        crate::arch::Arch::write(new_root);
        crate::arch::PageTable::flush_tlb_all();
        unsafe {
            crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].pt_root = new_root;
        }
    }

    // Stack ASLR: random offset within the mapped stack region (0-7 pages)
    let stack_top = {
        use rux_arch::TimerOps;
        let stack_entropy = ((crate::arch::Arch::ticks() >> 8) & 0x7) as u64;
        stack_top - stack_entropy * 4096
    };

    // Write exec args to user stack (needs stac for SMAP — user pages)
    crate::uaccess::stac();
    let user_sp = rux_proc::execargs::write_to_stack(stack_top as usize);
    crate::uaccess::clac();

    // Copy cmdline to current task slot for /proc/[pid]/cmdline
    {
        let (cmdline, cmdline_len) = rux_proc::execargs::get_cmdline();
        let idx = crate::task_table::current_task_idx();
        let slot = &mut crate::task_table::TASK_TABLE[idx];
        let len = (cmdline_len as usize).min(128);
        slot.cmdline[..len].copy_from_slice(&cmdline[..len]);
        slot.cmdline_len = len as u8;
    }
    // Check for pending reschedule before entering userspace.
    // After exec, other pipeline processes may be waiting to run.
    // Without this, the post_syscall check is skipped (exec doesn't return).
    unsafe {
        let sched = crate::scheduler::get();
        if sched.need_resched {
            sched.schedule();
        }
    }
    {
        use rux_arch::UserModeOps;
        crate::arch::Arch::enter_user_mode(entry_point, user_sp);
    }
}

/// Load the dynamic interpreter (ld.so) for a dynamically-linked binary.
///
/// Reads the PT_INTERP path, resolves the interpreter in VFS, parses its ELF,
/// loads its segments at a high base address, sets auxv entries, and returns
/// the interpreter's entry point (which becomes the process's actual entry).
unsafe fn load_dynamic_interp(
    main_elf: &rux_elf::ElfInfo,
    upt: &mut crate::arch::PageTable,
    alloc: &mut dyn rux_mm::FrameAllocator,
    fs: &mut impl rux_fs::FileSystem,
    main_ino: u64,
    main_hdr: &[u8],
    pie_base: u64,
) -> usize {
    use rux_arch::ConsoleOps;

    // 1. Read interpreter path from PT_INTERP
    let interp_off = main_elf.interp_offset as usize;
    let interp_len = main_elf.interp_len;
    let mut interp_path = [0u8; 256];
    let path_len = interp_len.min(255);
    // Read from the ELF file (main_hdr may contain it if offset < 4096)
    if interp_off + path_len <= main_hdr.len() {
        interp_path[..path_len].copy_from_slice(&main_hdr[interp_off..interp_off + path_len]);
    } else {
        // Read from VFS
        let mut buf = [0u8; 256];
        let _ = fs.read(main_ino, interp_off as u64, &mut buf[..path_len]);
        interp_path[..path_len].copy_from_slice(&buf[..path_len]);
    }
    // Strip trailing null
    let mut plen = path_len;
    while plen > 0 && interp_path[plen - 1] == 0 { plen -= 1; }

    crate::arch::Arch::write_str("rux: dynamic: interp=");
    crate::arch::Arch::write_bytes(&interp_path[..plen]);
    crate::arch::Arch::write_str("\n");

    // 2. Resolve interpreter in VFS
    let interp_ino = match rux_fs::path::resolve_path(fs, &interp_path[..plen]) {
        Ok(ino) => ino,
        Err(_) => {
            crate::arch::Arch::write_str("rux: dynamic: interpreter not found\n");
            loop { core::hint::spin_loop(); }
        }
    };

    // 3. Parse interpreter's ELF
    let mut interp_hdr = [0u8; 4096];
    let _ = fs.read(interp_ino, 0, &mut interp_hdr);
    let interp_elf = rux_elf::parse_elf(&interp_hdr).expect("interp ELF parse failed");

    // 4. Load interpreter at a base address outside the kernel identity map.
    // Randomize interpreter base for ASLR (0-255 page offset = 0-1MB)
    let interp_base = {
        use rux_arch::MemoryLayout;
        use rux_arch::TimerOps;
        let interp_entropy = ((crate::arch::Arch::ticks() >> 16) & 0xFF) as u64;
        crate::arch::Arch::INTERP_BASE + interp_entropy * 4096
    };
    let mut interp_reader = VfsReader { ino: interp_ino };
    let mut pt_adapter = PtAdapter { pt: upt };
    let interp_end = rux_elf::load_elf_to_pt_at_base(
        &interp_elf, &mut interp_reader, &mut pt_adapter, alloc, interp_base,
    );

    // Bump mmap_base past the interpreter's end
    let interp_end_aligned = ((interp_end + 0xFFF) & !0xFFF) as usize;
    if interp_end_aligned > crate::syscall::process().mmap_base {
        crate::syscall::process().mmap_base = interp_end_aligned;
    }

    // 5. Set auxv for ld.so
    // phdr_vaddr: if PT_PHDR was mapped by PT_LOAD, use its vaddr.
    // Otherwise, use e_phoff offset from the first segment's base.
    // For PIE binaries, add pie_base to the PHDR and entry addresses.
    let phdr_addr = if main_elf.phdr_vaddr != 0 {
        main_elf.phdr_vaddr as usize + pie_base as usize
    } else {
        main_elf.segments[0].vaddr as usize + pie_base as usize
            + main_elf.e_phoff as usize
            - main_elf.segments[0].file_offset as usize
    };

    rux_proc::execargs::set_dynamic_auxv(
        phdr_addr,
        main_elf.e_phentsize as usize,
        main_elf.e_phnum as usize,
        main_elf.entry as usize + pie_base as usize,
        interp_base as usize,
    );

    // 6. Return interpreter's entry point (offset by base)
    (interp_base + interp_elf.entry) as usize
}

