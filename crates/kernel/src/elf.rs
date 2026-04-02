/// ELF loading: builds user page tables and enters user mode.
///
/// ELF parsing and segment loading are handled by the `rux_elf` crate.
/// This module handles the kernel-specific parts: page table construction,
/// VFS reader adapter, and the transition to user mode.

pub use rux_elf::{parse_elf, ElfInfo, LoadSegment, PF_R, PF_W, PF_X, load_segments};


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
    use rux_klib::VirtAddr;
    use rux_fs::FileSystem;

    let mut talloc = crate::pgtrack::TrackingAllocator::new(alloc);
    let alloc: &mut dyn rux_mm::FrameAllocator = &mut talloc;

    let fs = crate::kstate::fs();

    // Read ELF header (first 4KB is enough for header + program headers)
    let mut hdr_buf = [0u8; 4096];
    let _n = fs.read(ino, 0, &mut hdr_buf).unwrap_or(0);
    let elf_info = parse_elf(&hdr_buf).expect("ELF parse failed");

    // Build user page table with kernel identity map
    let mut upt = {
        use crate::arch::KernelMapOps;
        let mut upt = crate::arch::PageTable::new(alloc).expect("user pt");
        crate::arch::Arch::map_kernel_pages(&mut upt, alloc);
        upt
    };

    // Load segments + map stack via rux-elf generic loader
    let mut reader = VfsReader { ino };
    let mut pt_adapter = PtAdapter { pt: &mut upt };
    let (stack_top, max_end) = rux_elf::load_elf_to_pt(
        &elf_info, &mut reader, &mut pt_adapter, alloc, 32,
    );

    // Set program break and mmap base for brk/mmap syscalls
    crate::syscall::PROCESS.program_brk = max_end as usize;
    crate::syscall::PROCESS.mmap_base = 0x10000000;
    rux_fs::fdtable::reset();

    // Dynamic linking: if PT_INTERP exists, load the interpreter alongside
    let entry_point;
    if elf_info.is_dynamic {
        entry_point = load_dynamic_interp(
            &elf_info, &mut upt, alloc, fs, ino, &hdr_buf,
        );
    } else {
        rux_proc::execargs::clear_dynamic_auxv();
        entry_point = elf_info.entry as usize;
    }

    // Activate page table
    {
        use rux_arch::PageTableRootOps;
        let new_root = upt.root_phys().as_usize() as u64;
        crate::arch::Arch::write(new_root);
        unsafe {
            crate::task_table::TASK_TABLE[crate::task_table::current_task_idx()].pt_root = new_root;
        }
    }

    // Write exec args to user stack (needs stac for SMAP — user pages)
    crate::uaccess::stac();
    let user_sp = rux_proc::execargs::write_to_stack(stack_top as usize);
    crate::uaccess::clac();
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
) -> usize {
    use rux_arch::ConsoleOps;
    use rux_fs::FileSystem;

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

    // 4. Load interpreter at a base address (0x40000000)
    const INTERP_BASE: u64 = 0x40000000;
    let mut interp_reader = VfsReader { ino: interp_ino };
    let mut pt_adapter = PtAdapter { pt: upt };
    let interp_end = rux_elf::load_elf_to_pt_at_base(
        &interp_elf, &mut interp_reader, &mut pt_adapter, alloc, INTERP_BASE,
    );

    // Bump mmap_base past the interpreter's end
    let interp_end_aligned = ((interp_end + 0xFFF) & !0xFFF) as usize;
    if interp_end_aligned > crate::syscall::PROCESS.mmap_base {
        crate::syscall::PROCESS.mmap_base = interp_end_aligned;
    }

    // 5. Set auxv for ld.so
    // phdr_vaddr: if PT_PHDR was mapped by PT_LOAD, use its vaddr.
    // Otherwise, use e_phoff offset from the first segment's base.
    let phdr_addr = if main_elf.phdr_vaddr != 0 {
        main_elf.phdr_vaddr as usize
    } else {
        // Program headers are at e_phoff from start of ELF file.
        // If the first LOAD segment starts at VA 0 (PIE), phdr is at e_phoff.
        main_elf.segments[0].vaddr as usize + main_elf.e_phoff as usize
            - main_elf.segments[0].file_offset as usize
    };

    rux_proc::execargs::set_dynamic_auxv(
        phdr_addr,
        main_elf.e_phentsize as usize,
        main_elf.e_phnum as usize,
        main_elf.entry as usize,
        INTERP_BASE as usize,
    );

    // 6. Return interpreter's entry point (offset by base)
    (INTERP_BASE + interp_elf.entry) as usize
}

