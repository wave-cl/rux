/// ELF loading: builds user page tables and enters user mode.
///
/// ELF parsing is handled by the `rux_elf` crate. This module handles
/// the kernel-specific parts: page table construction, memory mapping,
/// and the transition to user mode.

pub use rux_elf::{parse_elf, ElfInfo, LoadSegment, PF_R, PF_W, PF_X, load_segments};

/// Architecture-specific buffer-based ELF loaders are in:
/// - `x86_64::loader::load_and_exec_elf`
/// - `aarch64::loader::load_and_exec_elf`

/// Load an ELF binary from a VFS inode into a fresh user page table.
///
/// This is the core of exec(): parse the ELF, allocate pages for each
/// PT_LOAD segment, copy data, build a user page table with the kernel
/// identity-mapped, map a user stack, activate, and jump to user mode.
/// Load an ELF binary from a VFS inode into a fresh user page table.
/// Handles arbitrarily large binaries by reading segment data page-by-page
/// directly from the filesystem instead of buffering the entire file.
///
/// Architecture-independent segment loading, stack setup, and brk.
/// Only the kernel memory map, page table activation, and enter_user_mode
/// differ between x86_64 and aarch64 (handled via #[cfg] blocks).
pub unsafe fn load_elf_from_inode(
    ino: u64,
    alloc: &mut dyn rux_mm::FrameAllocator,
) -> ! {
    use rux_klib::{PhysAddr, VirtAddr};
    use rux_mm::{MappingFlags, PageSize};
    use rux_vfs::FileSystem;

    let mut talloc = crate::pgtrack::TrackingAllocator::new(alloc);
    let alloc: &mut dyn rux_mm::FrameAllocator = &mut talloc;

    let fs = crate::kstate::fs();

    // Read ELF header (first 4KB is enough for header + program headers)
    let mut hdr_buf = [0u8; 4096];
    let _n = fs.read(ino, 0, &mut hdr_buf).unwrap_or(0);
    let elf_info = parse_elf(&hdr_buf).expect("ELF parse failed");

    // ── Step 1: Build user page table with kernel identity map ──────

    #[cfg(target_arch = "x86_64")]
    let mut upt = {
        let mut upt = crate::x86_64::paging::PageTable4Level::new(alloc).expect("user pt");
        let kflags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::EXECUTE);
        upt.identity_map_range(PhysAddr::new(0), 128 * 1024 * 1024, kflags, alloc)
            .expect("kernel map");
        upt
    };

    #[cfg(target_arch = "aarch64")]
    let mut upt = {
        let mut upt = crate::aarch64::paging::PageTable4Level::new(alloc).expect("user pt");
        let kflags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::EXECUTE);
        upt.identity_map_range(PhysAddr::new(0x40000000), 128 * 1024 * 1024, kflags, alloc)
            .expect("kernel map");
        let dev_flags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::NO_CACHE);
        upt.identity_map_range(PhysAddr::new(0x08000000), 0x20000, dev_flags, alloc)
            .expect("gic map");
        upt.identity_map_range(PhysAddr::new(0x09000000), 0x1000, dev_flags, alloc)
            .expect("uart map");
        upt
    };

    // ── Step 2: Load each segment page-by-page from VFS ─────────────

    let mut tmp_buf = [0u8; 4096];
    for i in 0..elf_info.num_segments {
        let seg = &elf_info.segments[i];
        let vaddr_base = seg.vaddr & !0xFFF;
        let vaddr_end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
        let num_pages = ((vaddr_end - vaddr_base) / 4096) as usize;

        let mut flags = MappingFlags::USER;
        if seg.flags & PF_R != 0 { flags = flags.or(MappingFlags::READ); }
        if seg.flags & PF_W != 0 { flags = flags.or(MappingFlags::WRITE); }
        if seg.flags & PF_X != 0 { flags = flags.or(MappingFlags::EXECUTE); }

        for p in 0..num_pages {
            let va = vaddr_base + (p as u64) * 4096;
            let phys = alloc.alloc(PageSize::FourK).expect("seg page");
            let page_ptr = phys.as_usize() as *mut u8;

            for j in 0..4096 { core::ptr::write_volatile(page_ptr.add(j), 0); }

            let page_va_start = va;
            let page_va_end = va + 4096;
            let seg_file_start = seg.vaddr;
            let seg_file_end = seg.vaddr + seg.filesz;
            let copy_start = page_va_start.max(seg_file_start);
            let copy_end = page_va_end.min(seg_file_end);

            if copy_start < copy_end {
                let file_off = seg.file_offset + (copy_start - seg.vaddr);
                let dest_off = (copy_start - page_va_start) as usize;
                let len = (copy_end - copy_start) as usize;

                let mut read_pos = 0;
                while read_pos < len {
                    let chunk = (len - read_pos).min(4096);
                    let n = fs.read(ino, file_off + read_pos as u64, &mut tmp_buf[..chunk]).unwrap_or(0);
                    if n == 0 { break; }
                    for j in 0..n {
                        *page_ptr.add(dest_off + read_pos + j) = tmp_buf[j];
                    }
                    read_pos += n;
                }
            }

            let va_addr = VirtAddr::new(va as usize);
            let _ = upt.unmap_4k(va_addr);
            upt.map_4k(va_addr, phys, flags, alloc).expect("map seg");
        }
    }

    // ── Step 3: Map user stack (4 pages = 16KB) ─────────────────────

    let stack_flags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::USER);
    let stack_pages = 32u64; // 128 KB user stack
    let stack_base = 0x80000000u64 - stack_pages * 4096;
    for p in 0..stack_pages {
        let sp = alloc.alloc(PageSize::FourK).expect("stack page");
        upt.map_4k(
            VirtAddr::new((stack_base + p * 4096) as usize), sp, stack_flags, alloc,
        ).expect("map stack");
    }
    let stack_top = stack_base + stack_pages * 4096;

    // Set program break to end of last segment (for brk syscall)
    {
        let mut max_end: u64 = 0;
        for i in 0..elf_info.num_segments {
            let seg = &elf_info.segments[i];
            let end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
            if end > max_end { max_end = end; }
        }
        crate::syscall_impl::PROGRAM_BRK = max_end;
        crate::syscall_impl::MMAP_BASE = 0x10000000;
        crate::fdtable::reset();
    }

    // Unmap page 0 to catch NULL pointer dereferences
    let _ = upt.unmap_4k(VirtAddr::new(0));

    // ── Step 4: Activate page table, write stack, enter user mode ────

    #[cfg(target_arch = "x86_64")]
    crate::x86_64::paging::activate(&upt);

    #[cfg(target_arch = "aarch64")]
    core::arch::asm!(
        "msr ttbr0_el1, {}",
        "isb",
        "tlbi vmalle1is",
        "dsb ish",
        "isb",
        in(reg) upt.root_phys().as_usize(),
        options(nostack)
    );

    let user_sp = crate::execargs::write_to_stack(stack_top);
    crate::syscall_impl::arch::serial_write_str("rux: entry=0x");
    crate::write_hex_serial(elf_info.entry as usize);
    crate::syscall_impl::arch::serial_write_str(" sp=0x");
    crate::write_hex_serial(user_sp as usize);
    let sp_ptr = user_sp as *const u64;
    crate::syscall_impl::arch::serial_write_str(" argc=");
    crate::write_hex_serial(*sp_ptr as usize);
    crate::syscall_impl::arch::serial_write_str(" argv0=0x");
    crate::write_hex_serial(*sp_ptr.add(1) as usize);
    crate::syscall_impl::arch::serial_write_str("\n");

    #[cfg(target_arch = "x86_64")]
    crate::x86_64::syscall::enter_user_mode(elf_info.entry, user_sp);

    #[cfg(target_arch = "aarch64")]
    crate::aarch64::syscall::enter_user_mode(elf_info.entry, user_sp);
}

// Buffer-based ELF loaders moved to:
//   x86_64/loader.rs  — crate::x86_64::loader::load_and_exec_elf
//   aarch64/loader.rs — crate::aarch64::loader::load_and_exec_elf
