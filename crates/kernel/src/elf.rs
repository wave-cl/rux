/// Minimal ELF64 loader. Parses an in-memory ELF binary, extracts
/// PT_LOAD segments and the entry point address.
///
/// No heap, no alloc — operates on a &[u8] byte slice (the embedded binary).

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 64-bit.
const ELFCLASS64: u8 = 2;

/// ELF data: little-endian.
const ELFDATA2LSB: u8 = 1;

/// Program header type: loadable segment.
const PT_LOAD: u32 = 1;

/// Segment permission flags.
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// ELF64 file header (first 64 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,       // program header table offset
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,   // size of one program header entry
    e_phnum: u16,       // number of program header entries
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 program header (one per segment).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,      // offset in file
    p_vaddr: u64,       // virtual address to load at
    p_paddr: u64,
    p_filesz: u64,      // bytes in file
    p_memsz: u64,       // bytes in memory (may be > filesz for BSS)
    p_align: u64,
}

/// A loadable segment extracted from the ELF.
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment {
    /// Virtual address where this segment should be mapped.
    pub vaddr: u64,
    /// Size in memory (includes BSS zero-fill).
    pub memsz: u64,
    /// Offset into the ELF binary where file data starts.
    pub file_offset: u64,
    /// Size of file data (rest is zero-filled BSS).
    pub filesz: u64,
    /// Permission flags (PF_R, PF_W, PF_X).
    pub flags: u32,
}

/// Result of parsing an ELF binary.
pub struct ElfInfo {
    /// Entry point virtual address.
    pub entry: u64,
    /// Loadable segments.
    pub segments: [LoadSegment; 8],
    /// Number of valid segments.
    pub num_segments: usize,
}

/// Parse an ELF64 binary from a byte slice.
/// Returns the entry point and loadable segments, or None if invalid.
pub fn parse_elf(data: &[u8]) -> Option<ElfInfo> {
    if data.len() < 64 {
        return None; // too small for ELF header
    }

    // Validate magic
    if data[0] != ELF_MAGIC[0] || data[1] != ELF_MAGIC[1]
        || data[2] != ELF_MAGIC[2] || data[3] != ELF_MAGIC[3]
    {
        return None;
    }

    // Must be 64-bit, little-endian
    if data[4] != ELFCLASS64 || data[5] != ELFDATA2LSB {
        return None;
    }

    // Read header fields manually to avoid alignment issues with include_bytes!
    let e_entry = u64::from_le_bytes([
        data[24], data[25], data[26], data[27],
        data[28], data[29], data[30], data[31],
    ]);
    let e_phoff = u64::from_le_bytes([
        data[32], data[33], data[34], data[35],
        data[36], data[37], data[38], data[39],
    ]);
    let e_phentsize = u16::from_le_bytes([data[54], data[55]]);
    let e_phnum = u16::from_le_bytes([data[56], data[57]]);

    let mut info = ElfInfo {
        entry: e_entry,
        segments: [LoadSegment {
            vaddr: 0, memsz: 0, file_offset: 0, filesz: 0, flags: 0,
        }; 8],
        num_segments: 0,
    };

    // Walk program headers (read fields manually for alignment safety)
    let ph_off = e_phoff as usize;
    let ph_size = e_phentsize as usize;
    let ph_num = e_phnum as usize;

    for i in 0..ph_num {
        let off = ph_off + i * ph_size;
        if off + 56 > data.len() { // Elf64Phdr is 56 bytes
            break;
        }

        let p_type = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let p_flags = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
        let p_offset = u64::from_le_bytes([
            data[off+8], data[off+9], data[off+10], data[off+11],
            data[off+12], data[off+13], data[off+14], data[off+15],
        ]);
        let p_vaddr = u64::from_le_bytes([
            data[off+16], data[off+17], data[off+18], data[off+19],
            data[off+20], data[off+21], data[off+22], data[off+23],
        ]);
        let p_filesz = u64::from_le_bytes([
            data[off+32], data[off+33], data[off+34], data[off+35],
            data[off+36], data[off+37], data[off+38], data[off+39],
        ]);
        let p_memsz = u64::from_le_bytes([
            data[off+40], data[off+41], data[off+42], data[off+43],
            data[off+44], data[off+45], data[off+46], data[off+47],
        ]);

        if p_type == PT_LOAD && p_memsz > 0 {
            if info.num_segments >= 8 {
                break;
            }
            info.segments[info.num_segments] = LoadSegment {
                vaddr: p_vaddr,
                memsz: p_memsz,
                file_offset: p_offset,
                filesz: p_filesz,
                flags: p_flags,
            };
            info.num_segments += 1;
        }
    }

    Some(info)
}

/// Load an ELF's segments into memory at their specified virtual addresses.
/// Assumes identity mapping — writes directly to physical addresses.
///
/// For each PT_LOAD segment:
/// 1. Copy `filesz` bytes from the ELF data to `vaddr`
/// 2. Zero the remaining `memsz - filesz` bytes (BSS)
///
/// # Safety
/// The caller must ensure the target addresses are valid and mapped.
pub unsafe fn load_segments(data: &[u8], info: &ElfInfo) {
    for i in 0..info.num_segments {
        let seg = &info.segments[i];
        let dest = seg.vaddr as *mut u8;

        // Copy file data
        let src = data.as_ptr().add(seg.file_offset as usize);
        let copy_len = seg.filesz as usize;
        for j in 0..copy_len {
            core::ptr::write_volatile(dest.add(j), *src.add(j));
        }

        // Zero BSS (memsz > filesz)
        let bss_start = copy_len;
        let bss_end = seg.memsz as usize;
        for j in bss_start..bss_end {
            core::ptr::write_volatile(dest.add(j), 0);
        }
    }
}

/// Load an ELF binary into a fresh user page table and enter user mode.
///
/// This is the core of exec(): parse the ELF, allocate pages for each
/// PT_LOAD segment, copy data, build a user page table with the kernel
/// identity-mapped, map a user stack, activate, and jump to user mode.
///
/// # Safety
/// - `elf_data` must be a valid ELF64 binary.
/// - `alloc` must be a valid frame allocator with identity-mapped pages.
/// - Does not return.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_and_exec_elf(
    elf_data: &[u8],
    alloc: &mut dyn rux_mm::FrameAllocator,
) -> ! {
    use rux_klib::{PhysAddr, VirtAddr};
    use rux_mm::{MappingFlags, PageSize};

    let mut talloc = crate::pgtrack::TrackingAllocator::new(alloc);
    let alloc: &mut dyn rux_mm::FrameAllocator = &mut talloc;

    let elf_info = parse_elf(elf_data).expect("ELF parse failed");

    // Step 1: Allocate physical pages for each segment and copy data.
    let mut seg_mappings: [(u64, PhysAddr, u32); 16] =
        [(0, PhysAddr::new(0), 0); 16];
    let mut map_count = 0;

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
            // Zero the page via boot identity map
            let ptr = phys.as_usize() as *mut u8;
            for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
            // Copy file data that falls within this page
            let page_va_start = va;
            let page_va_end = va + 4096;
            if seg.file_offset + seg.filesz > 0 {
                let seg_file_start = seg.vaddr;
                let seg_file_end = seg.vaddr + seg.filesz;
                let copy_start = page_va_start.max(seg_file_start);
                let copy_end = page_va_end.min(seg_file_end);
                if copy_start < copy_end {
                    let file_off = seg.file_offset + (copy_start - seg.vaddr);
                    let dest_off = copy_start - page_va_start;
                    let len = (copy_end - copy_start) as usize;
                    let src = elf_data.as_ptr().add(file_off as usize);
                    let dst = ptr.add(dest_off as usize);
                    for j in 0..len { *dst.add(j) = *src.add(j); }
                }
            }
            if map_count < 16 {
                seg_mappings[map_count] = (va, phys, flags.0);
                map_count += 1;
            }
        }
    }

    // Step 2: Build user page table
    let mut upt = crate::x86_64::paging::PageTable4Level::new(alloc).expect("user pt");

    // Kernel identity map (0-8 MiB, RWX, no USER)
    let kflags = MappingFlags::READ
        .or(MappingFlags::WRITE)
        .or(MappingFlags::EXECUTE);
    upt.identity_map_range(PhysAddr::new(0), 16 * 1024 * 1024, kflags, alloc)
        .expect("kernel map");

    // Map ELF segment pages (user virtual -> physical)
    for i in 0..map_count {
        let (va, phys, flags_raw) = seg_mappings[i];
        let flags = MappingFlags(flags_raw);
        upt.map_4k(VirtAddr::new(va as usize), phys, flags, alloc)
            .expect("map user seg");
    }

    // Map user stack (4 pages = 16KB)
    let stack_flags = MappingFlags::READ
        .or(MappingFlags::WRITE)
        .or(MappingFlags::USER);
    let stack_pages_x86 = 32u64;
    let stack_base = 0x80000000u64 - stack_pages_x86 * 4096;
    for p in 0..stack_pages_x86 {
        let sp = alloc.alloc(PageSize::FourK).expect("stack page");
        upt.map_4k(
            VirtAddr::new((stack_base + p * 4096) as usize), sp, stack_flags, alloc,
        ).expect("map stack");
    }
    let stack_top = stack_base + stack_pages_x86 * 4096;

    // Step 3: Activate and enter user mode
    crate::x86_64::paging::activate(&upt);
    let user_sp = crate::execargs::write_to_stack(stack_top);
    crate::x86_64::syscall::enter_user_mode(elf_info.entry, user_sp);
}

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

/// aarch64 buffer-based ELF loader (for small binaries loaded during init).
#[cfg(target_arch = "aarch64")]
pub unsafe fn load_and_exec_elf(
    elf_data: &[u8],
    alloc: &mut dyn rux_mm::FrameAllocator,
) -> ! {
    use rux_klib::{PhysAddr, VirtAddr};
    use rux_mm::{MappingFlags, PageSize};

    let mut talloc = crate::pgtrack::TrackingAllocator::new(alloc);
    let alloc: &mut dyn rux_mm::FrameAllocator = &mut talloc;

    let elf_info = parse_elf(elf_data).expect("ELF parse failed");

    let mut seg_mappings: [(u64, PhysAddr, u32); 16] =
        [(0, PhysAddr::new(0), 0); 16];
    let mut map_count = 0;

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
            let ptr = phys.as_usize() as *mut u8;
            for j in 0..4096 { core::ptr::write_volatile(ptr.add(j), 0); }
            if seg.file_offset + seg.filesz > 0 {
                let seg_file_start = seg.vaddr;
                let seg_file_end = seg.vaddr + seg.filesz;
                let page_va_start = va;
                let page_va_end = va + 4096;
                let copy_start = page_va_start.max(seg_file_start);
                let copy_end = page_va_end.min(seg_file_end);
                if copy_start < copy_end {
                    let file_off = seg.file_offset + (copy_start - seg.vaddr);
                    let dest_off = copy_start - page_va_start;
                    let len = (copy_end - copy_start) as usize;
                    let src = elf_data.as_ptr().add(file_off as usize);
                    let dst = ptr.add(dest_off as usize);
                    for j in 0..len { *dst.add(j) = *src.add(j); }
                }
            }
            if map_count < 16 {
                seg_mappings[map_count] = (va, phys, flags.0);
                map_count += 1;
            }
        }
    }

    let mut upt = crate::aarch64::paging::PageTable4Level::new(alloc).expect("user pt");
    let kflags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::EXECUTE);
    upt.identity_map_range(PhysAddr::new(0x40000000), 128 * 1024 * 1024, kflags, alloc)
        .expect("kernel map");
    let dev_flags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::NO_CACHE);
    upt.identity_map_range(PhysAddr::new(0x08000000), 0x20000, dev_flags, alloc)
        .expect("gic map");
    upt.identity_map_range(PhysAddr::new(0x09000000), 0x1000, dev_flags, alloc)
        .expect("uart map");

    for i in 0..map_count {
        let (va, phys, flags_raw) = seg_mappings[i];
        let flags = MappingFlags(flags_raw);
        upt.map_4k(VirtAddr::new(va as usize), phys, flags, alloc)
            .expect("map user seg");
    }

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
    crate::aarch64::syscall::enter_user_mode(elf_info.entry, user_sp);
}
