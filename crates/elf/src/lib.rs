//! Minimal ELF64 parser.
//!
//! Parses an in-memory ELF binary and extracts PT_LOAD segments
//! and the entry point address. No heap, no alloc — operates on
//! a `&[u8]` byte slice.

#![cfg_attr(not(test), no_std)]

use rux_klib::{PhysAddr, VirtAddr};
use rux_mm::{FrameAllocator, MappingFlags, PageSize};

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 64-bit.
const ELFCLASS64: u8 = 2;

/// ELF data: little-endian.
const ELFDATA2LSB: u8 = 1;

/// Program header types.
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;

/// Segment permission flags.
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

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
    /// Dynamic linking: true if PT_INTERP found.
    pub is_dynamic: bool,
    /// File offset of the PT_INTERP string (interpreter path).
    pub interp_offset: u64,
    /// Length of the interpreter path.
    pub interp_len: usize,
    /// Virtual address where program headers are mapped (from PT_PHDR).
    pub phdr_vaddr: u64,
    /// File offset of the program header table.
    pub e_phoff: u64,
    /// Size of one program header entry.
    pub e_phentsize: u16,
    /// Number of program headers.
    pub e_phnum: u16,
    /// ELF type (ET_EXEC=2, ET_DYN=3).
    pub e_type: u16,
}

/// Parse an ELF64 binary from a byte slice.
/// Returns the entry point and loadable segments, or None if invalid.
pub fn parse_elf(data: &[u8]) -> Option<ElfInfo> {
    if data.len() < 64 {
        return None;
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

    let e_type = u16::from_le_bytes([data[16], data[17]]);

    let mut info = ElfInfo {
        entry: e_entry,
        segments: [LoadSegment {
            vaddr: 0, memsz: 0, file_offset: 0, filesz: 0, flags: 0,
        }; 8],
        num_segments: 0,
        is_dynamic: false,
        interp_offset: 0,
        interp_len: 0,
        phdr_vaddr: 0,
        e_phoff,
        e_phentsize,
        e_phnum,
        e_type,
    };

    let ph_off = e_phoff as usize;
    let ph_size = e_phentsize as usize;
    let ph_num = e_phnum as usize;

    for i in 0..ph_num {
        let off = ph_off + i * ph_size;
        if off + 56 > data.len() {
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

        match p_type {
            PT_LOAD if p_memsz > 0 => {
                if info.num_segments >= 8 { break; }
                info.segments[info.num_segments] = LoadSegment {
                    vaddr: p_vaddr,
                    memsz: p_memsz,
                    file_offset: p_offset,
                    filesz: p_filesz,
                    flags: p_flags,
                };
                info.num_segments += 1;
            }
            PT_INTERP => {
                info.is_dynamic = true;
                info.interp_offset = p_offset;
                info.interp_len = p_filesz as usize;
            }
            PT_PHDR => {
                info.phdr_vaddr = p_vaddr;
            }
            _ => {}
        }
    }

    Some(info)
}

/// Load an ELF's segments into memory at their specified virtual addresses.
/// Assumes identity mapping — writes directly to physical addresses.
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
        core::ptr::copy_nonoverlapping(src, dest, copy_len);

        // Zero BSS (memsz > filesz)
        let bss_len = seg.memsz as usize - copy_len;
        if bss_len > 0 {
            core::ptr::write_bytes(dest.add(copy_len), 0, bss_len);
        }
    }
}

// ── VFS-based ELF loader ───────────────────────────────────────────────

/// Trait for reading ELF data from a source (VFS inode, buffer, etc.).
pub trait ElfReader {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize;
}

/// Trait for page table operations needed by the ELF loader.
///
/// # Safety
/// Implementations manipulate hardware page tables.
pub unsafe trait ElfPageTable {
    fn map_4k(
        &mut self,
        va: VirtAddr,
        phys: PhysAddr,
        flags: MappingFlags,
        alloc: &mut dyn FrameAllocator,
    );
    fn unmap_4k(&mut self, va: VirtAddr);
}

/// Load ELF segments page-by-page from a reader into a page table.
///
/// Reads segment data from `reader` (typically VFS), allocates physical pages,
/// copies data, and maps them into `pt`. Also maps a user stack.
///
/// Returns `(stack_top, max_segment_end)` where max_segment_end is the
/// page-aligned end of the highest segment (for setting program break).
///
/// # Safety
/// Allocates and maps physical pages. Caller must ensure the page table
/// and allocator are valid.
pub unsafe fn load_elf_to_pt(
    info: &ElfInfo,
    reader: &mut dyn ElfReader,
    pt: &mut dyn ElfPageTable,
    alloc: &mut dyn FrameAllocator,
    stack_pages: u64,
) -> (u64, u64) {
    let mut tmp_buf = [0u8; 4096];
    let mut max_end: u64 = 0;

    // Load each PT_LOAD segment page-by-page
    for i in 0..info.num_segments {
        let seg = &info.segments[i];
        let vaddr_base = seg.vaddr & !0xFFF;
        let vaddr_end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
        let num_pages = ((vaddr_end - vaddr_base) / 4096) as usize;

        if vaddr_end > max_end { max_end = vaddr_end; }

        let mut flags = MappingFlags::USER;
        if seg.flags & PF_R != 0 { flags = flags.or(MappingFlags::READ); }
        if seg.flags & PF_W != 0 { flags = flags.or(MappingFlags::WRITE); }
        if seg.flags & PF_X != 0 { flags = flags.or(MappingFlags::EXECUTE); }

        for p in 0..num_pages {
            let va = vaddr_base + (p as u64) * 4096;
            let phys = alloc.alloc(PageSize::FourK).expect("seg page");
            let page_ptr = phys.as_usize() as *mut u8;

            // Zero the page (compiler emits memset)
            core::ptr::write_bytes(page_ptr, 0, 4096);

            // Copy file data that falls within this page
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
                    let n = reader.read_at(file_off + read_pos as u64, &mut tmp_buf[..chunk]);
                    if n == 0 { break; }
                    core::ptr::copy_nonoverlapping(
                        tmp_buf.as_ptr(), page_ptr.add(dest_off + read_pos), n,
                    );
                    read_pos += n;
                }
            }

            let va_addr = VirtAddr::new(va as usize);
            pt.unmap_4k(va_addr);
            pt.map_4k(va_addr, phys, flags, alloc);
        }
    }

    // Map user stack
    let stack_flags = MappingFlags::READ.or(MappingFlags::WRITE).or(MappingFlags::USER);
    let stack_base = 0x80000000u64 - stack_pages * 4096;
    for p in 0..stack_pages {
        let sp = alloc.alloc(PageSize::FourK).expect("stack page");
        pt.map_4k(
            VirtAddr::new((stack_base + p * 4096) as usize),
            sp, stack_flags, alloc,
        );
    }
    let stack_top = stack_base + stack_pages * 4096;

    // Guard page below user stack — catches stack overflow with a page fault
    pt.unmap_4k(VirtAddr::new((stack_base - 4096) as usize));

    // Unmap page 0 to catch NULL dereferences
    pt.unmap_4k(VirtAddr::new(0));

    (stack_top, max_end)
}

/// Load ELF segments at a base address offset (for ET_DYN / dynamic linker).
///
/// Same as `load_elf_to_pt` but adds `base` to all virtual addresses.
/// Does NOT map a stack (caller manages that). Returns max_segment_end.
///
/// # Safety
/// Same as `load_elf_to_pt`.
pub unsafe fn load_elf_to_pt_at_base(
    info: &ElfInfo,
    reader: &mut dyn ElfReader,
    pt: &mut dyn ElfPageTable,
    alloc: &mut dyn FrameAllocator,
    base: u64,
) -> u64 {
    let mut tmp_buf = [0u8; 4096];
    let mut max_end: u64 = 0;

    for i in 0..info.num_segments {
        let seg = &info.segments[i];
        let vaddr_base = (base + seg.vaddr) & !0xFFF;
        let vaddr_end = ((base + seg.vaddr + seg.memsz) + 0xFFF) & !0xFFF;
        let num_pages = ((vaddr_end - vaddr_base) / 4096) as usize;

        if vaddr_end > max_end { max_end = vaddr_end; }

        let mut flags = MappingFlags::USER;
        if seg.flags & PF_R != 0 { flags = flags.or(MappingFlags::READ); }
        if seg.flags & PF_W != 0 { flags = flags.or(MappingFlags::WRITE); }
        if seg.flags & PF_X != 0 { flags = flags.or(MappingFlags::EXECUTE); }

        for p in 0..num_pages {
            let va = vaddr_base + (p as u64) * 4096;
            let phys = alloc.alloc(PageSize::FourK).expect("interp page");
            let page_ptr = phys.as_usize() as *mut u8;
            core::ptr::write_bytes(page_ptr, 0, 4096);

            let page_va_start = va;
            let page_va_end = va + 4096;
            let seg_file_start = base + seg.vaddr;
            let seg_file_end = base + seg.vaddr + seg.filesz;
            let copy_start = page_va_start.max(seg_file_start);
            let copy_end = page_va_end.min(seg_file_end);

            if copy_start < copy_end {
                let file_off = seg.file_offset + (copy_start - (base + seg.vaddr));
                let dest_off = (copy_start - page_va_start) as usize;
                let len = (copy_end - copy_start) as usize;

                let mut read_pos = 0;
                while read_pos < len {
                    let chunk = (len - read_pos).min(4096);
                    let n = reader.read_at(file_off + read_pos as u64, &mut tmp_buf[..chunk]);
                    if n == 0 { break; }
                    core::ptr::copy_nonoverlapping(
                        tmp_buf.as_ptr(), page_ptr.add(dest_off + read_pos), n,
                    );
                    read_pos += n;
                }
            }

            let va_addr = VirtAddr::new(va as usize);
            pt.unmap_4k(va_addr);
            pt.map_4k(va_addr, phys, flags, alloc);
        }
    }

    max_end
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a minimal valid ELF64 header (64 bytes)
    fn minimal_elf64_header(entry: u64, e_type: u16, phoff: u64, phnum: u16, phentsize: u16) -> [u8; 64] {
        let mut h = [0u8; 64];
        h[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']); // magic
        h[4] = 2; // ELFCLASS64
        h[5] = 1; // ELFDATA2LSB
        h[6] = 1; // EV_CURRENT
        h[16..18].copy_from_slice(&e_type.to_le_bytes()); // e_type
        h[24..32].copy_from_slice(&entry.to_le_bytes()); // e_entry
        h[32..40].copy_from_slice(&phoff.to_le_bytes()); // e_phoff
        h[54..56].copy_from_slice(&phentsize.to_le_bytes()); // e_phentsize
        h[56..58].copy_from_slice(&phnum.to_le_bytes()); // e_phnum
        h
    }

    #[test]
    fn test_parse_too_small() {
        assert!(parse_elf(&[0u8; 10]).is_none());
        assert!(parse_elf(&[0u8; 63]).is_none());
    }

    #[test]
    fn test_parse_bad_magic() {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(b"\x7fXLF");
        assert!(parse_elf(&data).is_none());
    }

    #[test]
    fn test_parse_32bit_rejected() {
        let mut data = minimal_elf64_header(0x400000, 2, 0, 0, 0);
        data[4] = 1; // ELFCLASS32
        assert!(parse_elf(&data).is_none());
    }

    #[test]
    fn test_parse_valid_static_elf() {
        let data = minimal_elf64_header(0x401000, 2, 0, 0, 56);
        let info = parse_elf(&data).unwrap();
        assert_eq!(info.entry, 0x401000);
        assert_eq!(info.e_type, 2); // ET_EXEC
        assert!(!info.is_dynamic);
        assert_eq!(info.num_segments, 0);
    }

    #[test]
    fn test_parse_with_load_segment() {
        // Header + one PT_LOAD program header
        let mut data = vec![0u8; 64 + 56];
        let hdr = minimal_elf64_header(0x400000, 2, 64, 1, 56);
        data[..64].copy_from_slice(&hdr);
        // PT_LOAD at offset 64
        data[64..68].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        data[68..72].copy_from_slice(&5u32.to_le_bytes()); // p_flags = PF_R|PF_X
        data[72..80].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        data[80..88].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
        data[96..104].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
        data[104..112].copy_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
        let info = parse_elf(&data).unwrap();
        assert_eq!(info.num_segments, 1);
        assert_eq!(info.segments[0].vaddr, 0x400000);
        assert_eq!(info.segments[0].memsz, 0x1000);
        assert_eq!(info.segments[0].flags, 5);
    }

    #[test]
    fn test_parse_interp_detected() {
        // Header + PT_INTERP program header
        let mut data = vec![0u8; 64 + 56 + 32]; // header + phdr + interp string
        let hdr = minimal_elf64_header(0x400000, 2, 64, 1, 56);
        data[..64].copy_from_slice(&hdr);
        // PT_INTERP at offset 64
        data[64..68].copy_from_slice(&3u32.to_le_bytes()); // p_type = PT_INTERP
        data[72..80].copy_from_slice(&120u64.to_le_bytes()); // p_offset (interp string)
        data[96..104].copy_from_slice(&20u64.to_le_bytes()); // p_filesz (interp len)
        data[120..140].copy_from_slice(b"/lib/ld-linux.so.2\0\0");
        let info = parse_elf(&data).unwrap();
        assert!(info.is_dynamic);
        assert_eq!(info.interp_offset, 120);
        assert_eq!(info.interp_len, 20);
    }
}
