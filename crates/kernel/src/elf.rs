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
