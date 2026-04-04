/// Minimal Flattened Device Tree (FDT) parser.
/// Extracts memory regions from the QEMU-provided DTB.
///
/// FDT format: big-endian header, then structure block with tokens:
///   FDT_BEGIN_NODE (0x01), FDT_END_NODE (0x02),
///   FDT_PROP (0x03), FDT_NOP (0x04), FDT_END (0x09)

use rux_klib::PhysAddr;

const FDT_MAGIC: u32 = 0xD00DFEED;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// FDT header (big-endian).
#[repr(C)]
#[allow(dead_code)]
struct FdtHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

/// A parsed memory region.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    pub base: PhysAddr,
    pub size: usize,
}

#[allow(dead_code)]
pub struct MemoryMap {
    pub regions: [MemRegion; 8],
    pub count: usize,
    pub total_usable: usize,
}

#[inline(always)]
fn be32(ptr: *const u8) -> u32 {
    unsafe {
        ((*ptr.add(0) as u32) << 24)
            | ((*ptr.add(1) as u32) << 16)
            | ((*ptr.add(2) as u32) << 8)
            | (*ptr.add(3) as u32)
    }
}

#[inline(always)]
fn be64(ptr: *const u8) -> u64 {
    ((be32(ptr) as u64) << 32) | (be32(unsafe { ptr.add(4) }) as u64)
}

/// Parse a DTB and extract memory regions.
///
/// # Safety
/// `dtb_addr` must point to a valid FDT blob.
#[allow(dead_code)]
pub unsafe fn parse_dtb(dtb_addr: usize) -> MemoryMap {
    let mut map = MemoryMap {
        regions: [MemRegion { base: PhysAddr::new(0), size: 0 }; 8],
        count: 0,
        total_usable: 0,
    };

    let base = dtb_addr as *const u8;

    // Validate magic
    let magic = be32(base);
    if magic != FDT_MAGIC {
        return map;
    }

    let struct_off = be32(base.add(8)) as usize;
    let strings_off = be32(base.add(12)) as usize;
    let strings_base = base.add(strings_off);

    // Walk the structure block looking for /memory node's "reg" property
    let mut pos = struct_off;
    let mut in_memory_node = false;
    let mut depth = 0u32;
    let mut memory_depth = 0u32;

    loop {
        let token = be32(base.add(pos));
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                depth += 1;
                // Read node name (null-terminated string)
                let name_ptr = base.add(pos);
                let name_len = str_len(name_ptr);

                // Check if this is a "memory" node (at depth 1)
                if depth == 1 && starts_with(name_ptr, b"memory") {
                    in_memory_node = true;
                    memory_depth = depth;
                }

                // Advance past name + padding to 4-byte boundary
                pos += (name_len + 4) & !3;
            }
            FDT_END_NODE => {
                if in_memory_node && depth == memory_depth {
                    in_memory_node = false;
                }
                depth -= 1;
            }
            FDT_PROP => {
                let val_len = be32(base.add(pos)) as usize;
                let name_off = be32(base.add(pos + 4)) as usize;
                pos += 8;

                // Check if we're in the memory node and this is "reg"
                if in_memory_node {
                    let prop_name = strings_base.add(name_off);
                    if starts_with(prop_name, b"reg") && val_len >= 16 {
                        // "reg" contains pairs of (base, size) as 64-bit big-endian
                        let mut off = 0;
                        while off + 16 <= val_len && map.count < 8 {
                            let reg_base = be64(base.add(pos + off)) as usize;
                            let reg_size = be64(base.add(pos + off + 8)) as usize;
                            if reg_size > 0 {
                                map.regions[map.count] = MemRegion {
                                    base: PhysAddr::new(reg_base),
                                    size: reg_size,
                                };
                                map.total_usable += reg_size;
                                map.count += 1;
                            }
                            off += 16;
                        }
                    }
                }

                // Advance past value + padding
                pos += (val_len + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => break, // unknown token — stop
        }
    }

    map
}

/// Parse DTB for initrd location from `/chosen` node.
/// QEMU sets `linux,initrd-start` and `linux,initrd-end` when `-initrd` is used.
///
/// # Safety
/// `dtb_addr` must point to a valid FDT blob.
pub unsafe fn get_initrd(dtb_addr: usize) -> Option<(usize, usize)> {
    if dtb_addr == 0 { return None; }
    let base = dtb_addr as *const u8;

    let magic = be32(base);
    if magic != FDT_MAGIC { return None; }

    let struct_off = be32(base.add(8)) as usize;
    let strings_off = be32(base.add(12)) as usize;
    let strings_base = base.add(strings_off);

    let mut pos = struct_off;
    let mut in_chosen = false;
    let mut depth = 0u32;
    let mut chosen_depth = 0u32;
    let mut initrd_start: u64 = 0;
    let mut initrd_end: u64 = 0;

    loop {
        let token = be32(base.add(pos));
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                depth += 1;
                let name_ptr = base.add(pos);
                let name_len = str_len(name_ptr);

                if depth == 1 && starts_with(name_ptr, b"chosen") {
                    in_chosen = true;
                    chosen_depth = depth;
                }

                pos += (name_len + 4) & !3;
            }
            FDT_END_NODE => {
                if in_chosen && depth == chosen_depth {
                    in_chosen = false;
                }
                depth -= 1;
            }
            FDT_PROP => {
                let val_len = be32(base.add(pos)) as usize;
                let name_off = be32(base.add(pos + 4)) as usize;
                pos += 8;

                if in_chosen {
                    let prop_name = strings_base.add(name_off);
                    if starts_with(prop_name, b"linux,initrd-start") && val_len >= 4 {
                        initrd_start = if val_len >= 8 {
                            be64(base.add(pos))
                        } else {
                            be32(base.add(pos)) as u64
                        };
                    } else if starts_with(prop_name, b"linux,initrd-end") && val_len >= 4 {
                        initrd_end = if val_len >= 8 {
                            be64(base.add(pos))
                        } else {
                            be32(base.add(pos)) as u64
                        };
                    }
                }

                pos += (val_len + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => break,
        }
    }

    if initrd_start > 0 && initrd_end > initrd_start {
        Some((initrd_start as usize, (initrd_end - initrd_start) as usize))
    } else {
        None
    }
}

unsafe fn str_len(ptr: *const u8) -> usize {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    len
}

unsafe fn starts_with(ptr: *const u8, prefix: &[u8]) -> bool {
    for (i, &b) in prefix.iter().enumerate() {
        if *ptr.add(i) != b {
            return false;
        }
    }
    true
}
