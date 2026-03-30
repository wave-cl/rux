/// Multiboot1 information structure parsing.
/// The bootloader (GRUB/QEMU) fills this and passes the physical address in EBX.

use rux_klib::PhysAddr;

/// Multiboot info structure (subset — we only need the memory map).
#[repr(C)]
struct MultibootInfo {
    flags: u32,
    mem_lower: u32,     // KB of lower memory (below 1MB)
    mem_upper: u32,     // KB of upper memory (above 1MB)
    _boot_device: u32,
    _cmdline: u32,
    mods_count: u32,
    mods_addr: u32,
    _syms: [u32; 4],
    mmap_length: u32,   // total size of memory map buffer
    mmap_addr: u32,     // physical address of memory map
}

/// Multiboot memory map entry.
#[repr(C, packed)]
struct MmapEntry {
    size: u32,          // size of this entry (not including this field)
    base_addr: u64,     // physical base address
    length: u64,        // size in bytes
    entry_type: u32,    // 1 = available, 2 = reserved, 3 = ACPI, etc.
}

/// A usable memory region parsed from the multiboot memory map.
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    pub base: PhysAddr,
    pub size: usize,
}

/// Maximum regions we'll track.
const MAX_REGIONS: usize = 32;

/// Parsed memory map.
pub struct MemoryMap {
    pub regions: [MemRegion; MAX_REGIONS],
    pub count: usize,
    pub total_usable: usize,
}

/// Parse the multiboot info structure and extract usable memory regions.
///
/// # Safety
/// `info_addr` must be the valid physical address of a MultibootInfo struct
/// passed by the bootloader.
pub unsafe fn parse_memory_map(info_addr: usize) -> MemoryMap {
    let info = &*(info_addr as *const MultibootInfo);

    let mut map = MemoryMap {
        regions: [MemRegion { base: PhysAddr::new(0), size: 0 }; MAX_REGIONS],
        count: 0,
        total_usable: 0,
    };

    // Debug: print flags
    crate::arch::x86_64::serial::write_str("  multiboot flags: ");
    { let mut __hb = [0u8; 16]; super::serial::write_str("0x"); super::serial::write_bytes(rux_klib::fmt::usize_to_hex(&mut __hb, info.flags as usize)); }
    crate::arch::x86_64::serial::write_str("\n");

    // Check if memory map is present (flag bit 6)
    if info.flags & (1 << 6) == 0 {
        // No memory map — fall back to mem_lower/mem_upper
        if info.flags & 1 != 0 {
            // Basic memory info available
            let upper_bytes = info.mem_upper as usize * 1024;
            if upper_bytes > 0 && map.count < MAX_REGIONS {
                map.regions[0] = MemRegion {
                    base: PhysAddr::new(0x100000), // upper memory starts at 1MB
                    size: upper_bytes,
                };
                map.count = 1;
                map.total_usable = upper_bytes;
            }
        }
        return map;
    }

    // Walk the memory map entries
    let mmap_start = info.mmap_addr as usize;
    let mmap_end = mmap_start + info.mmap_length as usize;
    let mut offset = mmap_start;

    while offset < mmap_end && map.count < MAX_REGIONS {
        let entry = &*(offset as *const MmapEntry);

        // Type 1 = available RAM
        if entry.entry_type == 1 {
            let base = entry.base_addr as usize;
            let size = entry.length as usize;

            // Skip the first 1MB (BIOS/VGA/bootloader area)
            if base >= 0x100000 && size > 0 {
                map.regions[map.count] = MemRegion {
                    base: PhysAddr::new(base),
                    size,
                };
                map.total_usable += size;
                map.count += 1;
            } else if base < 0x100000 && base + size > 0x100000 {
                // Region spans across 1MB — take the part above
                let usable_base = 0x100000;
                let usable_size = size - (usable_base - base);
                map.regions[map.count] = MemRegion {
                    base: PhysAddr::new(usable_base),
                    size: usable_size,
                };
                map.total_usable += usable_size;
                map.count += 1;
            }
        }

        // Advance to next entry (size field + 4 bytes for the size field itself)
        offset += entry.size as usize + 4;
    }

    map
}

/// Multiboot module entry.
#[repr(C)]
struct MultibootModule {
    mod_start: u32,
    mod_end: u32,
    _string: u32,
    _reserved: u32,
}

/// Get the first multiboot module (initramfs).
/// Returns (start_addr, size) or None if no modules.
///
/// # Safety
/// `info_addr` must be a valid MultibootInfo pointer.
pub unsafe fn get_initrd(info_addr: usize) -> Option<(usize, usize)> {
    let info = &*(info_addr as *const MultibootInfo);

    // Check if modules are present (flag bit 3)
    if info.flags & (1 << 3) == 0 || info.mods_count == 0 {
        return None;
    }

    let module = &*(info.mods_addr as *const MultibootModule);
    let start = module.mod_start as usize;
    let end = module.mod_end as usize;
    if end > start {
        Some((start, end - start))
    } else {
        None
    }
}
