/// ACPI table parsing: RSDP discovery, RSDT traversal, SRAT extraction.
///
/// Used at boot to detect NUMA topology. The kernel identity-maps
/// 0-128MB, so all ACPI tables in that range are accessible.

/// RSDP v1 structure (20 bytes).
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],   // "RSD PTR "
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// ACPI table header (common to all tables).
#[repr(C, packed)]
struct AcpiHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// SRAT Memory Affinity entry (type 1, 40 bytes).
#[repr(C, packed)]
#[allow(dead_code)]
struct SratMemAffinity {
    entry_type: u8,        // 1
    length: u8,            // 40
    proximity_domain: u32,
    _reserved1: u16,
    base_low: u32,
    base_high: u32,
    length_low: u32,
    length_high: u32,
    _reserved2: u32,
    flags: u32,            // bit 0 = enabled
    _reserved3: [u8; 8],
}

/// Scan the BIOS region (0xE0000-0xFFFFF) for the ACPI RSDP.
/// Returns the RSDP physical address, or None if not found.
pub unsafe fn find_rsdp() -> Option<usize> {
    let mut addr = 0xE0000usize;
    while addr < 0x100000 {
        let sig = core::slice::from_raw_parts(addr as *const u8, 8);
        if sig == b"RSD PTR " {
            // Validate checksum (sum of first 20 bytes must be 0)
            let bytes = core::slice::from_raw_parts(addr as *const u8, 20);
            let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
            if sum == 0 {
                return Some(addr);
            }
        }
        addr += 16; // RSDP is always 16-byte aligned
    }
    None
}

/// Parse the RSDT to find the SRAT table address.
pub unsafe fn find_srat(rsdp_addr: usize) -> Option<usize> {
    let rsdp = &*(rsdp_addr as *const Rsdp);
    let rsdt_addr = rsdp.rsdt_address as usize;
    if rsdt_addr == 0 || rsdt_addr >= 128 * 1024 * 1024 { return None; }

    let rsdt = &*(rsdt_addr as *const AcpiHeader);
    if &rsdt.signature != b"RSDT" { return None; }

    let header_size = core::mem::size_of::<AcpiHeader>();
    let rsdt_len = rsdt.length as usize;
    // Sanity check: RSDT length must be reasonable (header + at most 256 entries)
    if rsdt_len < header_size || rsdt_len > header_size + 256 * 4 { return None; }
    // Verify the entire RSDT is within mapped memory
    let rsdt_end = rsdt_addr + rsdt_len;
    if rsdt_end >= 128 * 1024 * 1024 { return None; }
    let entry_count = (rsdt_len - header_size) / 4;
    let entries = (rsdt_addr + header_size) as *const u32;

    // Limit to avoid accessing unmapped memory. Identity map covers 0-128MB,
    // but QEMU may place ACPI tables near the top of RAM which can shift
    // when PCI devices are added.
    let mem_limit = 128 * 1024 * 1024;
    for i in 0..entry_count {
        let entry_ptr = entries.add(i) as usize;
        if entry_ptr + 4 > mem_limit { break; }
        let table_addr = core::ptr::read_unaligned(entry_ptr as *const u32) as usize;
        if table_addr == 0 || table_addr + 36 >= mem_limit { continue; }
        let header = &*(table_addr as *const AcpiHeader);
        if &header.signature == b"SRAT" {
            return Some(table_addr);
        }
    }
    None
}

/// Parse the SRAT table to extract NUMA memory affinity entries.
pub unsafe fn parse_srat(srat_addr: usize) -> rux_arch::numa::NumaTopology {
    let mut topo = rux_arch::numa::NumaTopology::empty();
    let header = &*(srat_addr as *const AcpiHeader);
    let end = srat_addr + header.length as usize;
    // SRAT has 12 bytes reserved after the header
    let mut pos = srat_addr + core::mem::size_of::<AcpiHeader>() + 12;

    while pos + 2 <= end {
        let entry_type = *(pos as *const u8);
        let entry_len = *((pos + 1) as *const u8) as usize;
        if entry_len == 0 { break; }

        // Type 1 = Memory Affinity
        if entry_type == 1 && entry_len >= 40 {
            let mem = &*(pos as *const SratMemAffinity);
            if mem.flags & 1 != 0 { // enabled
                let base = (mem.base_high as u64) << 32 | mem.base_low as u64;
                let size = (mem.length_high as u64) << 32 | mem.length_low as u64;
                topo.add(base, size, mem.proximity_domain);
            }
        }
        pos += entry_len;
    }
    topo
}
