/// Shared demand paging and page fault resolution.
///
/// Used by both x86_64 and aarch64 fault handlers.
/// Provides: demand page allocation, COW resolution, and SIGSEGV delivery.

use rux_arch::MemoryLayout;

/// Allocate and map a zero-filled user page at the faulting address.
/// Reads software PTE marker bits to determine permissions:
/// - Prot marker with R/W/X bits → map with those permissions
/// - No marker → default RWX (stack, heap, ELF segments)
/// - Already-valid PTE → return false (permission fault, not demand-pageable)
#[inline]
pub unsafe fn demand_page(addr: usize) -> bool {
    let va = rux_klib::VirtAddr::new(addr & !0xFFF);
    let raw_pte = crate::syscall::current_user_page_table().read_leaf_pte(va);

    // If page is already mapped (VALID/PRESENT bit), this is a permission fault.
    // Do NOT replace the existing page with zeros — return false for SIGSEGV.
    if raw_pte & 1 != 0 {
        return false;
    }

    // Decode prot marker from software PTE bits
    let (has_marker, prot) = crate::arch::PageTable::decode_prot_marker(raw_pte);
    let flags = if has_marker {
        let mut f = rux_mm::MappingFlags::USER;
        if prot & 1 != 0 { f = f.or(rux_mm::MappingFlags::READ); }
        if prot & 2 != 0 { f = f.or(rux_mm::MappingFlags::WRITE); }
        if prot & 4 != 0 { f = f.or(rux_mm::MappingFlags::EXECUTE); }
        f
    } else {
        // No marker — default RWX (stack, heap, ELF segments)
        rux_mm::MappingFlags::READ
            .or(rux_mm::MappingFlags::WRITE)
            .or(rux_mm::MappingFlags::EXECUTE)
            .or(rux_mm::MappingFlags::USER)
    };

    use rux_mm::FrameAllocator;
    let alloc = crate::kstate::alloc();
    let frame = match alloc.alloc(rux_mm::PageSize::FourK) {
        Ok(f) => f,
        Err(_) => return false,
    };
    core::ptr::write_bytes(frame.as_usize() as *mut u8, 0, 4096);
    let mut upt = crate::syscall::current_user_page_table();
    let _ = upt.unmap_4k(va);
    match upt.map_4k(va, frame, flags, alloc) {
        Ok(()) => true,
        Err(_) => false,
    }
}

/// Maximum stack size in pages (8MB / 4KB = 2048 pages, like Linux RLIMIT_STACK default).
const MAX_STACK_PAGES: usize = 2048;

/// Stack base: lowest address of the initial stack mapping.
/// ELF loader maps 32 pages below stack_top (typically 0x80000000).
const STACK_TOP: usize = 0x80000000;
#[allow(dead_code)]
const INITIAL_STACK_PAGES: usize = 32;
const STACK_FLOOR: usize = STACK_TOP - MAX_STACK_PAGES * 4096;

/// Try to resolve a user-space page fault.
///
/// Attempts COW resolution (for write faults), then demand paging,
/// then stack growth (for faults just below the current stack).
/// Returns true if the fault was resolved; false means the caller
/// should deliver SIGSEGV or panic (kernel fault).
#[inline]
pub unsafe fn handle_user_fault(addr: u64, is_write: bool) -> bool {
    // COW resolution for write faults to user addresses
    if is_write && addr < crate::arch::Arch::USER_ADDR_LIMIT {
        if crate::cow::handle_cow_fault(addr as usize).is_ok() {
            return true;
        }
    }
    // Demand paging for any fault at a valid user address (>= 0x1000 avoids null guard)
    if addr >= 0x1000 && addr < crate::arch::Arch::USER_ADDR_LIMIT {
        // Check for PROT_NONE marker — the PTE is non-present but has the
        // software PROT_NONE bit set, meaning this address is intentionally
        // inaccessible (guard page). Deliver SIGSEGV, don't demand-page.
        let raw_pte = crate::syscall::current_user_page_table()
            .read_leaf_pte(rux_klib::VirtAddr::new(addr as usize & !0xFFF));
        if raw_pte & crate::arch::PageTable::prot_none_bit() != 0 {
            return false; // PROT_NONE → SIGSEGV
        }
        if demand_page(addr as usize) {
            return true;
        }
        // Stack growth: if the fault is in the growable stack region
        // (below the initial stack mapping but above the stack floor),
        // map a new page. Linux allows growth up to RLIMIT_STACK (8MB).
        let page_addr = addr as usize & !0xFFF;
        if page_addr >= STACK_FLOOR && page_addr < STACK_TOP {
            return demand_page(page_addr);
        }
    }
    false
}
