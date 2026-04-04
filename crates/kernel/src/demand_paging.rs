/// Shared demand paging and page fault resolution.
///
/// Used by both x86_64 and aarch64 fault handlers.
/// Provides: demand page allocation, COW resolution, and SIGSEGV delivery.

use rux_arch::MemoryLayout;

/// Allocate and map a zero-filled RWX user page at the faulting address.
/// Returns true if the page was successfully mapped.
#[inline]
pub unsafe fn demand_page(addr: usize) -> bool {
    use rux_mm::FrameAllocator;
    let alloc = crate::kstate::alloc();
    let frame = match alloc.alloc(rux_mm::PageSize::FourK) {
        Ok(f) => f,
        Err(_) => return false,
    };
    core::ptr::write_bytes(frame.as_usize() as *mut u8, 0, 4096);
    let va = rux_klib::VirtAddr::new(addr & !0xFFF);
    let flags = rux_mm::MappingFlags::READ
        .or(rux_mm::MappingFlags::WRITE)
        .or(rux_mm::MappingFlags::EXECUTE)
        .or(rux_mm::MappingFlags::USER);
    let mut upt = crate::syscall::current_user_page_table();
    let _ = upt.unmap_4k(va);
    match upt.map_4k(va, frame, flags, alloc) {
        Ok(()) => true,
        Err(_) => false,
    }
}

/// Try to resolve a user-space page fault.
///
/// Attempts COW resolution (for write faults), then demand paging.
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
        if demand_page(addr as usize) {
            return true;
        }
    }
    false
}
