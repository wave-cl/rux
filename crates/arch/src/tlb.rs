use rux_klib::VirtAddr;

/// TLB invalidation operations.
///
/// # Safety
/// TLB flushes affect address translation globally or locally. Incorrect
/// flushing causes stale translations → silent memory corruption.
pub unsafe trait TlbOps {
    /// Invalidate the TLB entry for a single page.
    /// x86_64: invlpg. aarch64: tlbi vale1is.
    unsafe fn flush_page(vaddr: VirtAddr);

    /// Invalidate all TLB entries.
    /// x86_64: write CR3 (reload). aarch64: tlbi vmalle1is.
    unsafe fn flush_all();

    /// Invalidate all non-global TLB entries.
    /// Used after address space switch (global kernel mappings stay cached).
    unsafe fn flush_non_global();

    /// Invalidate TLB entries for a range of pages.
    /// Default implementation calls flush_page in a loop; architectures
    /// with range invalidation can override.
    unsafe fn flush_range(start: VirtAddr, pages: usize) {
        let page_size = 4096usize;
        let mut addr = start;
        for _ in 0..pages {
            Self::flush_page(addr);
            addr = VirtAddr::new(addr.as_usize() + page_size);
        }
    }
}
