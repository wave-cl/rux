/// x86_64 buffer-based ELF loader.
///
/// Loads an ELF binary from a byte slice into a fresh user page table,
/// then enters user mode. Used during boot init (before VFS is available).

use crate::elf::{parse_elf, PF_R, PF_W, PF_X};

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

    let mut upt = super::paging::PageTable4Level::new(alloc).expect("user pt");
    let kflags = MappingFlags::READ
        .or(MappingFlags::WRITE)
        .or(MappingFlags::EXECUTE);
    upt.identity_map_range(PhysAddr::new(0), 16 * 1024 * 1024, kflags, alloc)
        .expect("kernel map");

    for i in 0..map_count {
        let (va, phys, flags_raw) = seg_mappings[i];
        let flags = MappingFlags(flags_raw);
        upt.map_4k(VirtAddr::new(va as usize), phys, flags, alloc)
            .expect("map user seg");
    }

    let stack_flags = MappingFlags::READ
        .or(MappingFlags::WRITE)
        .or(MappingFlags::USER);
    let stack_pages = 32u64;
    let stack_base = 0x80000000u64 - stack_pages * 4096;
    for p in 0..stack_pages {
        let sp = alloc.alloc(PageSize::FourK).expect("stack page");
        upt.map_4k(
            VirtAddr::new((stack_base + p * 4096) as usize), sp, stack_flags, alloc,
        ).expect("map stack");
    }
    let stack_top = stack_base + stack_pages * 4096;

    super::paging::activate(&upt);
    let user_sp = crate::execargs::write_to_stack(stack_top as usize);
    super::syscall::enter_user_mode(elf_info.entry as usize, user_sp);
}
