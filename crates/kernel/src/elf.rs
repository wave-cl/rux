/// ELF loading: builds user page tables and enters user mode.
///
/// ELF parsing and segment loading are handled by the `rux_elf` crate.
/// This module handles the kernel-specific parts: page table construction,
/// VFS reader adapter, and the transition to user mode.

pub use rux_elf::{parse_elf, ElfInfo, LoadSegment, PF_R, PF_W, PF_X, load_segments};

/// Architecture-specific buffer-based ELF loaders are in:
/// - `x86_64::loader::load_and_exec_elf`
/// - `aarch64::loader::load_and_exec_elf`

/// VFS-backed ELF reader — adapts a VFS inode to the `ElfReader` trait.
struct VfsReader {
    ino: u64,
}

impl rux_elf::ElfReader for VfsReader {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> usize {
        unsafe {
            use rux_vfs::FileSystem;
            let fs = crate::kstate::fs();
            fs.read(self.ino, offset, buf).unwrap_or(0)
        }
    }
}

/// Page table adapter — wraps the kernel's PageTable4Level for ElfPageTable.
struct PtAdapter<'a> {
    pt: &'a mut crate::arch::PageTable,
}

unsafe impl<'a> rux_elf::ElfPageTable for PtAdapter<'a> {
    fn map_4k(
        &mut self,
        va: rux_klib::VirtAddr,
        phys: rux_klib::PhysAddr,
        flags: rux_mm::MappingFlags,
        alloc: &mut dyn rux_mm::FrameAllocator,
    ) {
        self.pt.map_4k(va, phys, flags, alloc).expect("map seg");
    }
    fn unmap_4k(&mut self, va: rux_klib::VirtAddr) {
        let _ = self.pt.unmap_4k(va);
    }
}

/// Load an ELF binary from a VFS inode into a fresh user page table.
///
/// This is the core of exec(): parse the ELF, build a user page table
/// with the kernel identity-mapped, load segments, map a user stack,
/// activate, and jump to user mode.
pub unsafe fn load_elf_from_inode(
    ino: u64,
    alloc: &mut dyn rux_mm::FrameAllocator,
) -> ! {
    use rux_klib::VirtAddr;
    use rux_vfs::FileSystem;

    let mut talloc = crate::pgtrack::TrackingAllocator::new(alloc);
    let alloc: &mut dyn rux_mm::FrameAllocator = &mut talloc;

    let fs = crate::kstate::fs();

    // Read ELF header (first 4KB is enough for header + program headers)
    let mut hdr_buf = [0u8; 4096];
    let _n = fs.read(ino, 0, &mut hdr_buf).unwrap_or(0);
    let elf_info = parse_elf(&hdr_buf).expect("ELF parse failed");

    // Build user page table with kernel identity map
    let mut upt = {
        use crate::arch::KernelMapOps;
        let mut upt = crate::arch::PageTable::new(alloc).expect("user pt");
        crate::arch::Arch::map_kernel_pages(&mut upt, alloc);
        upt
    };

    // Load segments + map stack via rux-elf generic loader
    let mut reader = VfsReader { ino };
    let mut pt_adapter = PtAdapter { pt: &mut upt };
    let (stack_top, max_end) = rux_elf::load_elf_to_pt(
        &elf_info, &mut reader, &mut pt_adapter, alloc, 32,
    );

    // Set program break and mmap base for brk/mmap syscalls
    crate::syscall::PROGRAM_BRK = max_end as usize;
    crate::syscall::MMAP_BASE = 0x10000000;
    crate::fdtable::reset();

    // Activate page table
    {
        use rux_arch::PageTableRootOps;
        crate::arch::Arch::write(upt.root_phys().as_usize() as u64);
    }

    // Write exec args to user stack and enter user mode
    let user_sp = crate::execargs::write_to_stack(stack_top);
    {
        use rux_arch::SerialOps;
        type A = crate::arch::Arch;
        A::write_str("rux: entry=0x");
        crate::write_hex_serial(elf_info.entry as usize);
        A::write_str(" sp=0x");
        crate::write_hex_serial(user_sp as usize);
        let sp_ptr = user_sp as *const u64;
        A::write_str(" argc=");
        crate::write_hex_serial(*sp_ptr as usize);
        A::write_str(" argv0=0x");
        crate::write_hex_serial(*sp_ptr.add(1) as usize);
        A::write_str("\n");
    }

    {
        use rux_arch::UserModeOps;
        crate::arch::Arch::enter_user_mode(elf_info.entry, user_sp);
    }
}

// Buffer-based ELF loaders moved to:
//   x86_64/loader.rs  — crate::arch::x86_64::loader::load_and_exec_elf
//   aarch64/loader.rs — crate::arch::aarch64::loader::load_and_exec_elf
