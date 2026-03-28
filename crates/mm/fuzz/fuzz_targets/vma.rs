#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_klib::VirtAddr;
use rux_mm::vma::{Vma, VmaKind, VmaList, VmaOps, MAX_VMAS};
use rux_mm::MappingFlags;

#[derive(Debug, Arbitrary)]
enum VmaOp {
    Insert { start_page: u16, size_pages: u8 },
    Remove { addr_page: u16 },
    Find { addr_page: u16 },
    Split { addr_page: u16 },
    Protect { start_page: u16, end_page: u16, writable: bool },
}

fn make_vma(start: usize, end: usize) -> Vma {
    Vma {
        start: VirtAddr::new(start),
        end: VirtAddr::new(end),
        flags: MappingFlags::READ.or(MappingFlags::WRITE),
        kind: VmaKind::Anonymous,
        _pad: [0; 3],
        inode: 0,
        offset: 0,
    }
}

fuzz_target!(|ops: Vec<VmaOp>| {
    if ops.len() > 256 {
        return;
    }

    let mut list = VmaList::new();

    for op in &ops {
        match op {
            VmaOp::Insert { start_page, size_pages } => {
                let start = (*start_page as usize) * 0x1000;
                let size = (*size_pages as usize + 1) * 0x1000;
                let end = start + size;
                let _ = list.insert(make_vma(start, end));
            }
            VmaOp::Remove { addr_page } => {
                let addr = VirtAddr::new((*addr_page as usize) * 0x1000 + 0x500);
                let _ = list.remove(addr);
            }
            VmaOp::Find { addr_page } => {
                let addr = VirtAddr::new((*addr_page as usize) * 0x1000 + 0x500);
                let _ = list.find(addr);
            }
            VmaOp::Split { addr_page } => {
                let addr = VirtAddr::new((*addr_page as usize) * 0x1000);
                let _ = list.split(addr);
            }
            VmaOp::Protect { start_page, end_page, writable } => {
                let start = VirtAddr::new((*start_page as usize) * 0x1000);
                let end = VirtAddr::new((*end_page as usize) * 0x1000);
                let flags = if *writable {
                    MappingFlags::READ.or(MappingFlags::WRITE)
                } else {
                    MappingFlags::READ
                };
                let _ = list.protect(start, end, flags);
            }
        }

        let n = list.count as usize;

        // ── Invariant: sorted by start address ──
        for i in 1..n {
            assert!(
                list.entries[i].start.as_usize() > list.entries[i - 1].start.as_usize(),
                "VMA list not sorted at index {}: {:#x} <= {:#x}",
                i, list.entries[i].start.as_usize(), list.entries[i - 1].start.as_usize()
            );
        }

        // ── Invariant: no overlaps ──
        for i in 1..n {
            assert!(
                list.entries[i].start.as_usize() >= list.entries[i - 1].end.as_usize(),
                "VMA overlap: [{:#x},{:#x}) and [{:#x},{:#x})",
                list.entries[i - 1].start.as_usize(), list.entries[i - 1].end.as_usize(),
                list.entries[i].start.as_usize(), list.entries[i].end.as_usize()
            );
        }

        // ── Invariant: all VMAs have start < end ──
        for i in 0..n {
            assert!(
                list.entries[i].start.as_usize() < list.entries[i].end.as_usize(),
                "VMA {} has start >= end",
                i
            );
        }

        // ── Invariant: count <= MAX_VMAS ──
        assert!(n <= MAX_VMAS);

        // ── Invariant: entries beyond count are empty ──
        for i in n..MAX_VMAS {
            assert_eq!(list.entries[i].start.as_usize(), 0);
        }
    }
});
