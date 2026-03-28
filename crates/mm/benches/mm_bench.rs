#![feature(test)]
extern crate test;

use rux_klib::{PhysAddr, VirtAddr};
use rux_mm::frame::BuddyAllocator;
use rux_mm::vma::{Vma, VmaKind, VmaList, VmaOps};
use rux_mm::pt::{pt_index, PageLevel};
use rux_mm::{MappingFlags, FrameAllocator, PageSize};
use test::Bencher;

fn make_allocator(frames: u32) -> Box<BuddyAllocator> {
    let mut alloc = unsafe {
        let layout = std::alloc::Layout::new::<BuddyAllocator>();
        let ptr = std::alloc::alloc_zeroed(layout) as *mut BuddyAllocator;
        Box::from_raw(ptr)
    };
    alloc.init(PhysAddr::new(0x10_0000), frames);
    alloc
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

// ── Buddy allocator benchmarks ──────────────────────────────────────────

#[bench]
fn bench_buddy_alloc_dealloc_order0(b: &mut Bencher) {
    let mut alloc = make_allocator(4096);
    b.iter(|| {
        let addr = alloc.alloc_order(0).unwrap();
        alloc.dealloc_order(addr, 0);
        test::black_box(addr);
    });
}

#[bench]
fn bench_buddy_alloc_1000_order0(b: &mut Bencher) {
    b.iter(|| {
        let mut alloc = make_allocator(4096);
        let mut addrs = Vec::with_capacity(1000);
        for _ in 0..1000 {
            addrs.push(alloc.alloc_order(0).unwrap());
        }
        for addr in addrs {
            alloc.dealloc_order(addr, 0);
        }
        test::black_box(alloc.free_frames);
    });
}

#[bench]
fn bench_buddy_alloc_order3(b: &mut Bencher) {
    let mut alloc = make_allocator(4096);
    b.iter(|| {
        let addr = alloc.alloc_order(3).unwrap();
        alloc.dealloc_order(addr, 3);
        test::black_box(addr);
    });
}

// ── VMA benchmarks ──────────────────────────────────────────────────────

#[bench]
fn bench_vma_find_64(b: &mut Bencher) {
    let mut list = VmaList::new();
    for i in 0..64 {
        let base = (i + 1) * 0x10000;
        list.insert(make_vma(base, base + 0x10000)).unwrap();
    }
    // Search for VMA in the middle
    let target = VirtAddr::new(32 * 0x10000 + 0x5000);
    b.iter(|| {
        test::black_box(list.find(target));
    });
}

#[bench]
fn bench_vma_find_128(b: &mut Bencher) {
    let mut list = VmaList::new();
    for i in 0..128 {
        let base = (i + 1) * 0x10000;
        list.insert(make_vma(base, base + 0x10000)).unwrap();
    }
    let target = VirtAddr::new(64 * 0x10000 + 0x5000);
    b.iter(|| {
        test::black_box(list.find(target));
    });
}

#[bench]
fn bench_vma_insert_remove(b: &mut Bencher) {
    let mut list = VmaList::new();
    for i in 0..63 {
        let base = (i + 1) * 0x10000;
        list.insert(make_vma(base, base + 0x10000)).unwrap();
    }
    let vma = make_vma(0x1000_0000, 0x1001_0000);
    b.iter(|| {
        list.insert(vma).unwrap();
        list.remove(VirtAddr::new(0x1000_5000)).unwrap();
    });
}

// ── PT index benchmarks ────────────────────────────────────────────────

#[bench]
fn bench_pt_index_extraction(b: &mut Bencher) {
    let vaddr = VirtAddr::new(0x7FFF_FFFF_F000);
    b.iter(|| {
        let l0 = pt_index(vaddr, PageLevel::L0);
        let l1 = pt_index(vaddr, PageLevel::L1);
        let l2 = pt_index(vaddr, PageLevel::L2);
        let l3 = pt_index(vaddr, PageLevel::L3);
        test::black_box((l0, l1, l2, l3));
    });
}
