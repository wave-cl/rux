#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_klib::PhysAddr;
use rux_mm::frame::BuddyAllocator;

const TEST_FRAMES: u32 = 256;

#[derive(Debug, Arbitrary)]
enum BuddyOp {
    Alloc { order: u8 },
    Dealloc { idx: u8 },
}

fuzz_target!(|ops: Vec<BuddyOp>| {
    if ops.len() > 512 {
        return;
    }

    let mut alloc = unsafe {
        let layout = std::alloc::Layout::new::<BuddyAllocator>();
        let ptr = std::alloc::alloc_zeroed(layout) as *mut BuddyAllocator;
        Box::from_raw(ptr)
    };
    alloc.init(PhysAddr::new(0x10_0000), TEST_FRAMES);

    let mut allocated: Vec<(PhysAddr, u8)> = Vec::new();

    for op in &ops {
        match op {
            BuddyOp::Alloc { order } => {
                let order = *order % 8; // limit to order 0-7
                if let Ok(addr) = alloc.alloc_order(order) {
                    allocated.push((addr, order));
                }
            }
            BuddyOp::Dealloc { idx } => {
                if !allocated.is_empty() {
                    let idx = *idx as usize % allocated.len();
                    let (addr, order) = allocated.remove(idx);
                    alloc.dealloc_order(addr, order);
                }
            }
        }

        // ── Invariant: free_frames + allocated_frames == total ──
        let allocated_frames: u32 = allocated.iter()
            .map(|(_, order)| 1u32 << order)
            .sum();
        assert_eq!(
            alloc.free_frames + allocated_frames, TEST_FRAMES,
            "free {} + alloc {} != total {}",
            alloc.free_frames, allocated_frames, TEST_FRAMES
        );

        // ── Invariant: no overlap between allocated blocks ──
        let mut ranges: Vec<(usize, usize)> = allocated.iter()
            .map(|(addr, order)| {
                let start = addr.as_usize();
                let size = (1usize << order) * 4096;
                (start, start + size)
            })
            .collect();
        ranges.sort();
        for i in 1..ranges.len() {
            assert!(
                ranges[i].0 >= ranges[i - 1].1,
                "overlap: [{:#x}, {:#x}) and [{:#x}, {:#x})",
                ranges[i - 1].0, ranges[i - 1].1, ranges[i].0, ranges[i].1
            );
        }
    }
});
