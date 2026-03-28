#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_proc::id::Pid;
use rux_proc::pid::PidBitmap;

use std::collections::HashSet;

#[derive(Debug, Arbitrary)]
enum PidOp {
    Alloc,
    Free { idx: u8 },
    AllocSpecific { pid: u16 },
    IsAllocated { pid: u16 },
}

fuzz_target!(|ops: Vec<PidOp>| {
    if ops.len() > 512 {
        return;
    }

    let mut bm = unsafe {
        let layout = std::alloc::Layout::new::<PidBitmap>();
        let ptr = std::alloc::alloc_zeroed(layout) as *mut PidBitmap;
        let mut b = Box::from_raw(ptr);
        *b = PidBitmap::new();
        b
    };

    // Shadow oracle: track which PIDs are allocated
    let mut shadow: HashSet<u32> = HashSet::new();
    shadow.insert(0); // PID 0 is reserved

    // Track allocated PIDs for indexed free
    let mut allocated_list: Vec<Pid> = Vec::new();

    for op in &ops {
        match op {
            PidOp::Alloc => {
                match bm.alloc() {
                    Ok(pid) => {
                        let n = pid.as_u32();
                        assert!(
                            !shadow.contains(&n),
                            "alloc returned PID {} which is already allocated",
                            n
                        );
                        shadow.insert(n);
                        allocated_list.push(pid);
                    }
                    Err(_) => {
                        // Should only fail if all PIDs are taken
                        assert_eq!(
                            shadow.len(),
                            rux_proc::pid::MAX_PIDS,
                            "alloc failed but only {} of {} PIDs allocated",
                            shadow.len(),
                            rux_proc::pid::MAX_PIDS
                        );
                    }
                }
            }
            PidOp::Free { idx } => {
                if !allocated_list.is_empty() {
                    let idx = *idx as usize % allocated_list.len();
                    let pid = allocated_list.remove(idx);
                    shadow.remove(&pid.as_u32());
                    bm.free(pid);
                }
            }
            PidOp::AllocSpecific { pid } => {
                let n = (*pid as u32) % rux_proc::pid::MAX_PIDS as u32;
                let pid = Pid::new(n);
                match bm.alloc_specific(pid) {
                    Ok(()) => {
                        assert!(
                            !shadow.contains(&n),
                            "alloc_specific succeeded for PID {} which shadow says is taken",
                            n
                        );
                        shadow.insert(n);
                        allocated_list.push(pid);
                    }
                    Err(_) => {
                        // Should fail if already allocated
                        assert!(
                            shadow.contains(&n),
                            "alloc_specific failed for PID {} but shadow says it's free",
                            n
                        );
                    }
                }
            }
            PidOp::IsAllocated { pid } => {
                let n = (*pid as u32) % rux_proc::pid::MAX_PIDS as u32;
                let result = bm.is_allocated(Pid::new(n));
                let expected = shadow.contains(&n);
                assert_eq!(
                    result, expected,
                    "is_allocated({}) = {} but shadow says {}",
                    n, result, expected
                );
            }
        }

        // ── Invariant: allocated count matches shadow ──
        assert_eq!(
            bm.allocated as usize, shadow.len(),
            "allocated {} != shadow len {}",
            bm.allocated, shadow.len()
        );
    }
});
