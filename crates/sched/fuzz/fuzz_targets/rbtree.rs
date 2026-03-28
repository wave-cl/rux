#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rux_sched::entity::SchedEntity;
use rux_sched::fair::rbtree::{FairTimeline, verify};

const MAX_ENTITIES: usize = 64;

#[derive(Debug, Arbitrary)]
enum Op {
    Insert { vruntime: u16, vdeadline: u16 },
    Remove { idx: u8 },
    PickEevdf { avg_vrt: u16 },
    Leftmost,
}

fuzz_target!(|ops: Vec<Op>| {
    if ops.len() > 256 {
        return;
    }

    let mut tree = FairTimeline::new();
    let mut entities: [SchedEntity; MAX_ENTITIES] = core::array::from_fn(|i| {
        SchedEntity::new(i as u64)
    });
    let mut in_tree = [false; MAX_ENTITIES];
    let mut next_slot: usize = 0;

    for op in &ops {
        match op {
            Op::Insert { vruntime, vdeadline } => {
                if next_slot >= MAX_ENTITIES {
                    continue;
                }
                let idx = next_slot;
                next_slot += 1;
                entities[idx].vruntime = *vruntime as u64;
                entities[idx].vdeadline = *vdeadline as u64;
                entities[idx].rb_min_vdeadline = *vdeadline as u64;
                entities[idx].rb_left = core::ptr::null_mut();
                entities[idx].rb_right = core::ptr::null_mut();
                entities[idx].rb_parent_color = 0;
                unsafe { tree.insert(&mut entities[idx]); }
                in_tree[idx] = true;
            }
            Op::Remove { idx } => {
                if next_slot == 0 {
                    continue;
                }
                let idx = (*idx as usize) % next_slot;
                if !in_tree[idx] {
                    continue;
                }
                unsafe { tree.remove(&mut entities[idx]); }
                in_tree[idx] = false;
            }
            Op::PickEevdf { avg_vrt } => {
                let avg = *avg_vrt as u64;
                let tree_result = tree.pick_eevdf(avg);
                let ptrs: Vec<*mut SchedEntity> = (0..next_slot)
                    .map(|i| &mut entities[i] as *mut _)
                    .collect();
                let oracle = verify::brute_force_pick(&ptrs, &in_tree[..next_slot], avg);

                // Both should agree: either both None, or both point to an
                // entity with the same vdeadline (ties may pick different ptrs)
                match (tree_result, oracle) {
                    (None, None) => {}
                    (Some(t), Some(o)) => unsafe {
                        assert_eq!(
                            (*t).vdeadline, (*o).vdeadline,
                            "pick_eevdf disagrees with oracle: tree picked vd={}, oracle picked vd={}",
                            (*t).vdeadline, (*o).vdeadline
                        );
                    }
                    (Some(_), None) => {
                        // Tree found something oracle didn't — tree is wrong
                        // (oracle scans everything, can't miss)
                        panic!("pick_eevdf returned Some but oracle returned None");
                    }
                    (None, Some(o)) => unsafe {
                        panic!(
                            "pick_eevdf returned None but oracle found entity with vruntime={}, vdeadline={}",
                            (*o).vruntime, (*o).vdeadline
                        );
                    }
                }
            }
            Op::Leftmost => {
                let result = tree.leftmost();
                // Verify it's actually the minimum vruntime
                if let Some(lm) = result {
                    unsafe {
                        for i in 0..next_slot {
                            if in_tree[i] {
                                assert!(
                                    (*lm).vruntime <= entities[i].vruntime,
                                    "leftmost vruntime {} > entity {} vruntime {}",
                                    (*lm).vruntime, i, entities[i].vruntime
                                );
                            }
                        }
                    }
                } else {
                    // If leftmost is None, no entity should be in tree
                    assert!(!in_tree[..next_slot].contains(&true));
                }
            }
        }

        // Check all invariants after every operation
        unsafe {
            assert!(verify::check_rb_properties(tree.root), "RB property violated");
            assert!(verify::check_bst_ordering(tree.root), "BST ordering violated");
            assert!(verify::check_augmentation(tree.root), "augmentation violated");
        }
    }
});
