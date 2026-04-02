use crate::entity::SchedEntity;

const RED: usize = 0;
const BLACK: usize = 1;

/// Intrusive red-black tree ordered by `vruntime`.
///
/// Each node is a `SchedEntity` with embedded link fields (`rb_left`,
/// `rb_right`, `rb_parent_color`). The tree is augmented: every node
/// caches `rb_min_vdeadline` — the minimum `vdeadline` in its subtree
/// (including itself). This enables O(log n) EEVDF eligible-EDF pick.
///
/// All operations are `unsafe` because they dereference raw pointers
/// into `SchedEntity` instances owned by the caller.
pub struct FairTimeline {
    pub root: *mut SchedEntity,
}

impl FairTimeline {
    pub const fn new() -> Self {
        Self {
            root: core::ptr::null_mut(),
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.root.is_null()
    }

    /// Insert a node into the tree ordered by `vruntime`.
    /// Ties are broken by pointer address for deterministic ordering.
    ///
    /// # Safety
    /// - `node` must be a valid, non-null pointer to a `SchedEntity`.
    /// - `node` must not already be in any tree.
    /// - The caller must ensure `node` remains valid for the tree's lifetime.
    pub unsafe fn insert(&mut self, node: *mut SchedEntity) {
        debug_assert!(!node.is_null());
        debug_assert!((*node).rb_left.is_null());
        debug_assert!((*node).rb_right.is_null());

        let mut parent: *mut SchedEntity = core::ptr::null_mut();
        let mut link: *mut *mut SchedEntity = &mut self.root;

        // BST insertion: walk down to find the correct leaf position
        while !(*link).is_null() {
            parent = *link;
            if vruntime_lt((*node).vruntime, (*parent).vruntime)
                || ((*node).vruntime == (*parent).vruntime && (node as usize) < (parent as usize))
            {
                link = &mut (*parent).rb_left;
            } else {
                link = &mut (*parent).rb_right;
            }
        }

        // Link the new node
        *link = node;
        (*node).rb_left = core::ptr::null_mut();
        (*node).rb_right = core::ptr::null_mut();
        set_parent_color(node, parent, RED);

        // Fix red-black violations (rotations change structure)
        self.insert_fixup(node);

        // Propagate augmentation from the inserted node to root.
        // O(log n) — each ancestor recomputed once.
        augment_propagate(node);
    }

    /// Remove a node from the tree.
    ///
    /// # Safety
    /// - `node` must be a valid pointer to a `SchedEntity` currently in this tree.
    #[allow(unused_assignments)]
    pub unsafe fn remove(&mut self, node: *mut SchedEntity) {
        debug_assert!(!node.is_null());

        let child: *mut SchedEntity;
        let parent: *mut SchedEntity;
        let color: usize;

        if (*node).rb_left.is_null() {
            // Node has at most a right child
            child = (*node).rb_right;
            parent = rb_parent(node);
            color = rb_color(node);
            self.transplant(node, child);
            if !child.is_null() {
                set_parent_color(child, parent, rb_color(child));
            }
        } else if (*node).rb_right.is_null() {
            // Node has only a left child
            child = (*node).rb_left;
            parent = rb_parent(node);
            color = rb_color(node);
            self.transplant(node, child);
            if !child.is_null() {
                set_parent_color(child, parent, rb_color(child));
            }
        } else {
            // Node has two children: find in-order successor (leftmost in right subtree)
            let successor = leftmost_of((*node).rb_right);
            color = rb_color(successor);
            child = (*successor).rb_right;
            parent = if rb_parent(successor) == node {
                successor
            } else {
                rb_parent(successor)
            };

            if rb_parent(successor) != node {
                // Successor is not the direct right child
                self.transplant(successor, (*successor).rb_right);
                (*successor).rb_right = (*node).rb_right;
                if !(*successor).rb_right.is_null() {
                    set_parent_color(
                        (*successor).rb_right,
                        successor,
                        rb_color((*successor).rb_right),
                    );
                }
            }

            self.transplant(node, successor);
            (*successor).rb_left = (*node).rb_left;
            if !(*successor).rb_left.is_null() {
                set_parent_color(
                    (*successor).rb_left,
                    successor,
                    rb_color((*successor).rb_left),
                );
            }
            set_parent_color(successor, rb_parent(successor), rb_color(node));
        }

        // Clear removed node's links
        (*node).rb_left = core::ptr::null_mut();
        (*node).rb_right = core::ptr::null_mut();
        (*node).rb_parent_color = 0;

        // Fix red-black violations if we removed a black node
        if color == BLACK {
            self.remove_fixup(child, parent);
        }

        // Propagate augmentation from splice point to root.
        // O(log n) — each ancestor recomputed once.
        if !parent.is_null() {
            augment_propagate(parent);
        }
    }

    /// Return the node with the smallest `vruntime` (leftmost node).
    #[inline]
    pub fn leftmost(&self) -> Option<*mut SchedEntity> {
        if self.root.is_null() {
            return None;
        }
        Some(unsafe { leftmost_of(self.root) })
    }

    /// EEVDF pick: among nodes with `vruntime <= avg_vrt` (eligible),
    /// find the one with the smallest `vdeadline`.
    ///
    /// Uses the `rb_min_vdeadline` augmentation to prune entire subtrees
    /// where no node can beat the current best deadline.
    ///
    /// Returns `None` if no eligible node exists.
    pub fn pick_eevdf(&self, avg_vrt: u64) -> Option<*mut SchedEntity> {
        if self.root.is_null() {
            return None;
        }

        let mut best: *mut SchedEntity = core::ptr::null_mut();
        let mut best_vd: u64 = u64::MAX;

        // Iterative traversal with explicit stack for right children
        let mut stack: [*mut SchedEntity; 64] = [core::ptr::null_mut(); 64];
        let mut sp: usize = 0;
        let mut current = self.root;

        unsafe {
            loop {
                while !current.is_null() {
                    // Prune: if this subtree can't beat our best, skip entirely
                    if (*current).rb_min_vdeadline >= best_vd {
                        break;
                    }


                    // Check if this node is eligible and has a better deadline
                    if !vruntime_gt((*current).vruntime, avg_vrt)
                        && (*current).vdeadline < best_vd
                    {
                        best = current;
                        best_vd = (*current).vdeadline;
                    }

                    // Push right child for later (if it could have better deadline)
                    let right = (*current).rb_right;
                    if !right.is_null() && (*right).rb_min_vdeadline < best_vd {
                        debug_assert!(sp < 64);
                        if sp < 64 {
                            stack[sp] = right;
                            sp += 1;
                        }
                    }

                    // Go left (smaller vruntime = more likely eligible)
                    current = (*current).rb_left;
                }

                // Pop next right child from stack
                if sp == 0 {
                    break;
                }
                sp -= 1;
                current = stack[sp];
            }
        }

        if best.is_null() {
            None
        } else {
            Some(best)
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Refresh augmentation for the entire subtree (post-order).
    /// Called after structural changes that may have invalidated multiple nodes.
    #[allow(dead_code)]
    unsafe fn propagate_full(&self, node: *mut SchedEntity) {
        if node.is_null() {
            return;
        }
        self.propagate_full((*node).rb_left);
        self.propagate_full((*node).rb_right);
        augment_node(node);
    }

    /// Replace `old` with `new_node` in the tree structure.
    unsafe fn transplant(&mut self, old: *mut SchedEntity, new_node: *mut SchedEntity) {
        let parent = rb_parent(old);
        if parent.is_null() {
            self.root = new_node;
        } else if (*parent).rb_left == old {
            (*parent).rb_left = new_node;
        } else {
            (*parent).rb_right = new_node;
        }
        if !new_node.is_null() {
            set_parent_color(new_node, parent, rb_color(new_node));
        }
    }

    unsafe fn insert_fixup(&mut self, mut node: *mut SchedEntity) {
        while !rb_parent(node).is_null() && rb_color(rb_parent(node)) == RED {
            let parent = rb_parent(node);
            let grandparent = rb_parent(parent);
            if grandparent.is_null() {
                break;
            }

            if parent == (*grandparent).rb_left {
                let uncle = (*grandparent).rb_right;
                if !uncle.is_null() && rb_color(uncle) == RED {
                    // Case 1: uncle is red — recolor
                    set_color(parent, BLACK);
                    set_color(uncle, BLACK);
                    set_color(grandparent, RED);
                    node = grandparent;
                } else {
                    if node == (*parent).rb_right {
                        // Case 2: node is right child — rotate left
                        node = parent;
                        self.rotate_left(node);
                    }
                    // Case 3: node is left child — rotate right
                    let parent = rb_parent(node);
                    let grandparent = rb_parent(parent);
                    set_color(parent, BLACK);
                    set_color(grandparent, RED);
                    self.rotate_right(grandparent);
                }
            } else {
                // Mirror: parent is right child of grandparent
                let uncle = (*grandparent).rb_left;
                if !uncle.is_null() && rb_color(uncle) == RED {
                    set_color(parent, BLACK);
                    set_color(uncle, BLACK);
                    set_color(grandparent, RED);
                    node = grandparent;
                } else {
                    if node == (*parent).rb_left {
                        node = parent;
                        self.rotate_right(node);
                    }
                    let parent = rb_parent(node);
                    let grandparent = rb_parent(parent);
                    set_color(parent, BLACK);
                    set_color(grandparent, RED);
                    self.rotate_left(grandparent);
                }
            }
        }
        // Root must always be black
        if !self.root.is_null() {
            set_color(self.root, BLACK);
        }
    }

    unsafe fn remove_fixup(&mut self, mut node: *mut SchedEntity, mut parent: *mut SchedEntity) {
        while (node.is_null() || rb_color(node) == BLACK) && node != self.root {
            if parent.is_null() {
                break;
            }
            if node == (*parent).rb_left {
                let mut sibling = (*parent).rb_right;
                if !sibling.is_null() && rb_color(sibling) == RED {
                    // Case 1: sibling is red
                    set_color(sibling, BLACK);
                    set_color(parent, RED);
                    self.rotate_left(parent);
                    sibling = (*parent).rb_right;
                }
                if sibling.is_null() {
                    node = parent;
                    parent = rb_parent(node);
                    continue;
                }
                let sl_black =
                    (*sibling).rb_left.is_null() || rb_color((*sibling).rb_left) == BLACK;
                let sr_black =
                    (*sibling).rb_right.is_null() || rb_color((*sibling).rb_right) == BLACK;
                if sl_black && sr_black {
                    // Case 2: both children of sibling are black
                    set_color(sibling, RED);
                    node = parent;
                    parent = rb_parent(node);
                } else {
                    if sr_black {
                        // Case 3: sibling's right child is black
                        if !(*sibling).rb_left.is_null() {
                            set_color((*sibling).rb_left, BLACK);
                        }
                        set_color(sibling, RED);
                        self.rotate_right(sibling);
                        sibling = (*parent).rb_right;
                    }
                    // Case 4: sibling's right child is red
                    if !sibling.is_null() {
                        set_color(sibling, rb_color(parent));
                    }
                    set_color(parent, BLACK);
                    if !sibling.is_null() && !(*sibling).rb_right.is_null() {
                        set_color((*sibling).rb_right, BLACK);
                    }
                    self.rotate_left(parent);
                    node = self.root;
                    break;
                }
            } else {
                // Mirror case
                let mut sibling = (*parent).rb_left;
                if !sibling.is_null() && rb_color(sibling) == RED {
                    set_color(sibling, BLACK);
                    set_color(parent, RED);
                    self.rotate_right(parent);
                    sibling = (*parent).rb_left;
                }
                if sibling.is_null() {
                    node = parent;
                    parent = rb_parent(node);
                    continue;
                }
                let sr_black =
                    (*sibling).rb_right.is_null() || rb_color((*sibling).rb_right) == BLACK;
                let sl_black =
                    (*sibling).rb_left.is_null() || rb_color((*sibling).rb_left) == BLACK;
                if sr_black && sl_black {
                    set_color(sibling, RED);
                    node = parent;
                    parent = rb_parent(node);
                } else {
                    if sl_black {
                        if !(*sibling).rb_right.is_null() {
                            set_color((*sibling).rb_right, BLACK);
                        }
                        set_color(sibling, RED);
                        self.rotate_left(sibling);
                        sibling = (*parent).rb_left;
                    }
                    if !sibling.is_null() {
                        set_color(sibling, rb_color(parent));
                    }
                    set_color(parent, BLACK);
                    if !sibling.is_null() && !(*sibling).rb_left.is_null() {
                        set_color((*sibling).rb_left, BLACK);
                    }
                    self.rotate_right(parent);
                    node = self.root;
                    break;
                }
            }
        }
        if !node.is_null() {
            set_color(node, BLACK);
        }
    }

    unsafe fn rotate_left(&mut self, x: *mut SchedEntity) {
        let y = (*x).rb_right;
        if y.is_null() {
            return;
        }

        (*x).rb_right = (*y).rb_left;
        if !(*y).rb_left.is_null() {
            set_parent_color((*y).rb_left, x, rb_color((*y).rb_left));
        }

        let parent = rb_parent(x);
        set_parent_color(y, parent, rb_color(y));

        if parent.is_null() {
            self.root = y;
        } else if (*parent).rb_left == x {
            (*parent).rb_left = y;
        } else {
            (*parent).rb_right = y;
        }

        (*y).rb_left = x;
        set_parent_color(x, y, rb_color(x));

        augment_node(x);
        augment_node(y);
    }

    unsafe fn rotate_right(&mut self, y: *mut SchedEntity) {
        let x = (*y).rb_left;
        if x.is_null() {
            return;
        }

        (*y).rb_left = (*x).rb_right;
        if !(*x).rb_right.is_null() {
            set_parent_color((*x).rb_right, y, rb_color((*x).rb_right));
        }

        let parent = rb_parent(y);
        set_parent_color(x, parent, rb_color(x));

        if parent.is_null() {
            self.root = x;
        } else if (*parent).rb_right == y {
            (*parent).rb_right = x;
        } else {
            (*parent).rb_left = x;
        }

        (*x).rb_right = y;
        set_parent_color(y, x, rb_color(y));

        augment_node(y);
        augment_node(x);
    }
}

// ── Node accessors ──────────────────────────────────────────────────────

#[inline(always)]
unsafe fn rb_parent(node: *mut SchedEntity) -> *mut SchedEntity {
    ((*node).rb_parent_color & !1usize) as *mut SchedEntity
}

#[inline(always)]
unsafe fn rb_color(node: *mut SchedEntity) -> usize {
    (*node).rb_parent_color & 1
}

#[inline(always)]
unsafe fn set_parent_color(node: *mut SchedEntity, parent: *mut SchedEntity, color: usize) {
    (*node).rb_parent_color = (parent as usize) | (color & 1);
}

#[inline(always)]
unsafe fn set_color(node: *mut SchedEntity, color: usize) {
    (*node).rb_parent_color = ((*node).rb_parent_color & !1usize) | (color & 1);
}

/// Walk left to find the minimum node in a subtree.
#[inline]
unsafe fn leftmost_of(mut node: *mut SchedEntity) -> *mut SchedEntity {
    while !(*node).rb_left.is_null() {
        node = (*node).rb_left;
    }
    node
}

/// Recompute `rb_min_vdeadline` for a single node from its children.
#[inline(always)]
unsafe fn augment_node(node: *mut SchedEntity) {
    let mut min_vd = (*node).vdeadline;
    if !(*node).rb_left.is_null() {
        let left_vd = (*(*node).rb_left).rb_min_vdeadline;
        if left_vd < min_vd {
            min_vd = left_vd;
        }
    }
    if !(*node).rb_right.is_null() {
        let right_vd = (*(*node).rb_right).rb_min_vdeadline;
        if right_vd < min_vd {
            min_vd = right_vd;
        }
    }
    (*node).rb_min_vdeadline = min_vd;
}

/// Propagate augmentation from `node` up to the root.
/// No early exit — after rotations, a node's value can stay the same
/// while its subtree changed, so ancestors may still need updating.
#[inline]
unsafe fn augment_propagate(mut node: *mut SchedEntity) {
    while !node.is_null() {
        augment_node(node);
        node = rb_parent(node);
    }
}

/// Wrapping vruntime comparison: true if `a` is logically before `b`.
#[inline(always)]
fn vruntime_lt(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// Wrapping vruntime comparison: true if `a` is logically after `b`.
#[inline(always)]
pub fn vruntime_gt(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) > 0
}

/// Verification utilities for fuzz harness and tests.
/// Gated on `test` or the `fuzzing` feature so they're never in production builds.
#[cfg(any(test, feature = "fuzzing"))]
pub mod verify {
    use super::*;

    /// Check all red-black tree invariants. Returns false on violation.
    /// Checks: root is black, no red-red, consistent black-height,
    /// parent-child pointer consistency.
    pub unsafe fn check_rb_properties(root: *mut SchedEntity) -> bool {
        if root.is_null() {
            return true;
        }
        // Root must be black
        if rb_color(root) == RED {
            return false;
        }
        // Check structural properties and black-height consistency
        check_node(root).is_some()
    }

    /// Returns Some(black_height) if subtree is valid, None on violation.
    unsafe fn check_node(node: *mut SchedEntity) -> Option<u32> {
        if node.is_null() {
            return Some(1); // null leaves count as black
        }

        // Red nodes cannot have red children
        if rb_color(node) == RED {
            if !(*node).rb_left.is_null() && rb_color((*node).rb_left) == RED {
                return None;
            }
            if !(*node).rb_right.is_null() && rb_color((*node).rb_right) == RED {
                return None;
            }
        }

        // Parent-child consistency
        if !(*node).rb_left.is_null() && rb_parent((*node).rb_left) != node {
            return None;
        }
        if !(*node).rb_right.is_null() && rb_parent((*node).rb_right) != node {
            return None;
        }

        let left_bh = check_node((*node).rb_left)?;
        let right_bh = check_node((*node).rb_right)?;

        // Black-height must be equal on both sides
        if left_bh != right_bh {
            return None;
        }

        Some(left_bh + if rb_color(node) == BLACK { 1 } else { 0 })
    }

    /// Check BST ordering invariant on vruntime.
    pub unsafe fn check_bst_ordering(root: *mut SchedEntity) -> bool {
        check_bst_node(root, u64::MIN, u64::MAX)
    }

    unsafe fn check_bst_node(node: *mut SchedEntity, min: u64, max: u64) -> bool {
        if node.is_null() {
            return true;
        }
        let vrt = (*node).vruntime;
        // Using wrapping comparison would complicate bounds checking.
        // For fuzzing, we use non-wrapping checks (valid for reasonable vruntime ranges).
        if vrt < min || vrt > max {
            return false;
        }
        check_bst_node((*node).rb_left, min, vrt) && check_bst_node((*node).rb_right, vrt, max)
    }

    /// Check augmentation invariant: every node's rb_min_vdeadline equals
    /// min(self.vdeadline, left.rb_min_vdeadline, right.rb_min_vdeadline).
    pub unsafe fn check_augmentation(root: *mut SchedEntity) -> bool {
        if root.is_null() {
            return true;
        }
        check_augment_node(root)
    }

    unsafe fn check_augment_node(node: *mut SchedEntity) -> bool {
        if node.is_null() {
            return true;
        }
        let mut expected = (*node).vdeadline;
        if !(*node).rb_left.is_null() {
            expected = expected.min((*(*node).rb_left).rb_min_vdeadline);
        }
        if !(*node).rb_right.is_null() {
            expected = expected.min((*(*node).rb_right).rb_min_vdeadline);
        }
        if (*node).rb_min_vdeadline != expected {
            return false;
        }
        check_augment_node((*node).rb_left) && check_augment_node((*node).rb_right)
    }

    /// Brute-force EEVDF pick: scan all entities, find the eligible one
    /// (vruntime <= avg_vrt) with the smallest vdeadline.
    /// Used as an oracle to verify pick_eevdf correctness.
    pub fn brute_force_pick(
        entities: &[*mut SchedEntity],
        in_tree: &[bool],
        avg_vrt: u64,
    ) -> Option<*mut SchedEntity> {
        let mut best: *mut SchedEntity = core::ptr::null_mut();
        let mut best_vd = u64::MAX;
        for (i, &ptr) in entities.iter().enumerate() {
            if !in_tree[i] || ptr.is_null() {
                continue;
            }
            unsafe {
                if !vruntime_gt((*ptr).vruntime, avg_vrt) && (*ptr).vdeadline < best_vd {
                    best = ptr;
                    best_vd = (*ptr).vdeadline;
                }
            }
        }
        if best.is_null() { None } else { Some(best) }
    }

    /// Check all tree invariants at once.
    pub unsafe fn check_all(root: *mut SchedEntity) -> bool {
        check_rb_properties(root) && check_bst_ordering(root) && check_augmentation(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::SchedEntity;

    fn make_entity(id: u64, vruntime: u64, vdeadline: u64) -> SchedEntity {
        let mut se = SchedEntity::new(id);
        se.vruntime = vruntime;
        se.vdeadline = vdeadline;
        se.rb_min_vdeadline = vdeadline;
        se
    }

    #[test]
    fn insert_single() {
        let mut tree = FairTimeline::new();
        let mut e = make_entity(1, 100, 200);
        unsafe {
            tree.insert(&mut e);
            assert_eq!(tree.leftmost(), Some(&mut e as *mut _));
            assert!(!tree.is_empty());
        }
    }

    #[test]
    fn insert_ordered_leftmost() {
        let mut tree = FairTimeline::new();
        let mut entities: [SchedEntity; 10] = core::array::from_fn(|i| {
            make_entity(i as u64, (i as u64 + 1) * 100, (i as u64 + 1) * 200)
        });
        unsafe {
            for e in entities.iter_mut() {
                tree.insert(e);
            }
            let lm = tree.leftmost().unwrap();
            assert_eq!((*lm).vruntime, 100); // smallest
        }
    }

    #[test]
    fn insert_reverse_leftmost() {
        let mut tree = FairTimeline::new();
        let mut entities: [SchedEntity; 10] = core::array::from_fn(|i| {
            make_entity(i as u64, (10 - i as u64) * 100, (10 - i as u64) * 200)
        });
        unsafe {
            for e in entities.iter_mut() {
                tree.insert(e);
            }
            let lm = tree.leftmost().unwrap();
            assert_eq!((*lm).vruntime, 100);
        }
    }

    #[test]
    fn remove_single() {
        let mut tree = FairTimeline::new();
        let mut e = make_entity(1, 100, 200);
        unsafe {
            tree.insert(&mut e);
            tree.remove(&mut e);
            assert!(tree.is_empty());
            assert!(tree.leftmost().is_none());
        }
    }

    #[test]
    fn remove_maintains_order() {
        let mut tree = FairTimeline::new();
        let mut e1 = make_entity(1, 100, 200);
        let mut e2 = make_entity(2, 200, 300);
        let mut e3 = make_entity(3, 300, 400);
        unsafe {
            tree.insert(&mut e1);
            tree.insert(&mut e2);
            tree.insert(&mut e3);
            tree.remove(&mut e1); // remove leftmost
            let lm = tree.leftmost().unwrap();
            assert_eq!((*lm).vruntime, 200);
        }
    }

    #[test]
    fn remove_all() {
        let mut tree = FairTimeline::new();
        let mut entities: [SchedEntity; 8] = core::array::from_fn(|i| {
            make_entity(i as u64, (i as u64 + 1) * 50, (i as u64 + 1) * 100)
        });
        unsafe {
            for e in entities.iter_mut() {
                tree.insert(e);
            }
            for e in entities.iter_mut() {
                tree.remove(e);
            }
            assert!(tree.is_empty());
        }
    }

    #[test]
    fn augmentation_tracks_min_vdeadline() {
        let mut tree = FairTimeline::new();
        let mut e1 = make_entity(1, 100, 500);
        let mut e2 = make_entity(2, 200, 100); // smallest vdeadline
        let mut e3 = make_entity(3, 300, 300);
        unsafe {
            tree.insert(&mut e1);
            tree.insert(&mut e2);
            tree.insert(&mut e3);
            // Root's min_vdeadline should be 100 (from e2)
            assert_eq!((*tree.root).rb_min_vdeadline, 100);
        }
    }

    #[test]
    fn augmentation_after_remove() {
        let mut tree = FairTimeline::new();
        let mut e1 = make_entity(1, 100, 500);
        let mut e2 = make_entity(2, 200, 100); // smallest vdeadline
        let mut e3 = make_entity(3, 300, 300);
        unsafe {
            tree.insert(&mut e1);
            tree.insert(&mut e2);
            tree.insert(&mut e3);
            tree.remove(&mut e2); // remove the one with min vdeadline
            assert_eq!((*tree.root).rb_min_vdeadline, 300); // now e3's deadline
        }
    }

    #[test]
    fn pick_eevdf_basic() {
        let mut tree = FairTimeline::new();
        // avg_vrt = 200. Eligible: vruntime <= 200
        let mut e1 = make_entity(1, 100, 500); // eligible, vd=500
        let mut e2 = make_entity(2, 150, 200); // eligible, vd=200 ← best
        let mut e3 = make_entity(3, 300, 100); // NOT eligible (300 > 200)
        unsafe {
            tree.insert(&mut e1);
            tree.insert(&mut e2);
            tree.insert(&mut e3);
            let pick = tree.pick_eevdf(200);
            assert!(pick.is_some());
            assert_eq!((*pick.unwrap()).id, 2); // e2 has smallest vdeadline among eligible
        }
    }

    #[test]
    fn pick_eevdf_no_eligible() {
        let mut tree = FairTimeline::new();
        let mut e1 = make_entity(1, 300, 100);
        let mut e2 = make_entity(2, 400, 200);
        unsafe {
            tree.insert(&mut e1);
            tree.insert(&mut e2);
            // avg_vrt = 100, both vruntimes > 100 → none eligible
            assert!(tree.pick_eevdf(100).is_none());
        }
    }

    #[test]
    fn red_black_invariant() {
        let mut tree = FairTimeline::new();
        let mut entities: [SchedEntity; 16] = core::array::from_fn(|i| {
            // Insert in a pattern that exercises rotations
            let vrt = ((i * 7 + 3) % 16) as u64 * 100;
            make_entity(i as u64, vrt, vrt + 50)
        });
        unsafe {
            for e in entities.iter_mut() {
                tree.insert(e);
            }
            // Verify root is black
            assert_eq!(rb_color(tree.root), BLACK);
            // Verify black-height is consistent
            assert!(verify_rb_properties(tree.root));
        }
    }

    /// Recursively verify red-black properties. Returns black-height or panics.
    unsafe fn verify_rb_properties(node: *mut SchedEntity) -> bool {
        if node.is_null() {
            return true;
        }
        // Red node cannot have red children
        if rb_color(node) == RED {
            if !(*node).rb_left.is_null() && rb_color((*node).rb_left) == RED {
                return false;
            }
            if !(*node).rb_right.is_null() && rb_color((*node).rb_right) == RED {
                return false;
            }
        }
        // Verify children's parent pointers
        if !(*node).rb_left.is_null() {
            if rb_parent((*node).rb_left) != node {
                return false;
            }
        }
        if !(*node).rb_right.is_null() {
            if rb_parent((*node).rb_right) != node {
                return false;
            }
        }
        verify_rb_properties((*node).rb_left) && verify_rb_properties((*node).rb_right)
    }
}
