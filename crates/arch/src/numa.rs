/// NUMA topology types.
///
/// Describes which physical memory ranges belong to which NUMA node.
/// Populated at boot from ACPI SRAT (x86_64) or DTB (aarch64).

/// Maximum number of NUMA nodes supported.
pub const MAX_NUMA_NODES: usize = 16;

/// A NUMA memory region: physical address range + node ID.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NumaNode {
    /// Physical base address of this memory region.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// NUMA proximity domain / node ID.
    pub node_id: u32,
    pub _pad: u32,
}

/// Parsed NUMA topology.
pub struct NumaTopology {
    pub nodes: [NumaNode; MAX_NUMA_NODES],
    pub count: usize,
}

impl NumaTopology {
    pub const fn empty() -> Self {
        Self {
            nodes: [NumaNode { base: 0, size: 0, node_id: 0, _pad: 0 }; MAX_NUMA_NODES],
            count: 0,
        }
    }

    /// Add a node. Returns false if full.
    pub fn add(&mut self, base: u64, size: u64, node_id: u32) -> bool {
        if self.count >= MAX_NUMA_NODES { return false; }
        self.nodes[self.count] = NumaNode { base, size, node_id, _pad: 0 };
        self.count += 1;
        true
    }
}
