pub mod cfs;
pub mod constants;
pub mod eevdf;
pub mod rbtree;
pub mod runqueue;
#[cfg(test)]
mod tests;

pub use cfs::CfsClass;
pub use constants::*;
pub use eevdf::EevdfClass;
pub use rbtree::{FairTimeline, vruntime_gt};
pub use runqueue::FairRunQueue;

/// Wall-clock delta to virtual delta. Higher weight = slower vruntime advance.
/// Fast path: weight == NICE_0_WEIGHT (nice 0) returns delta_ns unchanged.
#[inline(always)]
pub fn calc_delta_fair(delta_ns: u64, weight: u32) -> u64 {
    if weight == NICE_0_WEIGHT {
        return delta_ns;
    }
    ((delta_ns as u128 * NICE_0_WEIGHT as u128) / weight as u128) as u64
}

/// Compute ideal time slice for an entity given the runqueue's load.
/// The scheduling period stretches when nr_running exceeds the base
/// latency / granularity ratio, ensuring every task gets at least
/// MIN_GRANULARITY_NS per period.
#[inline(always)]
pub fn calc_slice(weight: u32, nr_running: u32, total_weight: u64) -> u64 {
    if total_weight == 0 {
        return BASE_SLICE_NS;
    }
    let period = core::cmp::max(
        SCHED_LATENCY_NS,
        nr_running as u64 * MIN_GRANULARITY_NS,
    );
    let slice = (period as u128 * weight as u128 / total_weight as u128) as u64;
    slice.clamp(MIN_SLICE_NS, MAX_SLICE_NS)
}
