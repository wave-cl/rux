//! virtio device drivers (MMIO transport).
//!
//! Implements virtio-blk over MMIO for QEMU's `virt` machine.
//! Uses synchronous polling — no interrupt wiring needed.

pub mod mmio;
pub mod queue;
pub mod blk;

#[cfg(target_arch = "x86_64")]
pub mod pci;
#[cfg(target_arch = "x86_64")]
pub mod blk_pci;
