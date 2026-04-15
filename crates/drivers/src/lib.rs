#![no_std]

#[cfg(target_arch = "x86_64")]
pub mod pci;
pub mod virtio;

/// Convert a kernel virtual address to a physical address for device DMA.
///
/// Virtio and other DMA-capable devices see **physical** memory, not the
/// kernel's virtual address space. Any time we hand a device a buffer
/// pointer — descriptor ring bases, scatter/gather entries, request
/// headers — we must first translate the Rust pointer (which is a VA)
/// to a PA.
///
/// Today the kernel is linked at low physical VAs (identity-mapped), so
/// VA == PA and this function is a no-op. Once the higher-half refactor
/// lands, kernel statics will live at `0xffffffff80000000+` and this
/// helper will subtract the offset. The `if va >= ...` guard makes the
/// function correct in **both** worlds so the driver audit can land
/// before the kernel link address moves.
#[inline]
pub fn kva_to_phys(va: u64) -> u64 {
    const KERNEL_VMA: u64 = 0xffffffff80000000;
    if va >= KERNEL_VMA { va - KERNEL_VMA } else { va }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceType {
    Block,
    Char,
    Net,
    Platform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DriverError {
    ProbeFailure,
    ResourceBusy,
    Unsupported,
    IoError,
    Timeout,
    InvalidState,
}

pub trait Driver {
    fn name(&self) -> &str;
    fn device_type(&self) -> DeviceType;
    fn probe(&mut self) -> Result<(), DriverError>;
    fn remove(&mut self) -> Result<(), DriverError>;
}

pub trait BlockDevice {
    fn block_size(&self) -> usize;
    fn block_count(&self) -> u64;

    /// # Safety
    /// `buf` must be at least `block_size()` bytes and properly aligned.
    unsafe fn read_block(&self, block: u64, buf: *mut u8) -> Result<(), DriverError>;

    /// # Safety
    /// `buf` must be at least `block_size()` bytes and properly aligned.
    unsafe fn write_block(&mut self, block: u64, buf: *const u8) -> Result<(), DriverError>;
}

pub trait CharDevice {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, DriverError>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, DriverError>;
}

pub trait NetDevice {
    fn mac_address(&self) -> [u8; 6];

    /// # Safety
    /// `buf` must point to a valid ethernet frame of `len` bytes.
    unsafe fn transmit(&mut self, buf: *const u8, len: usize) -> Result<(), DriverError>;

    /// # Safety
    /// `buf` must have capacity for at least `max_len` bytes.
    unsafe fn receive(&mut self, buf: *mut u8, max_len: usize) -> Result<usize, DriverError>;
}
