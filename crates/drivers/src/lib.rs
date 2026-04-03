#![no_std]

pub mod virtio;

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
