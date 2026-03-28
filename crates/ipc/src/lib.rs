#![no_std]

use rux_klib::VirtAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcMethod {
    Pipe,
    SharedMemory,
    MessageQueue,
    Signal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcError {
    BrokenPipe,
    BufferFull,
    BufferEmpty,
    Timeout,
    InvalidDescriptor,
    PermissionDenied,
}

pub trait Channel {
    type Message;

    fn send(&mut self, msg: &Self::Message) -> Result<(), IpcError>;
    fn recv(&mut self) -> Result<Self::Message, IpcError>;
    fn try_recv(&mut self) -> Result<Self::Message, IpcError>;
}

/// # Safety
/// Implementations must ensure correct memory mapping and access
/// synchronization between processes sharing memory regions.
pub unsafe trait SharedMemory {
    fn attach(&mut self, addr: VirtAddr, size: usize) -> Result<(), IpcError>;
    fn detach(&mut self, addr: VirtAddr) -> Result<(), IpcError>;
}
