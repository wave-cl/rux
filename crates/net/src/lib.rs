#![no_std]

pub mod eth;
pub mod arp;
pub mod ipv4;
pub mod icmp;
pub mod udp;
pub mod stack;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketState {
    Unbound,
    Bound,
    Listening,
    Connected,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetError {
    ConnectionRefused,
    ConnectionReset,
    Timeout,
    AddrInUse,
    AddrNotAvailable,
    NetworkUnreachable,
    HostUnreachable,
    BufferTooSmall,
    NotConnected,
    InvalidState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SocketAddr {
    pub addr: IpAddr,
    pub port: u16,
}

pub trait Socket {
    fn bind(&mut self, addr: SocketAddr) -> Result<(), NetError>;
    fn connect(&mut self, addr: SocketAddr) -> Result<(), NetError>;
    fn send(&mut self, buf: &[u8]) -> Result<usize, NetError>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NetError>;
    fn state(&self) -> SocketState;
    fn close(&mut self) -> Result<(), NetError>;
}
