//! rux network stack — thin wrapper over smoltcp.
//!
//! Provides a static, no-alloc TCP/IP stack using smoltcp with virtio backends.
//! All state is in statics — no heap allocation required.

#![no_std]

mod device;

use device::{VirtioDevice, SendFn, RecvFn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use core::net::Ipv4Addr;

/// Re-export SocketHandle as an opaque type for the kernel.
pub type RawSocketHandle = SocketHandle;

/// Convert a raw usize to a SocketHandle.
pub fn handle_from_raw(raw: usize) -> SocketHandle {
    unsafe { core::mem::transmute(raw) }
}

/// Convert a SocketHandle to a raw usize.
pub fn handle_to_raw(h: SocketHandle) -> usize {
    unsafe { core::mem::transmute(h) }
}

// ── Configuration ──────────────────────────────────────────────────

const MAX_TCP_SOCKETS: usize = 8;
const MAX_UDP_SOCKETS: usize = 4;
const MAX_SOCKETS: usize = MAX_TCP_SOCKETS + MAX_UDP_SOCKETS;

const TCP_RX_BUF_SIZE: usize = 65536;
const TCP_TX_BUF_SIZE: usize = 16384;
const UDP_RX_META_SIZE: usize = 8;  // max queued packets
const UDP_TX_META_SIZE: usize = 8;
const UDP_RX_BUF_SIZE: usize = 4096;
const UDP_TX_BUF_SIZE: usize = 4096;

// ── Static storage (no alloc) ──────────────────────────────────────

static mut DEVICE: VirtioDevice = VirtioDevice::empty();
static CONFIGURED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static mut OUR_IP: [u8; 4] = [0; 4];

// Socket storage for smoltcp
static mut SOCKET_STORAGE: [SocketStorage<'static>; MAX_SOCKETS] = [SocketStorage::EMPTY; MAX_SOCKETS];

// TCP buffers: 8 sockets × (64KB RX + 16KB TX) = ~640KB
static mut TCP_RX_BUFS: [[u8; TCP_RX_BUF_SIZE]; MAX_TCP_SOCKETS] = [[0; TCP_RX_BUF_SIZE]; MAX_TCP_SOCKETS];
static mut TCP_TX_BUFS: [[u8; TCP_TX_BUF_SIZE]; MAX_TCP_SOCKETS] = [[0; TCP_TX_BUF_SIZE]; MAX_TCP_SOCKETS];
static mut TCP_BUF_USED: [bool; MAX_TCP_SOCKETS] = [false; MAX_TCP_SOCKETS];

// UDP buffers: 4 sockets
static mut UDP_RX_BUFS: [[u8; UDP_RX_BUF_SIZE]; MAX_UDP_SOCKETS] = [[0; UDP_RX_BUF_SIZE]; MAX_UDP_SOCKETS];
static mut UDP_TX_BUFS: [[u8; UDP_TX_BUF_SIZE]; MAX_UDP_SOCKETS] = [[0; UDP_TX_BUF_SIZE]; MAX_UDP_SOCKETS];
static mut UDP_RX_META: [[udp::PacketMetadata; UDP_RX_META_SIZE]; MAX_UDP_SOCKETS] =
    [[udp::PacketMetadata::EMPTY; UDP_RX_META_SIZE]; MAX_UDP_SOCKETS];
static mut UDP_TX_META: [[udp::PacketMetadata; UDP_TX_META_SIZE]; MAX_UDP_SOCKETS] =
    [[udp::PacketMetadata::EMPTY; UDP_TX_META_SIZE]; MAX_UDP_SOCKETS];
static mut UDP_BUF_USED: [bool; MAX_UDP_SOCKETS] = [false; MAX_UDP_SOCKETS];

// Interface and SocketSet live here — initialized by init()
static mut IFACE: Option<Interface> = None;
static mut SOCKETS: Option<SocketSet<'static>> = None;

// Ephemeral port counter
static mut NEXT_PORT: u16 = 49152;

// ── Public API ─────────────────────────────────────────────────────

/// Initialize the network stack. Called once during boot.
///
/// # Safety
/// Must be called exactly once, before any other network function.
pub unsafe fn init(
    send_fn: SendFn,
    recv_fn: RecvFn,
    mac: [u8; 6],
    ip: [u8; 4],
    gateway: [u8; 4],
    netmask: [u8; 4],
) {
    DEVICE.init(send_fn, recv_fn);
    OUR_IP = ip;

    let hw_addr = HardwareAddress::Ethernet(EthernetAddress(mac));
    let config = Config::new(hw_addr);
    let now = Instant::from_millis(0);

    let mut iface = Interface::new(config, &mut DEVICE, now);

    // Set IP address
    let prefix_len = netmask_to_prefix(netmask);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Addr::from(ip)),
            prefix_len,
        ));
    });

    // Set default gateway
    iface.routes_mut().add_default_ipv4_route(Ipv4Addr::from(gateway)).ok();

    IFACE = Some(iface);
    SOCKETS = Some(SocketSet::new(&mut *(&raw mut SOCKET_STORAGE) as &mut [SocketStorage<'static>]));
    CONFIGURED.store(true, core::sync::atomic::Ordering::Release);
}

/// Poll the network stack. Call from timer ISR and before socket operations.
///
/// # Safety
/// Must not be called concurrently with other network functions.
pub unsafe fn poll(timestamp_millis: u64) {
    if !CONFIGURED.load(core::sync::atomic::Ordering::Acquire) { return; }
    let iface = IFACE.as_mut().unwrap_unchecked();
    let sockets = SOCKETS.as_mut().unwrap_unchecked();
    let now = Instant::from_millis(timestamp_millis as i64);
    let _ = iface.poll(now, &mut DEVICE, sockets);
}

pub fn is_configured() -> bool {
    CONFIGURED.load(core::sync::atomic::Ordering::Acquire)
}

pub fn our_ip() -> [u8; 4] {
    unsafe { OUR_IP }
}

// ── TCP API ────────────────────────────────────────────────────────

/// Allocate a TCP socket. Returns the SocketHandle on success.
pub unsafe fn tcp_alloc() -> Option<SocketHandle> {
    let sockets = SOCKETS.as_mut()?;

    // Find a free TCP buffer slot
    let idx = TCP_BUF_USED.iter().position(|&used| !used)?;
    TCP_BUF_USED[idx] = true;

    // Zero the buffers (use write_bytes to avoid 64KB stack copy)
    core::ptr::write_bytes(TCP_RX_BUFS[idx].as_mut_ptr(), 0, TCP_RX_BUF_SIZE);
    core::ptr::write_bytes(TCP_TX_BUFS[idx].as_mut_ptr(), 0, TCP_TX_BUF_SIZE);

    let rx_slice: &mut [u8] = &mut *(&raw mut TCP_RX_BUFS[idx]);
    let tx_slice: &mut [u8] = &mut *(&raw mut TCP_TX_BUFS[idx]);

    // Verify buffer sizes (diagnostic)
    if rx_slice.len() != TCP_RX_BUF_SIZE || tx_slice.len() != TCP_TX_BUF_SIZE {
        return None; // Buffer creation failed
    }

    let rx_buf = tcp::SocketBuffer::new(rx_slice);
    let tx_buf = tcp::SocketBuffer::new(tx_slice);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None); // Disable delayed ACKs — our tick counter may not advance between polls

    // Verify buffer capacity
    debug_assert!(socket.recv_capacity() == TCP_RX_BUF_SIZE);

    Some(sockets.add(socket))
}

/// Initiate a TCP connection.
pub unsafe fn tcp_connect(
    handle: SocketHandle,
    dst_ip: [u8; 4],
    dst_port: u16,
    src_port: u16,
) -> Result<(), i32> {
    let sockets = SOCKETS.as_mut().ok_or(-1)?;
    let iface = IFACE.as_mut().ok_or(-1)?;
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    let remote = IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::from(dst_ip)), dst_port);
    let local = IpListenEndpoint { addr: None, port: src_port };
    socket.connect(iface.context(), remote, local).map_err(|_| -1)
}

/// Send data on a TCP socket. Returns bytes sent.
pub unsafe fn tcp_send(handle: SocketHandle, data: &[u8]) -> Result<usize, i32> {
    let sockets = SOCKETS.as_mut().ok_or(-1)?;
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    socket.send_slice(data).map_err(|_| -1)
}

/// Put a TCP socket into listen mode on the specified port.
pub unsafe fn tcp_listen(handle: SocketHandle, port: u16) -> Result<(), i32> {
    let sockets = SOCKETS.as_mut().ok_or(-1)?;
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    socket.listen(port).map_err(|_| -1)
}

/// Receive data from a TCP socket. Returns bytes received.
pub unsafe fn tcp_recv(handle: SocketHandle, buf: &mut [u8]) -> Result<usize, i32> {
    let sockets = SOCKETS.as_mut().ok_or(-1)?;
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    socket.recv_slice(buf).map_err(|e| match e {
        tcp::RecvError::Finished => 0, // signal EOF by returning Ok(0) via special value
        tcp::RecvError::InvalidState => -1,
    })
}

/// Close a TCP socket (send FIN).
pub unsafe fn tcp_close(handle: SocketHandle) {
    if let Some(sockets) = SOCKETS.as_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        socket.close();
    }
}

/// Check if TCP socket has data to receive.
pub unsafe fn tcp_can_recv(handle: SocketHandle) -> bool {
    SOCKETS.as_mut()
        .map(|s| {
            let sock = s.get_mut::<tcp::Socket>(handle);
            sock.can_recv() || !sock.may_recv()
        })
        .unwrap_or(false)
}

/// Check if TCP socket can send data.
pub unsafe fn tcp_can_send(handle: SocketHandle) -> bool {
    SOCKETS.as_mut()
        .map(|s| s.get_mut::<tcp::Socket>(handle).can_send())
        .unwrap_or(false)
}

/// Check if TCP socket is active (connected or connecting).
pub unsafe fn tcp_is_active(handle: SocketHandle) -> bool {
    SOCKETS.as_mut()
        .map(|s| s.get_mut::<tcp::Socket>(handle).is_active())
        .unwrap_or(false)
}

/// Get TCP socket state.
pub unsafe fn tcp_state(handle: SocketHandle) -> tcp::State {
    SOCKETS.as_mut()
        .map(|s| s.get_mut::<tcp::Socket>(handle).state())
        .unwrap_or(tcp::State::Closed)
}

// ── UDP API ────────────────────────────────────────────────────────

/// Allocate a UDP socket.
pub unsafe fn udp_alloc() -> Option<SocketHandle> {
    let sockets = SOCKETS.as_mut()?;

    let idx = UDP_BUF_USED.iter().position(|&used| !used)?;
    UDP_BUF_USED[idx] = true;

    UDP_RX_BUFS[idx] = [0; UDP_RX_BUF_SIZE];
    UDP_TX_BUFS[idx] = [0; UDP_TX_BUF_SIZE];
    UDP_RX_META[idx] = [udp::PacketMetadata::EMPTY; UDP_RX_META_SIZE];
    UDP_TX_META[idx] = [udp::PacketMetadata::EMPTY; UDP_TX_META_SIZE];

    let rx_buf = udp::PacketBuffer::new(
        &mut *(&raw mut UDP_RX_META[idx]) as &mut [udp::PacketMetadata],
        &mut *(&raw mut UDP_RX_BUFS[idx]) as &mut [u8],
    );
    let tx_buf = udp::PacketBuffer::new(
        &mut *(&raw mut UDP_TX_META[idx]) as &mut [udp::PacketMetadata],
        &mut *(&raw mut UDP_TX_BUFS[idx]) as &mut [u8],
    );
    let socket = udp::Socket::new(rx_buf, tx_buf);
    Some(sockets.add(socket))
}

/// Bind a UDP socket to a port.
pub unsafe fn udp_bind(handle: SocketHandle, port: u16) -> Result<(), i32> {
    let sockets = SOCKETS.as_mut().ok_or(-1)?;
    let socket = sockets.get_mut::<udp::Socket>(handle);
    socket.bind(IpListenEndpoint { addr: None, port }).map_err(|_| -1)
}

/// Send a UDP packet.
pub unsafe fn udp_send(
    handle: SocketHandle,
    dst_ip: [u8; 4],
    dst_port: u16,
    data: &[u8],
) -> Result<(), i32> {
    let sockets = SOCKETS.as_mut().ok_or(-1)?;
    let socket = sockets.get_mut::<udp::Socket>(handle);
    let dst = IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::from(dst_ip)), dst_port);
    let meta = udp::UdpMetadata::from(dst);
    socket.send_slice(data, meta).map_err(|_| -1)
}

/// Receive a UDP packet. Returns (bytes_read, src_ip, src_port).
pub unsafe fn udp_recv(
    handle: SocketHandle,
    buf: &mut [u8],
) -> Result<(usize, [u8; 4], u16), i32> {
    let sockets = SOCKETS.as_mut().ok_or(-1)?;
    let socket = sockets.get_mut::<udp::Socket>(handle);
    match socket.recv_slice(buf) {
        Ok((len, meta)) => {
            let ip = match meta.endpoint.addr {
                IpAddress::Ipv4(v4) => v4.octets(),
            };
            Ok((len, ip, meta.endpoint.port))
        }
        Err(_) => Err(-1),
    }
}

/// Check if UDP socket has data to receive.
pub unsafe fn udp_can_recv(handle: SocketHandle) -> bool {
    SOCKETS.as_mut()
        .map(|s| s.get_mut::<udp::Socket>(handle).can_recv())
        .unwrap_or(false)
}

// ── Socket management ──────────────────────────────────────────────

/// Free a socket handle, returning its slot to the pool.
pub unsafe fn socket_free(handle: SocketHandle) {
    if let Some(sockets) = SOCKETS.as_mut() {
        sockets.remove(handle);
        // Note: buffer slots are NOT freed here because smoltcp doesn't
        // tell us which buffer slot was used. For a production kernel we'd
        // track this; for now the 8/4 slot limit is adequate.
    }
}

/// Allocate an ephemeral port number.
pub unsafe fn alloc_port() -> u16 {
    NEXT_PORT += 1;
    if NEXT_PORT == 0 { NEXT_PORT = 49152; }
    NEXT_PORT
}

// ── Helpers ────────────────────────────────────────────────────────

fn netmask_to_prefix(mask: [u8; 4]) -> u8 {
    let n = u32::from_be_bytes(mask);
    n.leading_ones() as u8
}
