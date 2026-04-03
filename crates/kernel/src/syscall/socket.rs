//! Socket syscalls — minimal implementation for ICMP ping and UDP.
//!
//! Supports AF_INET + SOCK_DGRAM (UDP) and SOCK_RAW (ICMP).
//! No TCP yet. Sockets use a simple static table, not file descriptors.

use crate::uaccess;

const AF_INET: u32 = 2;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const IPPROTO_ICMP: u32 = 1;
const IPPROTO_UDP: u32 = 17;

const MAX_SOCKETS: usize = 8;

#[derive(Clone, Copy)]
struct SocketSlot {
    active: bool,
    family: u32,
    sock_type: u32,
    protocol: u32,
    bound_port: u16,
    // Receive buffer (one packet)
    rx_buf: [u8; 1500],
    rx_len: usize,
    rx_from_ip: [u8; 4],
    rx_from_port: u16,
    rx_ready: bool,
}

impl SocketSlot {
    const fn empty() -> Self {
        Self {
            active: false, family: 0, sock_type: 0, protocol: 0,
            bound_port: 0,
            rx_buf: [0; 1500], rx_len: 0,
            rx_from_ip: [0; 4], rx_from_port: 0,
            rx_ready: false,
        }
    }
}

static mut SOCKETS: [SocketSlot; MAX_SOCKETS] = [SocketSlot::empty(); MAX_SOCKETS];

/// socket(domain, type, protocol) → fd
pub fn sys_socket(domain: usize, stype: usize, protocol: usize) -> isize {
    if domain as u32 != AF_INET { return crate::errno::EAFNOSUPPORT; }
    let st = stype as u32 & 0xFF; // mask out SOCK_NONBLOCK etc.
    if st != SOCK_DGRAM && st != SOCK_RAW { return crate::errno::EPROTONOSUPPORT; }

    unsafe {
        for i in 0..MAX_SOCKETS {
            if !SOCKETS[i].active {
                SOCKETS[i] = SocketSlot::empty();
                SOCKETS[i].active = true;
                SOCKETS[i].family = domain as u32;
                SOCKETS[i].sock_type = st;
                SOCKETS[i].protocol = protocol as u32;
                // Return socket "fd" as 100 + index (above normal FD range)
                return (100 + i) as isize;
            }
        }
    }
    crate::errno::ENOMEM
}

/// bind(fd, addr, addrlen) — bind to a local port
pub fn sys_bind(fd: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = fd.wrapping_sub(100);
    if idx >= MAX_SOCKETS { return crate::errno::EBADF; }
    unsafe {
        if !SOCKETS[idx].active { return crate::errno::EBADF; }
        // Parse sockaddr_in: family(2) + port(2) + ip(4) + pad(8)
        let port = u16::from_be_bytes([
            *(addr_ptr as *const u8).add(2),
            *(addr_ptr as *const u8).add(3),
        ]);
        SOCKETS[idx].bound_port = port;
    }
    0
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen) — send a packet
#[cfg(target_arch = "aarch64")]
pub fn sys_sendto(fd: usize, buf_ptr: usize, len: usize, _flags: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = fd.wrapping_sub(100);
    if idx >= MAX_SOCKETS { return crate::errno::EBADF; }
    unsafe {
        if !SOCKETS[idx].active { return crate::errno::EBADF; }

        // Parse destination sockaddr_in
        let dst_port = u16::from_be_bytes([
            *(addr_ptr as *const u8).add(2),
            *(addr_ptr as *const u8).add(3),
        ]);
        let dst_ip: [u8; 4] = [
            *(addr_ptr as *const u8).add(4),
            *(addr_ptr as *const u8).add(5),
            *(addr_ptr as *const u8).add(6),
            *(addr_ptr as *const u8).add(7),
        ];

        // Copy user buffer to kernel
        let send_len = len.min(1400);
        let mut kbuf = [0u8; 1400];
        core::ptr::copy_nonoverlapping(buf_ptr as *const u8, kbuf.as_mut_ptr(), send_len);

        let sock = &SOCKETS[idx];
        if sock.sock_type == SOCK_RAW && sock.protocol == IPPROTO_ICMP {
            // Raw ICMP: kbuf is the ICMP payload, wrap in IP
            rux_net::stack::send_ip(dst_ip, rux_net::ipv4::PROTO_ICMP, &kbuf[..send_len]);
        } else if sock.sock_type == SOCK_DGRAM {
            // UDP
            let mut udp_buf = [0u8; 1408];
            let src_port = if sock.bound_port != 0 { sock.bound_port } else { 49152 + (idx as u16) };
            let udp_len = rux_net::udp::build(&mut udp_buf, src_port, dst_port, &kbuf[..send_len]);
            rux_net::stack::send_ip(dst_ip, rux_net::ipv4::PROTO_UDP, &udp_buf[..udp_len]);
        }

        send_len as isize
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub fn sys_sendto(_fd: usize, _buf_ptr: usize, _len: usize, _flags: usize, _addr_ptr: usize, _addrlen: usize) -> isize {
    crate::errno::ENETUNREACH
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) — receive a packet
pub fn sys_recvfrom(fd: usize, buf_ptr: usize, len: usize, _flags: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    let idx = fd.wrapping_sub(100);
    if idx >= MAX_SOCKETS { return crate::errno::EBADF; }
    unsafe {
        if !SOCKETS[idx].active { return crate::errno::EBADF; }

        // Poll until a packet arrives (with timeout)
        for _ in 0..10_000_000u32 {
            #[cfg(target_arch = "aarch64")]
            rux_net::stack::poll();

            if SOCKETS[idx].rx_ready {
                let copy_len = len.min(SOCKETS[idx].rx_len);
                core::ptr::copy_nonoverlapping(
                    SOCKETS[idx].rx_buf.as_ptr(),
                    buf_ptr as *mut u8,
                    copy_len,
                );

                // Fill in source address if requested
                if addr_ptr != 0 {
                    let sa = addr_ptr as *mut u8;
                    *sa.add(0) = 0; *sa.add(1) = AF_INET as u8; // sin_family
                    let port_be = SOCKETS[idx].rx_from_port.to_be_bytes();
                    *sa.add(2) = port_be[0]; *sa.add(3) = port_be[1];
                    *sa.add(4) = SOCKETS[idx].rx_from_ip[0];
                    *sa.add(5) = SOCKETS[idx].rx_from_ip[1];
                    *sa.add(6) = SOCKETS[idx].rx_from_ip[2];
                    *sa.add(7) = SOCKETS[idx].rx_from_ip[3];
                    if addrlen_ptr != 0 {
                        *(addrlen_ptr as *mut u32) = 16;
                    }
                }

                SOCKETS[idx].rx_ready = false;
                return copy_len as isize;
            }
            core::hint::spin_loop();
        }
        crate::errno::EAGAIN
    }
}

/// close a socket
pub fn sys_close_socket(fd: usize) -> isize {
    let idx = fd.wrapping_sub(100);
    if idx >= MAX_SOCKETS { return crate::errno::EBADF; }
    unsafe {
        SOCKETS[idx].active = false;
    }
    0
}

/// Check if an fd is a socket (>= 100)
pub fn is_socket(fd: usize) -> bool {
    fd >= 100 && fd < 100 + MAX_SOCKETS
}

/// Deliver an incoming UDP packet to the matching socket.
#[cfg(target_arch = "aarch64")]
pub unsafe fn deliver_udp(src_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    for sock in SOCKETS.iter_mut() {
        if sock.active && sock.sock_type == SOCK_DGRAM && sock.bound_port == dst_port {
            let n = data.len().min(1500);
            sock.rx_buf[..n].copy_from_slice(&data[..n]);
            sock.rx_len = n;
            sock.rx_from_ip = src_ip;
            sock.rx_from_port = src_port;
            sock.rx_ready = true;
            return;
        }
    }
}

/// Deliver an incoming ICMP packet to a raw socket.
#[cfg(target_arch = "aarch64")]
pub unsafe fn deliver_icmp(src_ip: [u8; 4], data: &[u8]) {
    for sock in SOCKETS.iter_mut() {
        if sock.active && sock.sock_type == SOCK_RAW && sock.protocol == IPPROTO_ICMP {
            let n = data.len().min(1500);
            sock.rx_buf[..n].copy_from_slice(&data[..n]);
            sock.rx_len = n;
            sock.rx_from_ip = src_ip;
            sock.rx_from_port = 0;
            sock.rx_ready = true;
            return;
        }
    }
}
