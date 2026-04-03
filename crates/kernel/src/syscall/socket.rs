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
        // Find free socket slot
        let sock_idx = match (0..MAX_SOCKETS).find(|&i| !SOCKETS[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };

        // Allocate from the normal FD table
        let fd_table = &mut *rux_fs::fdtable::FD_TABLE;
        let fd = match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
            .find(|&f| !fd_table[f].active)
        {
            Some(f) => f,
            None => return crate::errno::ENOMEM,
        };

        SOCKETS[sock_idx] = SocketSlot::empty();
        SOCKETS[sock_idx].active = true;
        SOCKETS[sock_idx].family = domain as u32;
        SOCKETS[sock_idx].sock_type = st;
        SOCKETS[sock_idx].protocol = protocol as u32;

        fd_table[fd] = rux_fs::fdtable::EMPTY_FD;
        fd_table[fd].active = true;
        fd_table[fd].is_socket = true;
        fd_table[fd].socket_idx = sock_idx as u8;

        fd as isize
    }
}

/// Resolve a socket FD to a socket index.
unsafe fn resolve_socket(fd: usize) -> Option<usize> {
    if fd >= rux_fs::fdtable::MAX_FDS { return None; }
    let entry = &(*rux_fs::fdtable::FD_TABLE)[fd];
    if entry.active && entry.is_socket {
        let idx = entry.socket_idx as usize;
        if idx < MAX_SOCKETS && SOCKETS[idx].active { return Some(idx); }
    }
    None
}

/// bind(fd, addr, addrlen) — bind to a local port
pub fn sys_bind(fd: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
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

pub fn sys_sendto(fd: usize, buf_ptr: usize, len: usize, _flags: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {

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

        #[cfg(feature = "net")]
        {
            let sock = &SOCKETS[idx];
            if sock.sock_type == SOCK_RAW && sock.protocol == IPPROTO_ICMP {
                rux_net::stack::send_ip(dst_ip, rux_net::ipv4::PROTO_ICMP, &kbuf[..send_len]);
            } else if sock.sock_type == SOCK_DGRAM {
                let mut udp_buf = [0u8; 1408];
                let src_port = if sock.bound_port != 0 { sock.bound_port } else { 49152 + (idx as u16) };
                let udp_len = rux_net::udp::build(&mut udp_buf, src_port, dst_port, &kbuf[..send_len]);
                rux_net::stack::send_ip(dst_ip, rux_net::ipv4::PROTO_UDP, &udp_buf[..udp_len]);
            }
        }
        #[cfg(not(feature = "net"))]
        { let _ = (dst_ip, dst_port, &kbuf); return crate::errno::ENETUNREACH; }

        send_len as isize
    }
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) — receive a packet
pub fn sys_recvfrom(fd: usize, buf_ptr: usize, len: usize, _flags: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {

        // Poll until a packet arrives (with timeout)
        for _ in 0..10_000_000u32 {
            
            #[cfg(feature = "net")]
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

/// close a socket FD — only deactivates the FD entry.
/// The socket slot stays active until no FDs reference it.
pub fn sys_close_socket(fd: usize) -> isize {
    unsafe {
        if fd >= rux_fs::fdtable::MAX_FDS { return crate::errno::EBADF; }
        let entry = &(*rux_fs::fdtable::FD_TABLE)[fd];
        if !entry.active || !entry.is_socket { return crate::errno::EBADF; }
        let sock_idx = entry.socket_idx as usize;

        (*rux_fs::fdtable::FD_TABLE)[fd] = rux_fs::fdtable::EMPTY_FD;

        // Check if any other FD still references this socket
        let still_referenced = (0..rux_fs::fdtable::MAX_FDS).any(|f| {
            let e = &(*rux_fs::fdtable::FD_TABLE)[f];
            e.active && e.is_socket && e.socket_idx as usize == sock_idx
        });
        if !still_referenced && sock_idx < MAX_SOCKETS {
            SOCKETS[sock_idx].active = false;
        }
    }
    0
}

/// Check if an fd is a socket
pub fn is_socket(fd: usize) -> bool {
    unsafe {
        if fd >= rux_fs::fdtable::MAX_FDS { return false; }
        let entry = &(*rux_fs::fdtable::FD_TABLE)[fd];
        entry.active && entry.is_socket
    }
}

/// Deliver an incoming UDP packet to the matching socket.

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
