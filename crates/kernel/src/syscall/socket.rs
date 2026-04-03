//! Socket syscalls — wraps smoltcp via rux-net.
//!
//! Supports AF_INET: SOCK_STREAM (TCP), SOCK_DGRAM (UDP), SOCK_RAW (ICMP stub).

const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;

const MAX_SOCKETS: usize = 16;

#[derive(Clone, Copy)]
struct SocketSlot {
    active: bool,
    sock_type: u32,
    bound_port: u16,
    /// smoltcp SocketHandle raw index. -1 = no handle.
    smol_handle_raw: i16,
    /// Connected destination (for UDP connect + send)
    connected_ip: [u8; 4],
    connected_port: u16,
    connected: bool,
}

impl SocketSlot {
    const fn empty() -> Self {
        Self {
            active: false, sock_type: 0, bound_port: 0,
            smol_handle_raw: -1,
            connected_ip: [0; 4], connected_port: 0, connected: false,
        }
    }
}

static mut SOCKETS: [SocketSlot; MAX_SOCKETS] = [SocketSlot::empty(); MAX_SOCKETS];

/// Convert raw handle index to smoltcp SocketHandle.
/// rux-net provides handle_from_raw() for this conversion.
#[cfg(feature = "net")]
fn to_handle(raw: i16) -> rux_net::RawSocketHandle {
    rux_net::handle_from_raw(raw as usize)
}

/// socket(domain, type, protocol) → fd
pub fn sys_socket(domain: usize, stype: usize, _protocol: usize) -> isize {
    if domain as u32 != AF_INET { return crate::errno::EAFNOSUPPORT; }
    let st = stype as u32 & 0xFF;
    let sock_nonblock = stype & 0x800 != 0;
    if st != SOCK_STREAM && st != SOCK_DGRAM && st != SOCK_RAW { return crate::errno::EPROTONOSUPPORT; }

    unsafe {
        let sock_idx = match (0..MAX_SOCKETS).find(|&i| !SOCKETS[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };

        let fd_table = &mut *rux_fs::fdtable::FD_TABLE;
        let fd = match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
            .find(|&f| !fd_table[f].active)
        {
            Some(f) => f,
            None => return crate::errno::ENOMEM,
        };

        // Allocate smoltcp socket
        #[cfg(feature = "net")]
        let handle_raw = {
            let h = if st == SOCK_STREAM {
                rux_net::tcp_alloc()
            } else if st == SOCK_DGRAM {
                rux_net::udp_alloc()
            } else {
                None // RAW — no smoltcp socket
            };
            match h {
                Some(handle) => rux_net::handle_to_raw(handle) as i16,
                None if st == SOCK_RAW => -1,
                None => return crate::errno::ENOMEM,
            }
        };
        #[cfg(not(feature = "net"))]
        let handle_raw: i16 = -1;

        SOCKETS[sock_idx] = SocketSlot::empty();
        SOCKETS[sock_idx].active = true;
        SOCKETS[sock_idx].sock_type = st;
        SOCKETS[sock_idx].smol_handle_raw = handle_raw;

        fd_table[fd] = rux_fs::fdtable::EMPTY_FD;
        fd_table[fd].active = true;
        fd_table[fd].is_socket = true;
        fd_table[fd].socket_idx = sock_idx as u8;
        if sock_nonblock { fd_table[fd].flags |= 0x800; }

        fd as isize
    }
}

unsafe fn resolve_socket(fd: usize) -> Option<usize> {
    if fd >= rux_fs::fdtable::MAX_FDS { return None; }
    let entry = &(*rux_fs::fdtable::FD_TABLE)[fd];
    if entry.active && entry.is_socket {
        let idx = entry.socket_idx as usize;
        if idx < MAX_SOCKETS && SOCKETS[idx].active { return Some(idx); }
    }
    None
}

/// bind(fd, addr, addrlen)
pub fn sys_bind(fd: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    if addr_ptr == 0 { return crate::errno::EFAULT; }
    unsafe {
        let port = u16::from_be_bytes([
            crate::uaccess::get_user::<u8>(addr_ptr + 2),
            crate::uaccess::get_user::<u8>(addr_ptr + 3),
        ]);
        SOCKETS[idx].bound_port = port;

        // Bind UDP socket in smoltcp
        #[cfg(feature = "net")]
        if SOCKETS[idx].sock_type == SOCK_DGRAM && SOCKETS[idx].smol_handle_raw >= 0 {
            let _ = rux_net::udp_bind(to_handle(SOCKETS[idx].smol_handle_raw), port);
        }
    }
    0
}

/// connect(fd, addr, addrlen)
pub fn sys_connect(fd: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        let dst_port = u16::from_be_bytes([
            crate::uaccess::get_user::<u8>(addr_ptr + 2),
            crate::uaccess::get_user::<u8>(addr_ptr + 3),
        ]);
        let dst_ip: [u8; 4] = [
            crate::uaccess::get_user::<u8>(addr_ptr + 4),
            crate::uaccess::get_user::<u8>(addr_ptr + 5),
            crate::uaccess::get_user::<u8>(addr_ptr + 6),
            crate::uaccess::get_user::<u8>(addr_ptr + 7),
        ];

        let sock = &mut SOCKETS[idx];
        sock.connected_ip = dst_ip;
        sock.connected_port = dst_port;
        sock.connected = true;

        if sock.sock_type != SOCK_STREAM { return 0; } // UDP connect = just store addr
        if addr_ptr == 0 { return crate::errno::EFAULT; }

        #[cfg(feature = "net")]
        {
            let handle = to_handle(sock.smol_handle_raw);
            let src_port = rux_net::alloc_port();

            // Poll to ensure smoltcp state is current before connect
            use rux_arch::TimerOps;
            rux_net::poll(crate::arch::Arch::ticks());

            if rux_net::tcp_connect(handle, dst_ip, dst_port, src_port).is_err() {
                return crate::errno::ENETUNREACH;
            }

            // Non-blocking: return EINPROGRESS
            let nonblock = fd < 64 && ((*rux_fs::fdtable::FD_TABLE)[fd].flags & 0x800) != 0;
            if nonblock { return crate::errno::EINPROGRESS; }

            // Blocking: poll until established
            for _ in 0..30_000u32 {
                rux_net::poll(crate::arch::Arch::ticks());
                if rux_net::tcp_can_send(handle) { return 0; }
                if !rux_net::tcp_is_active(handle) { return crate::errno::ECONNREFUSED; }
                use rux_arch::HaltOps;
                crate::arch::Arch::halt_until_interrupt();
            }
            return crate::errno::ETIMEDOUT;
        }
        #[cfg(not(feature = "net"))]
        return crate::errno::ENETUNREACH;
    }
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen)
pub fn sys_sendto(fd: usize, buf_ptr: usize, len: usize, _flags: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        let (dst_ip, dst_port) = if addr_ptr != 0 {
            let p = u16::from_be_bytes([
                crate::uaccess::get_user::<u8>(addr_ptr + 2),
                crate::uaccess::get_user::<u8>(addr_ptr + 3),
            ]);
            let ip: [u8; 4] = [
                crate::uaccess::get_user::<u8>(addr_ptr + 4),
                crate::uaccess::get_user::<u8>(addr_ptr + 5),
                crate::uaccess::get_user::<u8>(addr_ptr + 6),
                crate::uaccess::get_user::<u8>(addr_ptr + 7),
            ];
            (ip, p)
        } else if SOCKETS[idx].connected {
            (SOCKETS[idx].connected_ip, SOCKETS[idx].connected_port)
        } else {
            ([0u8; 4], 0u16)
        };

        let send_len = len.min(1400);
        let mut kbuf = [0u8; 1400];
        core::ptr::copy_nonoverlapping(buf_ptr as *const u8, kbuf.as_mut_ptr(), send_len);

        #[cfg(feature = "net")]
        {
            use rux_arch::TimerOps;
            let sock = &SOCKETS[idx];
            let handle = to_handle(sock.smol_handle_raw);

            if sock.sock_type == SOCK_STREAM {
                match rux_net::tcp_send(handle, &kbuf[..send_len]) {
                    Ok(n) => {
                        // Drive egress
                        rux_net::poll(crate::arch::Arch::ticks());
                        return n as isize;
                    }
                    Err(_) => return crate::errno::EIO,
                }
            } else if sock.sock_type == SOCK_DGRAM {
                if SOCKETS[idx].bound_port == 0 {
                    let port = rux_net::alloc_port();
                    SOCKETS[idx].bound_port = port;
                    let _ = rux_net::udp_bind(handle, port);
                }
                match rux_net::udp_send(handle, dst_ip, dst_port, &kbuf[..send_len]) {
                    Ok(()) => {
                        rux_net::poll(crate::arch::Arch::ticks());
                        return send_len as isize;
                    }
                    Err(_) => return crate::errno::EIO,
                }
            }
        }
        send_len as isize
    }
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen)
pub fn sys_recvfrom(fd: usize, buf_ptr: usize, len: usize, _flags: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        let nonblock = fd < 64 && ((*rux_fs::fdtable::FD_TABLE)[fd].flags & 0x800) != 0;

        #[cfg(feature = "net")]
        {
            use rux_arch::TimerOps;
            let sock = &SOCKETS[idx];
            let handle = to_handle(sock.smol_handle_raw);

            if sock.sock_type == SOCK_STREAM {
                let max_iters = if nonblock { 10u32 } else { 30_000u32 };
                for _ in 0..max_iters {
                    rux_net::poll(crate::arch::Arch::ticks());
                    let mut kbuf = [0u8; 4096];
                    match rux_net::tcp_recv(handle, &mut kbuf[..len.min(4096)]) {
                        Ok(n) if n > 0 => {
                            core::ptr::copy_nonoverlapping(kbuf.as_ptr(), buf_ptr as *mut u8, n);
                            return n as isize;
                        }
                        Ok(_) => return 0, // EOF
                        Err(0) => return 0, // Finished (EOF signal)
                        Err(_) => {
                            // No data yet — check if connection closed
                            if !rux_net::tcp_is_active(handle) && !rux_net::tcp_can_recv(handle) {
                                return 0; // EOF
                            }
                        }
                    }
                    if nonblock { return crate::errno::EAGAIN; }
                    use rux_arch::HaltOps;
                    crate::arch::Arch::halt_until_interrupt();
                }
                return crate::errno::EAGAIN;
            } else if sock.sock_type == SOCK_DGRAM {
                let max_iters = if nonblock { 10u32 } else { 30_000u32 };
                for _ in 0..max_iters {
                    rux_net::poll(crate::arch::Arch::ticks());
                    let mut kbuf = [0u8; 4096];
                    match rux_net::udp_recv(handle, &mut kbuf[..len.min(4096)]) {
                        Ok((n, src_ip, src_port)) => {
                            core::ptr::copy_nonoverlapping(kbuf.as_ptr(), buf_ptr as *mut u8, n);
                            if addr_ptr != 0 {
                                let sa = addr_ptr as *mut u8;
                                *sa.add(0) = AF_INET as u8; *sa.add(1) = 0;
                                let port_be = src_port.to_be_bytes();
                                *sa.add(2) = port_be[0]; *sa.add(3) = port_be[1];
                                *sa.add(4) = src_ip[0]; *sa.add(5) = src_ip[1];
                                *sa.add(6) = src_ip[2]; *sa.add(7) = src_ip[3];
                                if addrlen_ptr != 0 { *(addrlen_ptr as *mut u32) = 16; }
                            }
                            return n as isize;
                        }
                        Err(_) => {}
                    }
                    if nonblock { return crate::errno::EAGAIN; }
                    use rux_arch::HaltOps;
                    crate::arch::Arch::halt_until_interrupt();
                }
                return crate::errno::EAGAIN;
            }
        }
        crate::errno::EAGAIN
    }
}

/// close a socket
pub fn sys_close_socket(fd: usize) -> isize {
    unsafe {
        if fd >= rux_fs::fdtable::MAX_FDS { return crate::errno::EBADF; }
        let entry = &(*rux_fs::fdtable::FD_TABLE)[fd];
        if !entry.active || !entry.is_socket { return crate::errno::EBADF; }
        let sock_idx = entry.socket_idx as usize;

        (*rux_fs::fdtable::FD_TABLE)[fd] = rux_fs::fdtable::EMPTY_FD;

        let still_referenced = (0..rux_fs::fdtable::MAX_FDS).any(|f| {
            let e = &(*rux_fs::fdtable::FD_TABLE)[f];
            e.active && e.is_socket && e.socket_idx as usize == sock_idx
        });
        if !still_referenced && sock_idx < MAX_SOCKETS {
            #[cfg(feature = "net")]
            if SOCKETS[sock_idx].smol_handle_raw >= 0 {
                let handle = to_handle(SOCKETS[sock_idx].smol_handle_raw);
                if SOCKETS[sock_idx].sock_type == SOCK_STREAM {
                    rux_net::tcp_close(handle);
                }
                rux_net::socket_free(handle);
            }
            SOCKETS[sock_idx].active = false;
        }
    }
    0
}

// ── sendmsg / recvmsg / sendmmsg / recvmmsg ─────────────────────────

pub fn sys_sendmsg(fd: usize, msghdr_ptr: usize) -> isize {
    if msghdr_ptr == 0 { return crate::errno::EINVAL; }
    unsafe {
        let msg_name: usize = crate::uaccess::get_user(msghdr_ptr);
        let msg_namelen: u32 = crate::uaccess::get_user(msghdr_ptr + 8);
        let msg_iov: usize = crate::uaccess::get_user(msghdr_ptr + 16);
        let msg_iovlen: usize = crate::uaccess::get_user(msghdr_ptr + 24);
        if msg_iovlen == 0 || msg_iov == 0 { return 0; }
        let iov_base: usize = crate::uaccess::get_user(msg_iov);
        let iov_len: usize = crate::uaccess::get_user(msg_iov + 8);
        sys_sendto(fd, iov_base, iov_len, 0, msg_name, msg_namelen as usize)
    }
}

pub fn sys_recvmsg(fd: usize, msghdr_ptr: usize) -> isize {
    if msghdr_ptr == 0 { return crate::errno::EINVAL; }
    unsafe {
        let msg_name: usize = crate::uaccess::get_user(msghdr_ptr);
        let msg_iov: usize = crate::uaccess::get_user(msghdr_ptr + 16);
        let msg_iovlen: usize = crate::uaccess::get_user(msghdr_ptr + 24);
        if msg_iovlen == 0 || msg_iov == 0 { return 0; }
        let iov_base: usize = crate::uaccess::get_user(msg_iov);
        let iov_len: usize = crate::uaccess::get_user(msg_iov + 8);
        let mut addrlen: u32 = 16;
        let addrlen_ptr = &mut addrlen as *mut u32 as usize;
        let r = sys_recvfrom(fd, iov_base, iov_len, 0, msg_name, addrlen_ptr);
        if r >= 0 && msg_name != 0 {
            crate::uaccess::put_user(msghdr_ptr + 8, 16u32);
        }
        crate::uaccess::put_user(msghdr_ptr + 40, 0u64);
        crate::uaccess::put_user(msghdr_ptr + 48, 0u32);
        r
    }
}

pub fn sys_sendmmsg(fd: usize, msgvec_ptr: usize, vlen: usize) -> isize {
    let mut sent = 0isize;
    unsafe {
        for i in 0..vlen.min(8) {
            let mhdr = msgvec_ptr + i * 64;
            let r = sys_sendmsg(fd, mhdr);
            if r < 0 { return if sent > 0 { sent } else { r }; }
            *((mhdr + 56) as *mut u32) = r as u32;
            sent += 1;
        }
    }
    sent
}

pub fn sys_recvmmsg(fd: usize, msgvec_ptr: usize, vlen: usize) -> isize {
    let mut recvd = 0isize;
    unsafe {
        for i in 0..vlen.min(8) {
            let mhdr = msgvec_ptr + i * 64;
            let r = sys_recvmsg(fd, mhdr);
            if r < 0 { return if recvd > 0 { recvd } else { r }; }
            *((mhdr + 56) as *mut u32) = r as u32;
            recvd += 1;
            break; // One message at a time for now
        }
    }
    recvd
}

// ── getsockopt / getsockname / getpeername ──────────────────────────

pub fn sys_getsockopt(_fd: usize, _level: usize, optname: usize, optval: usize, optlen: usize) -> isize {
    unsafe {
        let val = match optname {
            4 => 0i32,     // SO_ERROR = success
            7 | 8 => 65536, // SO_SNDBUF / SO_RCVBUF
            _ => 0,
        };
        if optval != 0 { *(optval as *mut i32) = val; }
        if optlen != 0 { *(optlen as *mut u32) = 4; }
    }
    0
}

pub fn sys_getsockname(fd: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    if addr_ptr == 0 { return 0; }
    unsafe {
        let sa = addr_ptr as *mut u8;
        *sa.add(0) = 2; *sa.add(1) = 0;
        let idx = match resolve_socket(fd) { Some(i) => i, None => return crate::errno::EBADF };
        let port = SOCKETS[idx].bound_port.to_be_bytes();
        *sa.add(2) = port[0]; *sa.add(3) = port[1];
        #[cfg(feature = "net")]
        {
            let ip = rux_net::our_ip();
            *sa.add(4) = ip[0]; *sa.add(5) = ip[1]; *sa.add(6) = ip[2]; *sa.add(7) = ip[3];
        }
        #[cfg(not(feature = "net"))]
        { *sa.add(4) = 0; *sa.add(5) = 0; *sa.add(6) = 0; *sa.add(7) = 0; }
        if addrlen_ptr != 0 { *(addrlen_ptr as *mut u32) = 16; }
    }
    0
}

pub fn sys_getpeername(fd: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    if addr_ptr == 0 { return 0; }
    unsafe {
        let idx = match resolve_socket(fd) { Some(i) => i, None => return crate::errno::EBADF };
        let sa = addr_ptr as *mut u8;
        *sa.add(0) = 2; *sa.add(1) = 0;
        let port = SOCKETS[idx].connected_port.to_be_bytes();
        *sa.add(2) = port[0]; *sa.add(3) = port[1];
        *sa.add(4) = SOCKETS[idx].connected_ip[0]; *sa.add(5) = SOCKETS[idx].connected_ip[1];
        *sa.add(6) = SOCKETS[idx].connected_ip[2]; *sa.add(7) = SOCKETS[idx].connected_ip[3];
        if addrlen_ptr != 0 { *(addrlen_ptr as *mut u32) = 16; }
    }
    0
}

// ── Status helpers ─────────────────────────────────────────────────

pub fn socket_can_write(fd: usize) -> bool {
    unsafe {
        let idx = match resolve_socket(fd) { Some(i) => i, None => return false };
        let sock = &SOCKETS[idx];
        if sock.sock_type == SOCK_DGRAM { return true; }
        #[cfg(feature = "net")]
        if sock.smol_handle_raw >= 0 {
            return rux_net::tcp_can_send(to_handle(sock.smol_handle_raw));
        }
        true
    }
}

pub fn socket_has_data(fd: usize) -> bool {
    unsafe {
        let idx = match resolve_socket(fd) { Some(i) => i, None => return false };
        let sock = &SOCKETS[idx];
        #[cfg(feature = "net")]
        if sock.smol_handle_raw >= 0 {
            if sock.sock_type == SOCK_STREAM {
                return rux_net::tcp_can_recv(to_handle(sock.smol_handle_raw));
            } else if sock.sock_type == SOCK_DGRAM {
                return rux_net::udp_can_recv(to_handle(sock.smol_handle_raw));
            }
        }
        false
    }
}

pub fn is_socket(fd: usize) -> bool {
    unsafe {
        if fd >= rux_fs::fdtable::MAX_FDS { return false; }
        let entry = &(*rux_fs::fdtable::FD_TABLE)[fd];
        entry.active && entry.is_socket
    }
}
