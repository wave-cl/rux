//! Socket syscalls — wraps smoltcp via rux-net.
//!
//! Supports AF_INET: SOCK_STREAM (TCP), SOCK_DGRAM (UDP), SOCK_RAW (ICMP stub).

const AF_INET: u32 = 2;

/// Sleep until I/O event (network activity) — like poll's WaitingForPoll.
/// Used by blocking socket operations (connect, accept, send, recv).
unsafe fn net_wait() {
    use rux_arch::TimerOps;
    let dl = crate::arch::Arch::ticks() + 30_000;
    crate::wait::block_until(crate::task_table::TaskState::WaitingForPoll, dl);
}
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const SOCK_NONBLOCK: usize = 0x800;
const O_NONBLOCK: u32 = 0x800;
const AF_UNIX: u32 = 1;

const MAX_SOCKETS: usize = 32;

#[derive(Clone, Copy)]
struct SocketSlot {
    active: bool,
    /// Reference count — number of fd references across all processes.
    /// Incremented on fork/dup, decremented on close. Socket freed at 0.
    ref_count: u8,
    sock_type: u32,
    bound_port: u16,
    /// smoltcp SocketHandle raw index. -1 = no handle.
    smol_handle_raw: i16,
    /// Connected destination (for UDP connect + send)
    connected_ip: [u8; 4],
    connected_port: u16,
    connected: bool,
    /// Socket options
    reuse_addr: bool,
    /// Pending error (set on failed operations, cleared by getsockopt SO_ERROR)
    pending_error: i32,
    /// AF_UNIX support
    is_unix: bool,
    unix_path: [u8; 32],
    unix_path_len: u8,
    unix_listening: bool,
    unix_pipe_a: u8,        // pipe for read direction (connected)
    unix_pipe_b: u8,        // pipe for write direction (connected)
    unix_pending: u8,       // pending connections waiting for accept
}

impl SocketSlot {
    const fn empty() -> Self {
        Self {
            active: false, ref_count: 0, sock_type: 0, bound_port: 0,
            smol_handle_raw: -1,
            connected_ip: [0; 4], connected_port: 0, connected: false,
            reuse_addr: false, pending_error: 0,
            is_unix: false, unix_path: [0; 32], unix_path_len: 0,
            unix_listening: false, unix_pipe_a: 0xFF, unix_pipe_b: 0xFF,
            unix_pending: 0,
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

// ── sockaddr_in helpers ────────────────────────────────────────────

/// Read port and IPv4 address from a user-space sockaddr_in.
/// Caller must validate addr_ptr for at least 8 bytes before calling.
#[inline]
unsafe fn read_sockaddr(addr_ptr: usize) -> (u16, [u8; 4]) {
    let port = u16::from_be_bytes([
        crate::uaccess::get_user::<u8>(addr_ptr + 2),
        crate::uaccess::get_user::<u8>(addr_ptr + 3),
    ]);
    let ip: [u8; 4] = [
        crate::uaccess::get_user::<u8>(addr_ptr + 4),
        crate::uaccess::get_user::<u8>(addr_ptr + 5),
        crate::uaccess::get_user::<u8>(addr_ptr + 6),
        crate::uaccess::get_user::<u8>(addr_ptr + 7),
    ];
    (port, ip)
}

/// Write a sockaddr_in (AF_INET, port, ip) to user-space.
/// Caller must validate addr_ptr for at least 16 bytes before calling.
#[inline]
unsafe fn write_sockaddr(addr_ptr: usize, port: u16, ip: [u8; 4]) {
    let sa = addr_ptr as *mut u8;
    *sa.add(0) = 2; *sa.add(1) = 0; // AF_INET
    let pb = port.to_be_bytes();
    *sa.add(2) = pb[0]; *sa.add(3) = pb[1];
    *sa.add(4) = ip[0]; *sa.add(5) = ip[1]; *sa.add(6) = ip[2]; *sa.add(7) = ip[3];
}

/// socket(domain, type, protocol) → fd
pub fn sys_socket(domain: usize, stype: usize, _protocol: usize) -> isize {
    let dom = domain as u32;
    if dom != AF_INET && dom != AF_UNIX { return crate::errno::EAFNOSUPPORT; }
    let st = stype as u32 & 0xFF;
    let sock_nonblock = stype & SOCK_NONBLOCK != 0;
    let sock_cloexec = stype & 0x80000 != 0;
    if st != SOCK_STREAM && st != SOCK_DGRAM && st != SOCK_RAW { return crate::errno::EPROTONOSUPPORT; }

    unsafe {
        // AF_UNIX: return a dummy fd (no SOCKETS[] entry, no smoltcp).
        // Programs that just need socket+connect+close work without state.
        if dom == AF_UNIX {
            let fd_table = &mut *rux_fs::fdtable::fd_table();
            let fd = match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
                .find(|&f| !fd_table[f].active)
            {
                Some(f) => f,
                None => return crate::errno::ENOMEM,
            };
            fd_table[fd] = rux_fs::fdtable::EMPTY_FD;
            fd_table[fd].active = true;
            // NOT marked as is_socket — close() will just deactivate the fd
            if sock_cloexec { fd_table[fd].fd_flags |= rux_fs::fdtable::FD_CLOEXEC; }
            return fd as isize;
        }

        let sock_idx = match (0..MAX_SOCKETS).find(|&i| !SOCKETS[i].active) {
            Some(i) => i,
            None => return crate::errno::ENOMEM,
        };

        let fd_table = &mut *rux_fs::fdtable::fd_table();
        let fd = match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
            .find(|&f| !fd_table[f].active)
        {
            Some(f) => f,
            None => return crate::errno::ENOMEM,
        };

        // Allocate smoltcp socket (AF_INET only at this point)
        #[cfg(feature = "net")]
        let handle_raw: i16 = {
            let h = if st == SOCK_STREAM {
                rux_net::tcp_alloc()
            } else if st == SOCK_DGRAM {
                rux_net::udp_alloc()
            } else {
                None
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
        SOCKETS[sock_idx].ref_count = 1;
        SOCKETS[sock_idx].sock_type = st;
        SOCKETS[sock_idx].smol_handle_raw = handle_raw;

        fd_table[fd] = rux_fs::fdtable::EMPTY_FD;
        fd_table[fd].active = true;
        fd_table[fd].is_socket = true;
        fd_table[fd].socket_idx = sock_idx as u8;
        if sock_nonblock { fd_table[fd].flags |= O_NONBLOCK; }
        if sock_cloexec { fd_table[fd].fd_flags |= rux_fs::fdtable::FD_CLOEXEC; }

        fd as isize
    }
}

unsafe fn resolve_socket(fd: usize) -> Option<usize> {
    if fd >= rux_fs::fdtable::MAX_FDS { return None; }
    let entry = &(*rux_fs::fdtable::fd_table())[fd];
    if entry.active && entry.is_socket {
        let idx = entry.socket_idx as usize;
        if idx < MAX_SOCKETS && SOCKETS[idx].active { return Some(idx); }
    }
    None
}

/// Increment socket reference count (called on fork/dup).
pub unsafe fn dup_socket_ref(sock_idx: u8) {
    let idx = sock_idx as usize;
    if idx < MAX_SOCKETS && SOCKETS[idx].active {
        SOCKETS[idx].ref_count = SOCKETS[idx].ref_count.saturating_add(1);
    }
}

/// Decrement socket reference count. Frees smoltcp handle when it reaches 0.
/// Disables interrupts to prevent timer ISR's poll() from accessing the freed socket.
pub unsafe fn close_socket_ref(sock_idx: u8) {
    let idx = sock_idx as usize;
    if idx < MAX_SOCKETS && SOCKETS[idx].active {
        SOCKETS[idx].ref_count = SOCKETS[idx].ref_count.saturating_sub(1);
        if SOCKETS[idx].ref_count == 0 {
            #[cfg(feature = "net")]
            if SOCKETS[idx].smol_handle_raw >= 0 {
                // Disable interrupts: poll() in the timer ISR must not access
                // the socket set while we're removing the socket from it.
                let was = crate::arch::irq_disable();
                let handle = to_handle(SOCKETS[idx].smol_handle_raw);
                SOCKETS[idx].smol_handle_raw = -1; // invalidate before free
                if SOCKETS[idx].sock_type == SOCK_STREAM {
                    rux_net::tcp_close(handle);
                }
                rux_net::socket_free(handle);
                crate::arch::irq_restore(was);
            }
            SOCKETS[idx].active = false;
        }
    }
}

/// bind(fd, addr, addrlen)
pub fn sys_bind(fd: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    if crate::uaccess::validate_user_ptr(addr_ptr, 8).is_err() { return crate::errno::EFAULT; }
    unsafe {
        // AF_UNIX bind: store path from sockaddr_un
        if SOCKETS[idx].is_unix {
            let family = *(addr_ptr as *const u16);
            if family != AF_UNIX as u16 { return crate::errno::EINVAL; }
            let path_ptr = addr_ptr + 2;
            let addrlen = _addrlen.min(110); // sockaddr_un = 2 + 108
            let path_len = if addrlen > 2 { addrlen - 2 } else { 0 };
            let path_len = path_len.min(31);
            for i in 0..path_len {
                let b = *((path_ptr + i) as *const u8);
                if b == 0 { SOCKETS[idx].unix_path_len = i as u8; break; }
                SOCKETS[idx].unix_path[i] = b;
                SOCKETS[idx].unix_path_len = (i + 1) as u8;
            }
            return 0;
        }
        let (port, _ip) = read_sockaddr(addr_ptr);
        // Check EADDRINUSE (skip if SO_REUSEADDR set on this socket)
        if port != 0 && !SOCKETS[idx].reuse_addr {
            for i in 0..MAX_SOCKETS {
                if SOCKETS[i].active && i != idx && SOCKETS[i].bound_port == port
                    && SOCKETS[i].sock_type == SOCKETS[idx].sock_type
                {
                    return crate::errno::EADDRINUSE;
                }
            }
        }
        SOCKETS[idx].bound_port = port;

        #[cfg(feature = "net")]
        if SOCKETS[idx].sock_type == SOCK_DGRAM && SOCKETS[idx].smol_handle_raw >= 0 {
            let _ = rux_net::udp_bind(to_handle(SOCKETS[idx].smol_handle_raw), port);
        }
    }
    0
}

/// connect(fd, addr, addrlen)
pub fn sys_connect(fd: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    if crate::uaccess::validate_user_ptr(addr_ptr, 8).is_err() { return crate::errno::EFAULT; }
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        // AF_UNIX connect: find listening socket by path, create pipe pair
        if SOCKETS[idx].is_unix {
            let family = *(addr_ptr as *const u16);
            if family != AF_UNIX as u16 { return crate::errno::EINVAL; }
            let path_ptr = addr_ptr + 2;
            let mut path = [0u8; 108];
            let mut plen = 0usize;
            for i in 0..107 {
                let b = *((path_ptr + i) as *const u8);
                if b == 0 { break; }
                path[i] = b;
                plen = i + 1;
            }
            // Find matching listener
            let listener = (0..MAX_SOCKETS).find(|&i| {
                i != idx && SOCKETS[i].active && SOCKETS[i].is_unix
                    && SOCKETS[i].unix_listening
                    && SOCKETS[i].unix_path_len == plen as u8
                    && SOCKETS[i].unix_path[..plen] == path[..plen]
            });
            let lis_idx = match listener {
                Some(i) => i,
                None => return crate::errno::ECONNREFUSED,
            };
            // Allocate two pipes for bidirectional communication
            let pipe_a = match rux_ipc::pipe::alloc() { Ok(id) => id, Err(e) => return e };
            let pipe_b = match rux_ipc::pipe::alloc() {
                Ok(id) => id,
                Err(_) => { rux_ipc::pipe::close(pipe_a, false); rux_ipc::pipe::close(pipe_a, true); return crate::errno::ENOMEM; }
            };
            // Client: reads pipe_a, writes pipe_b
            SOCKETS[idx].unix_pipe_a = pipe_a;
            SOCKETS[idx].unix_pipe_b = pipe_b;
            SOCKETS[idx].connected = true;
            // Store reverse info for the listener to pick up in accept
            SOCKETS[lis_idx].unix_pipe_a = pipe_b; // listener reads what client writes
            SOCKETS[lis_idx].unix_pipe_b = pipe_a; // listener writes what client reads
            SOCKETS[lis_idx].unix_pending = SOCKETS[lis_idx].unix_pending.saturating_add(1);
            // Set up fd as pipe-based for I/O
            let f = &mut (*rux_fs::fdtable::fd_table())[fd];
            f.is_pipe = true;
            f.pipe_id = pipe_a;
            f.pipe_write = false;
            f.pipe_id_write = pipe_b;
            return 0;
        }

        let (dst_port, dst_ip) = read_sockaddr(addr_ptr);
        let sock = &mut SOCKETS[idx];
        sock.connected_ip = dst_ip;
        sock.connected_port = dst_port;

        if sock.sock_type != SOCK_STREAM {
            sock.connected = true;
            return 0;
        }
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
            let nonblock = fd < rux_fs::fdtable::MAX_FDS && ((*rux_fs::fdtable::fd_table())[fd].flags & O_NONBLOCK) != 0;
            if nonblock { return crate::errno::EINPROGRESS; }

            // Blocking: poll until established
            for _ in 0..30_000u32 {
                rux_net::poll(crate::arch::Arch::ticks());
                if rux_net::tcp_is_established(handle) { SOCKETS[idx].connected = true; return 0; }
                if !rux_net::tcp_is_active(handle) { return crate::errno::ECONNREFUSED; }
                unsafe { net_wait(); }
            }
            return crate::errno::ETIMEDOUT;
        }
        #[cfg(not(feature = "net"))]
        return crate::errno::ENETUNREACH;
    }
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen)
/// Supports MSG_DONTWAIT (0x40), MSG_NOSIGNAL (0x4000).
pub fn sys_sendto(fd: usize, buf_ptr: usize, len: usize, flags: usize, addr_ptr: usize, _addrlen: usize) -> isize {
    const MSG_NOSIGNAL: usize = 0x4000;
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        if buf_ptr != 0 && crate::uaccess::validate_user_ptr(buf_ptr, len.min(1400)).is_err() { return crate::errno::EFAULT; }
        let (dst_ip, dst_port) = if addr_ptr != 0 {
            if crate::uaccess::validate_user_ptr(addr_ptr, 8).is_err() { return crate::errno::EFAULT; }
            let (p, ip) = read_sockaddr(addr_ptr);
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
                let nonblock = fd < rux_fs::fdtable::MAX_FDS
                    && ((*rux_fs::fdtable::fd_table())[fd].flags & O_NONBLOCK) != 0;
                let max_iters = if nonblock { 10u32 } else { 30_000u32 };
                for _ in 0..max_iters {
                    rux_net::poll(crate::arch::Arch::ticks());
                    if !rux_net::tcp_is_established(handle) {
                        // EPIPE: connection closed. Send SIGPIPE unless MSG_NOSIGNAL.
                        if flags & MSG_NOSIGNAL == 0 {
                            (*super::process()).signal_hot.pending.0 |= 1u64 << 12; // SIGPIPE=13
                        }
                        return -32;
                    }
                    match rux_net::tcp_send(handle, &kbuf[..send_len]) {
                        Ok(n) => {
                            rux_net::poll(crate::arch::Arch::ticks());
                            return n as isize;
                        }
                        Err(_) => {
                            // TX buffer full — yield to scheduler then retry
                            unsafe { net_wait(); }
                        }
                    }
                }
                return if nonblock { crate::errno::EAGAIN } else { crate::errno::EIO };
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
/// Supports MSG_DONTWAIT (0x40) — non-blocking regardless of socket flags.
pub fn sys_recvfrom(fd: usize, buf_ptr: usize, len: usize, flags: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    const MSG_DONTWAIT: usize = 0x40;
    if buf_ptr != 0 && crate::uaccess::validate_user_ptr(buf_ptr, len.min(4096)).is_err() { return crate::errno::EFAULT; }
    if addr_ptr != 0 && crate::uaccess::validate_user_ptr(addr_ptr, 16).is_err() { return crate::errno::EFAULT; }
    if addrlen_ptr != 0 && crate::uaccess::validate_user_ptr(addrlen_ptr, 4).is_err() { return crate::errno::EFAULT; }
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        let nonblock = (fd < rux_fs::fdtable::MAX_FDS && ((*rux_fs::fdtable::fd_table())[fd].flags & O_NONBLOCK) != 0)
            || flags & MSG_DONTWAIT != 0;

        #[cfg(feature = "net")]
        {
            use rux_arch::TimerOps;
            let sock = &SOCKETS[idx];
            let handle = to_handle(sock.smol_handle_raw);

            if sock.sock_type == SOCK_STREAM {
                let max_iters = if nonblock { 10u32 } else { 30_000u32 };
                for _iter in 0..max_iters {
                    // Poll with interrupts disabled (we own smoltcp exclusively)
                    rux_net::poll(crate::arch::Arch::ticks());
                    if rux_net::tcp_can_recv(handle) {
                        let mut kbuf = [0u8; 4096];
                        match rux_net::tcp_recv(handle, &mut kbuf[..len.min(4096)]) {
                            Ok(n) if n > 0 => {
                                core::ptr::copy_nonoverlapping(kbuf.as_ptr(), buf_ptr as *mut u8, n);
                                return n as isize;
                            }
                            Ok(_) => return 0,
                            Err(0) => return 0,
                            Err(_) => return 0,
                        }
                    }
                    if !rux_net::tcp_is_active(handle) && !rux_net::tcp_can_recv(handle) {
                        return 0;
                    }
                    if nonblock { return crate::errno::EAGAIN; }
                    unsafe { net_wait(); }
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
                    unsafe { net_wait(); }
                }
                return crate::errno::EAGAIN;
            }
        }
        crate::errno::EAGAIN
    }
}

/// listen(fd, backlog) — mark socket as passive (server)
pub fn sys_listen(fd: usize, _backlog: usize) -> isize {
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        if SOCKETS[idx].sock_type != SOCK_STREAM { return crate::errno::EOPNOTSUPP; }
        if SOCKETS[idx].is_unix {
            SOCKETS[idx].unix_listening = true;
            return 0;
        }
        #[cfg(feature = "net")]
        if SOCKETS[idx].smol_handle_raw >= 0 && SOCKETS[idx].bound_port != 0 {
            let handle = to_handle(SOCKETS[idx].smol_handle_raw);
            if rux_net::tcp_listen(handle, SOCKETS[idx].bound_port).is_err() {
                return crate::errno::EADDRINUSE;
            }
        }
    }
    0
}

/// accept(fd, addr, addrlen) — accept incoming connection
///
/// smoltcp model: a listening socket becomes the connected socket when a client
/// connects. To keep accepting, we allocate a new smoltcp socket for the listen
/// fd and re-listen on the same port. The original smoltcp socket (now connected)
/// moves to a new fd.
pub fn sys_accept(fd: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    if addr_ptr != 0 && crate::uaccess::validate_user_ptr(addr_ptr, 16).is_err() { return crate::errno::EFAULT; }
    if addrlen_ptr != 0 && crate::uaccess::validate_user_ptr(addrlen_ptr, 4).is_err() { return crate::errno::EFAULT; }
    let idx = match unsafe { resolve_socket(fd) } {
        Some(i) => i,
        None => return crate::errno::EBADF,
    };
    unsafe {
        if SOCKETS[idx].sock_type != SOCK_STREAM { return crate::errno::EOPNOTSUPP; }

        // AF_UNIX accept: wait for pending connection, return fd with pipes
        if SOCKETS[idx].is_unix {
            let nonblock = fd < rux_fs::fdtable::MAX_FDS && ((*rux_fs::fdtable::fd_table())[fd].flags & O_NONBLOCK) != 0;
            let max_iters = if nonblock { 10u32 } else { 30_000u32 };
            for _ in 0..max_iters {
                if SOCKETS[idx].unix_pending > 0 {
                    SOCKETS[idx].unix_pending -= 1;
                    let pipe_a = SOCKETS[idx].unix_pipe_a;
                    let pipe_b = SOCKETS[idx].unix_pipe_b;
                    // Allocate new socket + fd for the accepted connection
                    let new_sock = match (0..MAX_SOCKETS).find(|&i| !SOCKETS[i].active) {
                        Some(i) => i, None => return crate::errno::ENOMEM,
                    };
                    let fd_table = &mut *rux_fs::fdtable::fd_table();
                    let new_fd = match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
                        .find(|&f| !fd_table[f].active) {
                        Some(f) => f, None => return crate::errno::ENOMEM,
                    };
                    SOCKETS[new_sock] = SocketSlot::empty();
                    SOCKETS[new_sock].active = true;
                    SOCKETS[new_sock].ref_count = 1;
                    SOCKETS[new_sock].sock_type = SOCK_STREAM;
                    SOCKETS[new_sock].is_unix = true;
                    SOCKETS[new_sock].connected = true;
                    SOCKETS[new_sock].unix_pipe_a = pipe_a;
                    SOCKETS[new_sock].unix_pipe_b = pipe_b;
                    fd_table[new_fd] = rux_fs::fdtable::EMPTY_FD;
                    fd_table[new_fd].active = true;
                    fd_table[new_fd].is_socket = true;
                    fd_table[new_fd].socket_idx = new_sock as u8;
                    // Also set up as pipe for I/O
                    fd_table[new_fd].is_pipe = true;
                    fd_table[new_fd].pipe_id = pipe_a;
                    fd_table[new_fd].pipe_write = false;
                    fd_table[new_fd].pipe_id_write = pipe_b;
                    return new_fd as isize;
                }
                if nonblock { return crate::errno::EAGAIN; }
                unsafe { net_wait(); }
            }
            return crate::errno::EAGAIN;
        }

        let listen_port = SOCKETS[idx].bound_port;
        if listen_port == 0 { return crate::errno::EINVAL; }

        #[cfg(feature = "net")]
        {
            use rux_arch::TimerOps;
            let nonblock = fd < rux_fs::fdtable::MAX_FDS && ((*rux_fs::fdtable::fd_table())[fd].flags & O_NONBLOCK) != 0;
            let listen_handle = to_handle(SOCKETS[idx].smol_handle_raw);
            let max_iters = if nonblock { 10u32 } else { 60_000u32 };

            // Wait for the listen socket to become established (client connected)
            for _ in 0..max_iters {
                rux_net::poll(crate::arch::Arch::ticks());
                if rux_net::tcp_is_established(listen_handle) {
                    // Connection arrived. The listen socket is now connected.
                    // 1. Allocate a new socket slot + fd for the connected socket
                    let new_sock_idx = match (0..MAX_SOCKETS).find(|&i| !SOCKETS[i].active) {
                        Some(i) => i,
                        None => return crate::errno::ENOMEM,
                    };
                    let fd_table = &mut *rux_fs::fdtable::fd_table();
                    let new_fd = match (rux_fs::fdtable::FIRST_FILE_FD..rux_fs::fdtable::MAX_FDS)
                        .find(|&f| !fd_table[f].active)
                    {
                        Some(f) => f,
                        None => return crate::errno::ENOMEM,
                    };

                    // 2. Move the connected smoltcp handle to the new slot
                    let listen_port = SOCKETS[idx].bound_port;
                    SOCKETS[new_sock_idx] = SocketSlot::empty();
                    SOCKETS[new_sock_idx].active = true;
                    SOCKETS[new_sock_idx].ref_count = 1;
                    SOCKETS[new_sock_idx].sock_type = SOCK_STREAM;
                    SOCKETS[new_sock_idx].smol_handle_raw = SOCKETS[idx].smol_handle_raw;
                    SOCKETS[new_sock_idx].bound_port = listen_port; // inherit local port
                    SOCKETS[new_sock_idx].connected = true;

                    fd_table[new_fd] = rux_fs::fdtable::EMPTY_FD;
                    fd_table[new_fd].active = true;
                    fd_table[new_fd].is_socket = true;
                    fd_table[new_fd].socket_idx = new_sock_idx as u8;

                    // 3. Allocate a fresh smoltcp socket for the listen fd and re-listen
                    match rux_net::tcp_alloc() {
                        Some(new_listen) => {
                            SOCKETS[idx].smol_handle_raw = rux_net::handle_to_raw(new_listen) as i16;
                            let _ = rux_net::tcp_listen(new_listen, listen_port);
                        }
                        None => {
                            // Out of smoltcp sockets — listen fd can't accept again.
                            // This is an OOM condition. The current accept succeeds,
                            // but the server can't accept more connections until a
                            // socket is freed. Mark handle invalid so next accept
                            // returns EAGAIN instead of operating on a stale handle.
                            SOCKETS[idx].smol_handle_raw = -1;
                        }
                    }

                    // 4. Get peer address from smoltcp and store in socket slot
                    #[cfg(feature = "net")]
                    if SOCKETS[new_sock_idx].smol_handle_raw >= 0 {
                        let h = to_handle(SOCKETS[new_sock_idx].smol_handle_raw);
                        let (peer_ip, peer_port) = rux_net::tcp_remote_addr(h);
                        SOCKETS[new_sock_idx].connected_ip = peer_ip;
                        SOCKETS[new_sock_idx].connected_port = peer_port;
                        SOCKETS[new_sock_idx].connected = true;
                    }

                    // 5. Write peer address to user buffer if requested
                    if addr_ptr != 0 {
                        write_sockaddr(addr_ptr, SOCKETS[new_sock_idx].connected_port,
                                       SOCKETS[new_sock_idx].connected_ip);
                        if addrlen_ptr != 0 { *(addrlen_ptr as *mut u32) = 16; }
                    }

                    return new_fd as isize;
                }
                if nonblock { return crate::errno::EAGAIN; }
                unsafe { net_wait(); }
            }
            return crate::errno::EAGAIN;
        }
        #[cfg(not(feature = "net"))]
        return crate::errno::EOPNOTSUPP;
    }
}

/// shutdown(fd, how) — shut down part of a full-duplex connection
pub fn sys_shutdown(fd: usize, how: usize) -> isize {
    // how: 0=SHUT_RD, 1=SHUT_WR, 2=SHUT_RDWR
    if how > 2 { return crate::errno::EINVAL; }
    #[cfg(feature = "net")]
    unsafe {
        let idx = match resolve_socket(fd) { Some(i) => i, None => return crate::errno::EBADF };
        if SOCKETS[idx].sock_type == SOCK_STREAM && SOCKETS[idx].smol_handle_raw >= 0 {
            if how == 0 || how == 2 {
                // SHUT_RD / SHUT_RDWR: mark socket as not connected for reads
                // (smoltcp doesn't have half-close for reads, so we mark it)
                SOCKETS[idx].connected = false;
            }
            if how == 1 || how == 2 {
                // SHUT_WR / SHUT_RDWR: close the TCP write side
                rux_net::tcp_close(to_handle(SOCKETS[idx].smol_handle_raw));
            }
        }
    }
    0
}

/// Close a CLOEXEC socket during exec. Called from close_on_exec callback.
/// The fd is known to be active and is_socket — skip those checks.
pub fn close_socket_for_exec(fd: usize) {
    unsafe {
        let sock_idx = (*rux_fs::fdtable::fd_table())[fd].socket_idx;
        close_socket_ref(sock_idx);
    }
}

/// close a socket — decrements refcount, frees when it reaches 0
pub fn sys_close_socket(fd: usize) -> isize {
    unsafe {
        if fd >= rux_fs::fdtable::MAX_FDS { return crate::errno::EBADF; }
        let entry = &(*rux_fs::fdtable::fd_table())[fd];
        if !entry.active || !entry.is_socket { return crate::errno::EBADF; }
        let sock_idx = entry.socket_idx;

        (*rux_fs::fdtable::fd_table())[fd] = rux_fs::fdtable::EMPTY_FD;
        close_socket_ref(sock_idx);
    }
    0
}

// ── sendmsg / recvmsg / sendmmsg / recvmmsg ─────────────────────────

pub fn sys_sendmsg(fd: usize, msghdr_ptr: usize) -> isize {
    if crate::uaccess::validate_user_ptr(msghdr_ptr, 56).is_err() { return crate::errno::EFAULT; }
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
    if crate::uaccess::validate_user_ptr(msghdr_ptr, 56).is_err() { return crate::errno::EFAULT; }
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

// ── setsockopt / getsockopt / getsockname / getpeername ─────────────

pub fn sys_setsockopt(fd: usize, level: usize, optname: usize, optval: usize, _optlen: usize) -> isize {
    // SOL_SOCKET=1, SO_REUSEADDR=2
    if level == 1 && optname == 2 {
        unsafe {
            if fd < rux_fs::fdtable::MAX_FDS && (*rux_fs::fdtable::fd_table())[fd].is_socket {
                let idx = (*rux_fs::fdtable::fd_table())[fd].socket_idx as usize;
                if idx < MAX_SOCKETS && SOCKETS[idx].active {
                    let val = if optval != 0 && crate::uaccess::validate_user_ptr(optval, 4).is_ok() {
                        *(optval as *const i32)
                    } else { 1 };
                    SOCKETS[idx].reuse_addr = val != 0;
                }
            }
        }
    }
    // All other options: accept silently (stub)
    0
}

pub fn sys_getsockopt(fd: usize, level: usize, optname: usize, optval: usize, optlen: usize) -> isize {
    if optval != 0 && crate::uaccess::validate_user_ptr(optval, 4).is_err() { return crate::errno::EFAULT; }
    if optlen != 0 && crate::uaccess::validate_user_ptr(optlen, 4).is_err() { return crate::errno::EFAULT; }
    unsafe {
        if level == 0 {
            // IPPROTO_IP level
            if optname == 4 {
                // IP_OPTIONS: return empty (no IP options)
                if optlen >= 0x1000 { crate::uaccess::put_user(optlen, 0u32); }
                return 0;
            }
            // Other IPPROTO_IP options: return 0
            if optval >= 0x1000 { crate::uaccess::put_user(optval, 0i32); }
            if optlen >= 0x1000 { crate::uaccess::put_user(optlen, 4u32); }
            return 0;
        }
        // Handle by level
        if level == 6 {
            // IPPROTO_TCP
            let val = match optname {
                1 => 1i32,    // TCP_NODELAY: always enabled (smoltcp disables Nagle)
                _ => 0,
            };
            if optval >= 0x1000 { crate::uaccess::put_user(optval, val); }
            if optlen >= 0x1000 { crate::uaccess::put_user(optlen, 4u32); }
            return 0;
        }
        // SOL_SOCKET (level=1) and others
        let val = match optname {
            2 => {
                // SO_REUSEADDR: return stored value from setsockopt
                if fd < rux_fs::fdtable::MAX_FDS && (*rux_fs::fdtable::fd_table())[fd].is_socket {
                    let idx = (*rux_fs::fdtable::fd_table())[fd].socket_idx as usize;
                    if idx < MAX_SOCKETS && SOCKETS[idx].reuse_addr { 1i32 } else { 0 }
                } else { 0 }
            }
            4 => {
                // SO_ERROR: read and clear pending error
                if fd < rux_fs::fdtable::MAX_FDS && (*rux_fs::fdtable::fd_table())[fd].is_socket {
                    let sidx = (*rux_fs::fdtable::fd_table())[fd].socket_idx as usize;
                    if sidx < MAX_SOCKETS {
                        let err = SOCKETS[sidx].pending_error;
                        SOCKETS[sidx].pending_error = 0;
                        err
                    } else { 0 }
                } else { 0 }
            }
            7 | 8 => 65536, // SO_SNDBUF / SO_RCVBUF
            _ => 0,
        };
        if optval >= 0x1000 { crate::uaccess::put_user(optval, val); }
        if optlen >= 0x1000 { crate::uaccess::put_user(optlen, 4u32); }
    }
    0
}

pub fn sys_getsockname(fd: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    if addr_ptr == 0 { return 0; }
    if crate::uaccess::validate_user_ptr(addr_ptr, 16).is_err() { return crate::errno::EFAULT; }
    unsafe {
        let idx = match resolve_socket(fd) { Some(i) => i, None => return crate::errno::EBADF };
        let ip = {
            #[cfg(feature = "net")] { rux_net::our_ip() }
            #[cfg(not(feature = "net"))] { [0u8; 4] }
        };
        write_sockaddr(addr_ptr, SOCKETS[idx].bound_port, ip);
        if addrlen_ptr != 0 { *(addrlen_ptr as *mut u32) = 16; }
    }
    0
}

pub fn sys_getpeername(fd: usize, addr_ptr: usize, addrlen_ptr: usize) -> isize {
    if addr_ptr == 0 { return 0; }
    if crate::uaccess::validate_user_ptr(addr_ptr, 16).is_err() { return crate::errno::EFAULT; }
    unsafe {
        let idx = match resolve_socket(fd) { Some(i) => i, None => return crate::errno::EBADF };
        if !SOCKETS[idx].connected { return crate::errno::ENOTCONN; }
        write_sockaddr(addr_ptr, SOCKETS[idx].connected_port, SOCKETS[idx].connected_ip);
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
                let handle = to_handle(sock.smol_handle_raw);
                // Listen sockets: POLLIN means "connection pending"
                if sock.bound_port != 0 && !sock.connected {
                    return rux_net::tcp_is_established(handle);
                }
                // Connected sockets: POLLIN means "data available"
                return rux_net::tcp_can_recv(handle);
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
        let entry = &(*rux_fs::fdtable::fd_table())[fd];
        entry.active && entry.is_socket
    }
}
