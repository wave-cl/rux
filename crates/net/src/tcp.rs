//! Minimal TCP: active open (connect), data transfer, close.
//!
//! State machine: CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
//! No listen/accept (passive open), no congestion control, no window scaling.
//! Fixed 8KB receive buffer. Retransmit via simple timeout.

use super::ipv4;

// ── TCP header ─────────────────────────────────────────────────────

const TCP_HLEN: usize = 20; // minimum TCP header (no options)
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

/// Parse a TCP segment. Returns (src_port, dst_port, seq, ack, flags, window, payload).
pub fn parse(data: &[u8]) -> Option<(u16, u16, u32, u32, u8, u16, &[u8])> {
    if data.len() < TCP_HLEN { return None; }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    if data.len() < data_offset { return None; }
    Some((src_port, dst_port, seq, ack, flags, window, &data[data_offset..]))
}

/// Build a TCP segment into `buf`. Returns total length.
pub fn build(
    buf: &mut [u8], src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, window: u16,
    payload: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4],
) -> usize {
    let tcp_len = TCP_HLEN + payload.len();
    if buf.len() < tcp_len { return 0; }
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack.to_be_bytes());
    buf[12] = (5 << 4); // data offset = 5 (20 bytes, no options)
    buf[13] = flags;
    buf[14..16].copy_from_slice(&window.to_be_bytes());
    buf[16..18].copy_from_slice(&[0, 0]); // checksum placeholder
    buf[18..20].copy_from_slice(&[0, 0]); // urgent pointer
    if !payload.is_empty() {
        buf[TCP_HLEN..tcp_len].copy_from_slice(payload);
    }
    // TCP checksum with pseudo-header
    let cksum = tcp_checksum(&buf[..tcp_len], src_ip, dst_ip);
    buf[16..18].copy_from_slice(&cksum.to_be_bytes());
    tcp_len
}

fn tcp_checksum(tcp_data: &[u8], src: [u8; 4], dst: [u8; 4]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + tcp_len(2)
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += 6u32; // protocol = TCP
    sum += tcp_data.len() as u32;
    // TCP data
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() { sum += (tcp_data[i] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

// ── TCP Connection State ───────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub enum TcpState {
    Closed,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
}

const RX_BUF_SIZE: usize = 8192;
const MAX_TCP_CONNS: usize = 4;

pub struct TcpConn {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_ip: [u8; 4],
    pub local_ip: [u8; 4],
    // Sequence numbers
    pub snd_nxt: u32, // next seq to send
    pub snd_una: u32, // oldest unacknowledged
    pub rcv_nxt: u32, // next expected seq from remote
    // Receive buffer (circular)
    pub rx_buf: [u8; RX_BUF_SIZE],
    pub rx_head: usize, // read position
    pub rx_tail: usize, // write position
    pub active: bool,
    pub fin_received: bool,
}

impl TcpConn {
    pub const fn empty() -> Self {
        Self {
            state: TcpState::Closed,
            local_port: 0, remote_port: 0,
            remote_ip: [0; 4], local_ip: [0; 4],
            snd_nxt: 0, snd_una: 0, rcv_nxt: 0,
            rx_buf: [0; RX_BUF_SIZE],
            rx_head: 0, rx_tail: 0,
            active: false, fin_received: false,
        }
    }

    pub fn rx_available(&self) -> usize {
        if self.rx_tail >= self.rx_head { self.rx_tail - self.rx_head }
        else { RX_BUF_SIZE - self.rx_head + self.rx_tail }
    }

    pub fn rx_read(&mut self, buf: &mut [u8]) -> usize {
        let avail = self.rx_available();
        let n = buf.len().min(avail);
        for i in 0..n {
            buf[i] = self.rx_buf[self.rx_head];
            self.rx_head = (self.rx_head + 1) % RX_BUF_SIZE;
        }
        n
    }

    fn rx_write(&mut self, data: &[u8]) {
        for &b in data {
            self.rx_buf[self.rx_tail] = b;
            self.rx_tail = (self.rx_tail + 1) % RX_BUF_SIZE;
        }
    }
}

static mut CONNS: [TcpConn; MAX_TCP_CONNS] = [
    TcpConn::empty(), TcpConn::empty(),
    TcpConn::empty(), TcpConn::empty(),
];
static mut NEXT_PORT: u16 = 49152;

/// Allocate a TCP connection slot. Returns index or None.
pub fn alloc_conn() -> Option<usize> {
    unsafe {
        for i in 0..MAX_TCP_CONNS {
            if !CONNS[i].active {
                CONNS[i] = TcpConn::empty();
                CONNS[i].active = true;
                NEXT_PORT += 1;
                CONNS[i].local_port = NEXT_PORT;
                return Some(i);
            }
        }
        None
    }
}

pub fn get_conn(idx: usize) -> &'static mut TcpConn {
    unsafe { &mut CONNS[idx] }
}

/// Initiate a TCP connection (active open = SYN).
pub unsafe fn connect(idx: usize, dst_ip: [u8; 4], dst_port: u16, src_ip: [u8; 4]) -> bool {
    let conn = &mut CONNS[idx];
    conn.remote_ip = dst_ip;
    conn.remote_port = dst_port;
    conn.local_ip = src_ip;
    // Use tick counter as initial sequence number
    conn.snd_nxt = 1000; // simple ISN
    conn.snd_una = conn.snd_nxt;
    conn.state = TcpState::SynSent;

    // Send SYN
    let mut seg = [0u8; 60];
    let len = build(&mut seg, conn.local_port, dst_port,
        conn.snd_nxt, 0, TCP_SYN, 8192, &[], src_ip, dst_ip);
    conn.snd_nxt += 1; // SYN consumes one seq
    super::stack::send_ip_raw(dst_ip, ipv4::PROTO_TCP, &seg[..len])
}

/// Send data on an established connection.
pub unsafe fn send(idx: usize, data: &[u8]) -> isize {
    let conn = &mut CONNS[idx];
    if conn.state != TcpState::Established { return -1; }

    let mut sent = 0usize;
    while sent < data.len() {
        let chunk = (data.len() - sent).min(1400); // MSS-ish
        let mut seg = [0u8; 1500];
        let flags = TCP_ACK | TCP_PSH;
        let len = build(&mut seg, conn.local_port, conn.remote_port,
            conn.snd_nxt, conn.rcv_nxt, flags, 8192,
            &data[sent..sent + chunk], conn.local_ip, conn.remote_ip);
        conn.snd_nxt = conn.snd_nxt.wrapping_add(chunk as u32);
        super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
        sent += chunk;
    }
    sent as isize
}

/// Close a TCP connection (send FIN).
pub unsafe fn close(idx: usize) {
    let conn = &mut CONNS[idx];
    if conn.state == TcpState::Established {
        let mut seg = [0u8; 60];
        let len = build(&mut seg, conn.local_port, conn.remote_port,
            conn.snd_nxt, conn.rcv_nxt, TCP_FIN | TCP_ACK, 0,
            &[], conn.local_ip, conn.remote_ip);
        conn.snd_nxt += 1;
        conn.state = TcpState::FinWait1;
        super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
    } else if conn.state == TcpState::CloseWait {
        let mut seg = [0u8; 60];
        let len = build(&mut seg, conn.local_port, conn.remote_port,
            conn.snd_nxt, conn.rcv_nxt, TCP_FIN | TCP_ACK, 0,
            &[], conn.local_ip, conn.remote_ip);
        conn.snd_nxt += 1;
        conn.state = TcpState::LastAck;
        super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
    }
}

/// Handle an incoming TCP segment. Called from the stack's IP handler.
pub unsafe fn handle_segment(
    src_ip: [u8; 4], dst_ip: [u8; 4],
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, payload: &[u8],
) {
    // Find matching connection
    let conn_idx = (0..MAX_TCP_CONNS).find(|&i| {
        CONNS[i].active
            && CONNS[i].local_port == dst_port
            && CONNS[i].remote_port == src_port
            && CONNS[i].remote_ip == src_ip
    });
    let idx = match conn_idx {
        Some(i) => i,
        None => {
            // No connection — send RST if not RST
            if flags & TCP_RST == 0 {
                let mut seg = [0u8; 60];
                let len = build(&mut seg, dst_port, src_port,
                    ack, seq.wrapping_add(1), TCP_RST | TCP_ACK, 0,
                    &[], dst_ip, src_ip);
                super::stack::send_ip_raw(src_ip, ipv4::PROTO_TCP, &seg[..len]);
            }
            return;
        }
    };
    let conn = &mut CONNS[idx];

    match conn.state {
        TcpState::SynSent => {
            if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
                // SYN+ACK received — complete handshake
                conn.rcv_nxt = seq.wrapping_add(1);
                conn.snd_una = ack;
                conn.state = TcpState::Established;
                // Send ACK
                let mut seg = [0u8; 60];
                let len = build(&mut seg, conn.local_port, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, 8192,
                    &[], conn.local_ip, conn.remote_ip);
                super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
            }
        }
        TcpState::Established => {
            // Process incoming data
            if !payload.is_empty() && seq == conn.rcv_nxt {
                conn.rx_write(payload);
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload.len() as u32);
                // Send ACK
                let mut seg = [0u8; 60];
                let len = build(&mut seg, conn.local_port, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, 8192,
                    &[], conn.local_ip, conn.remote_ip);
                super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
            }
            // FIN received
            if flags & TCP_FIN != 0 {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                conn.fin_received = true;
                conn.state = TcpState::CloseWait;
                let mut seg = [0u8; 60];
                let len = build(&mut seg, conn.local_port, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, 0,
                    &[], conn.local_ip, conn.remote_ip);
                super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
            }
            // ACK of our data
            if flags & TCP_ACK != 0 {
                conn.snd_una = ack;
            }
        }
        TcpState::FinWait1 => {
            if flags & TCP_ACK != 0 {
                conn.state = TcpState::FinWait2;
            }
            if flags & TCP_FIN != 0 {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                let mut seg = [0u8; 60];
                let len = build(&mut seg, conn.local_port, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, 0,
                    &[], conn.local_ip, conn.remote_ip);
                super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
                conn.state = TcpState::Closed;
                conn.active = false;
            }
        }
        TcpState::FinWait2 => {
            if flags & TCP_FIN != 0 {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                let mut seg = [0u8; 60];
                let len = build(&mut seg, conn.local_port, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, 0,
                    &[], conn.local_ip, conn.remote_ip);
                super::stack::send_ip_raw(conn.remote_ip, ipv4::PROTO_TCP, &seg[..len]);
                conn.state = TcpState::Closed;
                conn.active = false;
            }
        }
        TcpState::LastAck => {
            if flags & TCP_ACK != 0 {
                conn.state = TcpState::Closed;
                conn.active = false;
            }
        }
        _ => {}
    }
}
