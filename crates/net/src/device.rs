/// smoltcp Device trait implementation wrapping virtio send/recv function pointers.

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

/// Function pointer types for the virtio driver layer.
pub type SendFn = fn(&[u8]) -> bool;
pub type RecvFn = fn(&mut [u8]) -> Option<usize>;

/// A network device backed by virtio function pointers.
pub struct VirtioDevice {
    send: SendFn,
    recv: RecvFn,
    /// Single-frame RX buffer. Filled by recv, consumed by RxToken.
    rx_buf: [u8; 1514],
    rx_len: usize,
    /// Loopback queue: TX frames destined for our own IP get looped back.
    /// Circular buffer of 8 frames to handle multi-step handshakes (TCP 3-way + data).
    loopback_bufs: [[u8; 1514]; 8],
    loopback_lens: [usize; 8],
    pub loopback_head: usize, // next slot to write
    pub loopback_tail: usize, // next slot to read
    /// Our IP address (for loopback detection).
    pub our_ip: [u8; 4],
}

impl VirtioDevice {
    pub const fn empty() -> Self {
        Self {
            send: dummy_send,
            recv: dummy_recv,
            rx_buf: [0u8; 1514],
            rx_len: 0,
            loopback_bufs: [[0u8; 1514]; 8],
            loopback_lens: [0; 8],
            loopback_head: 0,
            loopback_tail: 0,
            our_ip: [0; 4],
        }
    }

    pub fn init(&mut self, send: SendFn, recv: RecvFn) {
        self.send = send;
        self.recv = recv;
    }
}

fn dummy_send(_: &[u8]) -> bool { false }
fn dummy_recv(_: &mut [u8]) -> Option<usize> { None }

// ── RxToken / TxToken ──────────────────────────────────────────────

/// RX token: holds a received frame in an internal buffer.
pub struct VirtioRxToken<'a> {
    buf: &'a [u8],
}

impl phy::RxToken for VirtioRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.buf)
    }
}

/// TX token: holds a reference to the send function and loopback info.
pub struct VirtioTxToken {
    send: SendFn,
    loopback_bufs: *mut [[u8; 1514]; 8],
    loopback_lens: *mut [usize; 8],
    loopback_head: *mut usize,
    our_ip: [u8; 4],
}

/// Check if an Ethernet frame is destined for ourselves (loopback).
/// Handles both IPv4 packets and ARP requests for our IP.
fn is_loopback_frame(frame: &[u8], our_ip: [u8; 4]) -> bool {
    if frame.len() < 14 { return false; }
    let ethertype = ((frame[12] as u16) << 8) | frame[13] as u16;
    match ethertype {
        0x0800 => { // IPv4
            if frame.len() < 34 { return false; }
            let dst = &frame[30..34];
            (dst[0] == 127) || (dst == our_ip)
        }
        0x0806 => { // ARP
            if frame.len() < 42 { return false; }
            // ARP target IP at offset 38-41
            let target_ip = &frame[38..42];
            target_ip == our_ip
        }
        _ => false,
    }
}

/// Convert an ARP request frame to an ARP reply (in place).
/// The request asks "Who has target_ip?" — we reply "I have it, here's my MAC."
fn arp_request_to_reply(frame: &mut [u8]) {
    if frame.len() < 42 { return; }
    // ARP opcode at offset 20-21: 1=request, 2=reply
    if frame[20] != 0 || frame[21] != 1 { return; } // not a request
    frame[21] = 2; // set opcode to reply
    // Swap sender/target: target becomes sender, sender becomes target
    // Sender HW addr (22-27) ↔ Target HW addr (32-37)
    // Sender IP (28-31) ↔ Target IP (38-41)
    for i in 0..10 {
        let tmp = frame[22 + i];
        frame[22 + i] = frame[32 + i];
        frame[32 + i] = tmp;
    }
    // Set sender HW addr: copy Ethernet source MAC (our MAC) to ARP sender HW
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[6..12]);
    frame[22..28].copy_from_slice(&mac);
}

impl phy::TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        static mut TX_BUF: [u8; 1514] = [0u8; 1514];
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(TX_BUF) };
        let result = f(&mut buf[..len]);
        // Check if this frame is destined for ourselves → loopback
        if is_loopback_frame(&buf[..len], self.our_ip) {
            unsafe {
                let head = *self.loopback_head;
                let bufs = &mut *self.loopback_bufs;
                let lens = &mut *self.loopback_lens;
                bufs[head % 8][..len].copy_from_slice(&buf[..len]);
                // Swap MAC: dst(0..6) ↔ src(6..12)
                for i in 0..6 {
                    let tmp = bufs[head % 8][i];
                    bufs[head % 8][i] = bufs[head % 8][i + 6];
                    bufs[head % 8][i + 6] = tmp;
                }
                // If this is an ARP request, convert to ARP reply
                let ethertype = ((bufs[head % 8][12] as u16) << 8) | bufs[head % 8][13] as u16;
                if ethertype == 0x0806 {
                    arp_request_to_reply(&mut bufs[head % 8]);
                }
                lens[head % 8] = len;
                *self.loopback_head = head + 1;
            }
        } else {
            (self.send)(&buf[..len]);
        }
        result
    }
}

// ── Device implementation ──────────────────────────────────────────

impl Device for VirtioDevice {
    type RxToken<'a> = VirtioRxToken<'a>;
    type TxToken<'a> = VirtioTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Check loopback queue first (frames we sent to ourselves)
        if self.loopback_tail < self.loopback_head {
            let tail = self.loopback_tail % 4;
            let len = self.loopback_lens[tail];
            self.rx_buf[..len].copy_from_slice(&self.loopback_bufs[tail][..len]);
            self.rx_len = len;
            self.loopback_lens[tail] = 0;
            self.loopback_tail += 1;
            let rx = VirtioRxToken { buf: &self.rx_buf[..len] };
            let tx = VirtioTxToken {
                send: self.send,
                loopback_bufs: &raw mut self.loopback_bufs,
                loopback_lens: &raw mut self.loopback_lens,
                loopback_head: &raw mut self.loopback_head,
                our_ip: self.our_ip,
            };
            return Some((rx, tx));
        }
        // Try to receive a frame from the driver
        match (self.recv)(&mut self.rx_buf) {
            Some(len) if len > 0 => {
                self.rx_len = len;
                let rx = VirtioRxToken { buf: &self.rx_buf[..len] };
                let tx = VirtioTxToken {
                    send: self.send,
                    loopback_bufs: &raw mut self.loopback_bufs,
                    loopback_lens: &raw mut self.loopback_lens,
                    loopback_head: &raw mut self.loopback_head,
                    our_ip: self.our_ip,
                };
                Some((rx, tx))
            }
            _ => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken {
            send: self.send,
            loopback_bufs: &raw mut self.loopback_bufs,
            loopback_lens: &raw mut self.loopback_lens,
            loopback_head: &raw mut self.loopback_head,
            our_ip: self.our_ip,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(4);
        caps
    }
}
