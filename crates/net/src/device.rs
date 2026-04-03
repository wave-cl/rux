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
}

impl VirtioDevice {
    pub const fn empty() -> Self {
        Self {
            send: dummy_send,
            recv: dummy_recv,
            rx_buf: [0u8; 1514],
            rx_len: 0,
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

/// TX token: holds a reference to the send function.
pub struct VirtioTxToken {
    send: SendFn,
}

impl phy::TxToken for VirtioTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = [0u8; 1514];
        let result = f(&mut buf[..len]);
        (self.send)(&buf[..len]);
        result
    }
}

// ── Device implementation ──────────────────────────────────────────

impl Device for VirtioDevice {
    type RxToken<'a> = VirtioRxToken<'a>;
    type TxToken<'a> = VirtioTxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Try to receive a frame from the driver
        match (self.recv)(&mut self.rx_buf) {
            Some(len) if len > 0 => {
                self.rx_len = len;
                let rx = VirtioRxToken { buf: &self.rx_buf[..len] };
                let tx = VirtioTxToken { send: self.send };
                Some((rx, tx))
            }
            _ => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken { send: self.send })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps.max_burst_size = Some(1);
        caps
    }
}
