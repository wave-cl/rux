//! UDP: minimal send/receive.

use super::ipv4;

const UDP_HLEN: usize = 8;

/// Parse a UDP packet. Returns (src_port, dst_port, payload).
pub fn parse(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    if data.len() < UDP_HLEN { return None; }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]) as usize;
    if data.len() < length { return None; }
    Some((src_port, dst_port, &data[UDP_HLEN..length]))
}

/// Build a UDP packet (header + payload). Returns length.
pub fn build(buf: &mut [u8], src_port: u16, dst_port: u16, payload: &[u8]) -> usize {
    let udp_len = UDP_HLEN + payload.len();
    if buf.len() < udp_len { return 0; }
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    buf[6..8].copy_from_slice(&[0, 0]); // checksum (optional for UDP over IPv4)
    buf[UDP_HLEN..udp_len].copy_from_slice(payload);
    udp_len
}
