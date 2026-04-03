//! Ethernet frame parsing and building.

pub const ETH_HLEN: usize = 14;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;
pub const BROADCAST: [u8; 6] = [0xFF; 6];

/// Parse an ethernet frame header.
pub fn parse(frame: &[u8]) -> Option<(/*dst*/&[u8; 6], /*src*/&[u8; 6], /*ethertype*/u16, /*payload*/&[u8])> {
    if frame.len() < ETH_HLEN { return None; }
    let dst = frame[0..6].try_into().ok()?;
    let src = frame[6..12].try_into().ok()?;
    let etype = u16::from_be_bytes([frame[12], frame[13]]);
    Some((dst, src, etype, &frame[ETH_HLEN..]))
}

/// Build an ethernet frame into `buf`. Returns total frame length.
pub fn build(buf: &mut [u8], dst: &[u8; 6], src: &[u8; 6], etype: u16, payload: &[u8]) -> usize {
    let len = ETH_HLEN + payload.len();
    if buf.len() < len { return 0; }
    buf[0..6].copy_from_slice(dst);
    buf[6..12].copy_from_slice(src);
    buf[12..14].copy_from_slice(&etype.to_be_bytes());
    buf[ETH_HLEN..len].copy_from_slice(payload);
    len
}
