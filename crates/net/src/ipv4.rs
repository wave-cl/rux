//! IPv4 packet parsing and building.

pub const IP_HLEN: usize = 20; // minimum IPv4 header (no options)
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Parse an IPv4 packet. Returns (src_ip, dst_ip, protocol, payload).
pub fn parse(data: &[u8]) -> Option<([u8; 4], [u8; 4], u8, &[u8])> {
    if data.len() < IP_HLEN { return None; }
    let version = data[0] >> 4;
    if version != 4 { return None; }
    let ihl = (data[0] & 0xF) as usize * 4;
    if data.len() < ihl { return None; }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < total_len { return None; }
    let protocol = data[9];
    let src: [u8; 4] = data[12..16].try_into().ok()?;
    let dst: [u8; 4] = data[16..20].try_into().ok()?;
    Some((src, dst, protocol, &data[ihl..total_len]))
}

/// Build an IPv4 header + payload into `buf`. Returns total packet length.
pub fn build(
    buf: &mut [u8], src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8], id: u16,
) -> usize {
    let total_len = IP_HLEN + payload.len();
    if buf.len() < total_len { return 0; }

    buf[0] = 0x45; // version=4, IHL=5 (20 bytes)
    buf[1] = 0;    // DSCP/ECN
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    buf[8] = 64;   // TTL
    buf[9] = protocol;
    buf[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    buf[IP_HLEN..total_len].copy_from_slice(payload);

    // Compute header checksum
    let cksum = checksum(&buf[..IP_HLEN]);
    buf[10..12].copy_from_slice(&cksum.to_be_bytes());

    total_len
}

/// Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
