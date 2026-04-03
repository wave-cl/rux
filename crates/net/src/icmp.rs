//! ICMP: Echo Request/Reply (ping).

use super::ipv4;

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;

/// Handle an incoming ICMP packet. Returns a reply packet if it's an echo request.
pub fn handle(src_ip: [u8; 4], dst_ip: [u8; 4], payload: &[u8]) -> Option<([u8; 1500], usize)> {
    if payload.len() < 8 { return None; }
    let icmp_type = payload[0];
    if icmp_type != ICMP_ECHO_REQUEST { return None; }

    // Build echo reply: same data but type=0
    let mut reply_icmp = [0u8; 1480];
    let icmp_len = payload.len().min(1480);
    reply_icmp[..icmp_len].copy_from_slice(&payload[..icmp_len]);
    reply_icmp[0] = ICMP_ECHO_REPLY;
    reply_icmp[2] = 0; reply_icmp[3] = 0; // clear checksum
    let cksum = ipv4::checksum(&reply_icmp[..icmp_len]);
    reply_icmp[2..4].copy_from_slice(&cksum.to_be_bytes());

    // Wrap in IPv4
    let mut pkt = [0u8; 1500];
    static mut IP_ID: u16 = 0;
    unsafe { IP_ID += 1; }
    let len = ipv4::build(&mut pkt, dst_ip, src_ip, ipv4::PROTO_ICMP, &reply_icmp[..icmp_len], unsafe { IP_ID });
    Some((pkt, len))
}
