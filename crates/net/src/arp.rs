//! ARP (Address Resolution Protocol) for IPv4 over Ethernet.

use super::eth;

const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const ARP_HLEN: usize = 28; // ARP packet for IPv4/Ethernet

/// ARP cache: 16 entries, static lifetime.
static mut ARP_CACHE: [ArpEntry; 16] = [ArpEntry::empty(); 16];

#[derive(Clone, Copy)]
struct ArpEntry {
    ip: [u8; 4],
    mac: [u8; 6],
    valid: bool,
}

impl ArpEntry {
    const fn empty() -> Self { Self { ip: [0; 4], mac: [0; 6], valid: false } }
}

/// Look up MAC for an IP in the ARP cache.
pub fn lookup(ip: [u8; 4]) -> Option<[u8; 6]> {
    unsafe {
        for e in ARP_CACHE.iter() {
            if e.valid && e.ip == ip { return Some(e.mac); }
        }
    }
    None
}

/// Insert/update an ARP cache entry.
pub fn insert(ip: [u8; 4], mac: [u8; 6]) {
    unsafe {
        // Update existing
        for e in ARP_CACHE.iter_mut() {
            if e.valid && e.ip == ip { e.mac = mac; return; }
        }
        // Find free slot
        for e in ARP_CACHE.iter_mut() {
            if !e.valid { *e = ArpEntry { ip, mac, valid: true }; return; }
        }
        // Overwrite first entry
        ARP_CACHE[0] = ArpEntry { ip, mac, valid: true };
    }
}

/// Handle an incoming ARP packet. Returns a reply frame if needed.
pub fn handle(payload: &[u8], our_ip: [u8; 4], our_mac: &[u8; 6]) -> Option<([u8; 1514], usize)> {
    if payload.len() < ARP_HLEN { return None; }
    let op = u16::from_be_bytes([payload[6], payload[7]]);
    let sender_mac: [u8; 6] = payload[8..14].try_into().ok()?;
    let sender_ip: [u8; 4] = payload[14..18].try_into().ok()?;
    let target_ip: [u8; 4] = payload[24..28].try_into().ok()?;

    // Always learn sender
    insert(sender_ip, sender_mac);

    if op == ARP_REQUEST && target_ip == our_ip {
        // Build ARP reply
        let mut reply = [0u8; ARP_HLEN];
        reply[0..2].copy_from_slice(&[0, 1]); // hw type = Ethernet
        reply[2..4].copy_from_slice(&[0x08, 0]); // proto = IPv4
        reply[4] = 6; // hw addr len
        reply[5] = 4; // proto addr len
        reply[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes());
        reply[8..14].copy_from_slice(our_mac); // sender MAC
        reply[14..18].copy_from_slice(&our_ip); // sender IP
        reply[18..24].copy_from_slice(&sender_mac); // target MAC
        reply[24..28].copy_from_slice(&sender_ip); // target IP

        let mut frame = [0u8; 1514];
        let len = eth::build(&mut frame, &sender_mac, our_mac, eth::ETH_P_ARP, &reply);
        Some((frame, len))
    } else {
        None
    }
}

/// Send an ARP request for the given IP.
pub fn send_request(target_ip: [u8; 4], our_ip: [u8; 4], our_mac: &[u8; 6]) -> ([u8; 1514], usize) {
    let mut arp = [0u8; ARP_HLEN];
    arp[0..2].copy_from_slice(&[0, 1]); // Ethernet
    arp[2..4].copy_from_slice(&[0x08, 0]); // IPv4
    arp[4] = 6; arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_REQUEST.to_be_bytes());
    arp[8..14].copy_from_slice(our_mac);
    arp[14..18].copy_from_slice(&our_ip);
    arp[18..24].copy_from_slice(&[0; 6]); // unknown target MAC
    arp[24..28].copy_from_slice(&target_ip);

    let mut frame = [0u8; 1514];
    let len = eth::build(&mut frame, &eth::BROADCAST, our_mac, eth::ETH_P_ARP, &arp);
    (frame, len)
}
