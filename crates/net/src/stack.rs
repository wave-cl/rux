//! Network stack: processes incoming packets, dispatches to protocol handlers.

use super::{eth, arp, ipv4, icmp, udp};

/// Network configuration.
pub struct NetConfig {
    pub ip: [u8; 4],
    pub gateway: [u8; 4],
    pub netmask: [u8; 4],
    pub mac: [u8; 6],
}

static mut CONFIG: NetConfig = NetConfig {
    ip: [10, 0, 2, 15],       // QEMU default user-mode networking
    gateway: [10, 0, 2, 2],   // QEMU default gateway
    netmask: [255, 255, 255, 0],
    mac: [0; 6],
};

/// Set the network configuration.
pub fn configure(ip: [u8; 4], gateway: [u8; 4], netmask: [u8; 4], mac: [u8; 6]) {
    unsafe {
        CONFIG.ip = ip;
        CONFIG.gateway = gateway;
        CONFIG.netmask = netmask;
        CONFIG.mac = mac;
    }
}

pub fn our_ip() -> [u8; 4] { unsafe { CONFIG.ip } }
pub fn our_mac() -> [u8; 6] { unsafe { CONFIG.mac } }
pub fn gateway() -> [u8; 4] { unsafe { CONFIG.gateway } }

/// Process a received ethernet frame. May generate response frames.
/// Returns (response_frame, length) or None.
pub fn process_frame(frame: &[u8]) -> Option<([u8; 1514], usize)> {
    let (dst, src, etype, payload) = eth::parse(frame)?;

    // Only accept frames for us or broadcast
    let our_mac = unsafe { &CONFIG.mac };
    if dst != our_mac && dst != &eth::BROADCAST { return None; }

    match etype {
        eth::ETH_P_ARP => {
            arp::handle(payload, unsafe { CONFIG.ip }, our_mac)
        }
        eth::ETH_P_IP => {
            let (src_ip, dst_ip, proto, ip_payload) = ipv4::parse(payload)?;
            // Only accept packets for our IP
            if dst_ip != unsafe { CONFIG.ip } { return None; }

            match proto {
                ipv4::PROTO_ICMP => {
                    let (ip_pkt, ip_len) = icmp::handle(src_ip, dst_ip, ip_payload)?;
                    // Wrap in ethernet
                    let mut frame_out = [0u8; 1514];
                    let len = eth::build(&mut frame_out, src, our_mac, eth::ETH_P_IP, &ip_pkt[..ip_len]);
                    Some((frame_out, len))
                }
                ipv4::PROTO_UDP => {
                    let (_src_port, _dst_port, _data) = udp::parse(ip_payload)?;
                    // TODO: deliver to socket
                    None
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Send an IP packet to a destination. Handles ARP resolution.
pub unsafe fn send_ip(dst_ip: [u8; 4], protocol: u8, payload: &[u8]) -> bool {
    let our_ip = CONFIG.ip;
    let our_mac = CONFIG.mac;

    // Determine next-hop MAC
    let next_hop = if same_subnet(dst_ip, our_ip, CONFIG.netmask) {
        dst_ip
    } else {
        CONFIG.gateway
    };

    let dst_mac = match arp::lookup(next_hop) {
        Some(m) => m,
        None => {
            // Send ARP request and wait briefly for reply
            let (req_frame, req_len) = arp::send_request(next_hop, our_ip, &our_mac);
            rux_drivers::virtio::net::send(&req_frame[..req_len]);
            // Poll for ARP reply (up to ~100ms)
            let mut rx_buf = [0u8; 1514];
            for _ in 0..100_000 {
                if let Some(n) = rux_drivers::virtio::net::recv(&mut rx_buf) {
                    if let Some((resp, rlen)) = process_frame(&rx_buf[..n]) {
                        rux_drivers::virtio::net::send(&resp[..rlen]);
                    }
                }
                if let Some(m) = arp::lookup(next_hop) {
                    return send_ip_with_mac(dst_ip, protocol, payload, &m, &our_mac, our_ip);
                }
                core::hint::spin_loop();
            }
            return false; // ARP timeout
        }
    };

    send_ip_with_mac(dst_ip, protocol, payload, &dst_mac, &our_mac, our_ip)
}

unsafe fn send_ip_with_mac(
    dst_ip: [u8; 4], protocol: u8, payload: &[u8],
    dst_mac: &[u8; 6], src_mac: &[u8; 6], src_ip: [u8; 4],
) -> bool {
    static mut IP_ID: u16 = 1;
    IP_ID += 1;

    let mut ip_pkt = [0u8; 1500];
    let ip_len = ipv4::build(&mut ip_pkt, src_ip, dst_ip, protocol, payload, IP_ID);
    if ip_len == 0 { return false; }

    let mut frame = [0u8; 1514];
    let frame_len = eth::build(&mut frame, dst_mac, src_mac, eth::ETH_P_IP, &ip_pkt[..ip_len]);
    rux_drivers::virtio::net::send(&frame[..frame_len])
}

fn same_subnet(a: [u8; 4], b: [u8; 4], mask: [u8; 4]) -> bool {
    for i in 0..4 {
        if (a[i] & mask[i]) != (b[i] & mask[i]) { return false; }
    }
    true
}

/// Poll for incoming packets and process them. Call periodically.
pub unsafe fn poll() {
    let mut buf = [0u8; 1514];
    while let Some(n) = rux_drivers::virtio::net::recv(&mut buf) {
        if let Some((resp, rlen)) = process_frame(&buf[..n]) {
            rux_drivers::virtio::net::send(&resp[..rlen]);
        }
    }
}
