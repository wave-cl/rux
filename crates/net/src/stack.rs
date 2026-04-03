//! Network stack: processes incoming packets, dispatches to protocol handlers.

use super::{eth, arp, ipv4, icmp, udp, tcp};

/// Function pointers for the network driver (set during init).
static mut NET_SEND: Option<unsafe fn(&[u8]) -> bool> = None;
static mut NET_RECV: Option<unsafe fn(&mut [u8]) -> Option<usize>> = None;

/// Callbacks to deliver packets to the kernel socket layer.
static mut DELIVER_UDP: Option<unsafe fn([u8; 4], u16, u16, &[u8])> = None;
static mut DELIVER_ICMP: Option<unsafe fn([u8; 4], &[u8])> = None;

/// Register network driver send/recv functions.
pub fn set_driver(
    send_fn: unsafe fn(&[u8]) -> bool,
    recv_fn: unsafe fn(&mut [u8]) -> Option<usize>,
) {
    unsafe {
        NET_SEND = Some(send_fn);
        NET_RECV = Some(recv_fn);
    }
}

/// Register socket delivery callbacks.
pub fn set_callbacks(
    udp_cb: unsafe fn([u8; 4], u16, u16, &[u8]),
    icmp_cb: unsafe fn([u8; 4], &[u8]),
) {
    unsafe {
        DELIVER_UDP = Some(udp_cb);
        DELIVER_ICMP = Some(icmp_cb);
    }
}

/// Send a raw ethernet frame via the registered driver.
unsafe fn driver_send(frame: &[u8]) -> bool {
    match NET_SEND {
        Some(f) => f(frame),
        None => false,
    }
}

/// Receive a raw ethernet frame via the registered driver.
unsafe fn driver_recv(buf: &mut [u8]) -> Option<usize> {
    match NET_RECV {
        Some(f) => f(buf),
        None => None,
    }
}

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

pub fn is_configured() -> bool { unsafe { NET_SEND.is_some() } }
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
                    // Deliver to raw ICMP socket if registered
                    unsafe {
                        if let Some(cb) = DELIVER_ICMP {
                            cb(src_ip, ip_payload);
                        }
                    }
                    // Also send kernel-level echo reply
                    let (ip_pkt, ip_len) = icmp::handle(src_ip, dst_ip, ip_payload)?;
                    let mut frame_out = [0u8; 1514];
                    let len = eth::build(&mut frame_out, src, our_mac, eth::ETH_P_IP, &ip_pkt[..ip_len]);
                    Some((frame_out, len))
                }
                ipv4::PROTO_TCP => {
                    let (sp, dp, seq, ack, flags, _win, payload) = tcp::parse(ip_payload)?;
                    unsafe { tcp::handle_segment(src_ip, dst_ip, sp, dp, seq, ack, flags, payload); }
                    None
                }
                ipv4::PROTO_UDP => {
                    let (src_port, dst_port, data) = udp::parse(ip_payload)?;
                    unsafe {
                        if let Some(cb) = DELIVER_UDP {
                            cb(src_ip, src_port, dst_port, data);
                        }
                    }
                    None
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Send an IP packet to a destination. Handles ARP resolution.
/// Send a raw IP packet (used by TCP which builds its own IP payload).
pub unsafe fn send_ip_raw(dst_ip: [u8; 4], protocol: u8, payload: &[u8]) -> bool {
    send_ip(dst_ip, protocol, payload)
}

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
            driver_send(&req_frame[..req_len]);
            // Poll for ARP reply (up to ~1s with multiple retries)
            let mut rx_buf = [0u8; 1514];
            for attempt in 0..3 {
                if attempt > 0 {
                    // Resend ARP request
                    let (req2, rlen2) = arp::send_request(next_hop, our_ip, &our_mac);
                    driver_send(&req2[..rlen2]);
                }
                for _ in 0..500_000 {
                    if let Some(n) = driver_recv(&mut rx_buf) {
                        if let Some((resp, rlen)) = process_frame(&rx_buf[..n]) {
                            driver_send(&resp[..rlen]);
                        }
                    }
                    if let Some(m) = arp::lookup(next_hop) {
                        return send_ip_with_mac(dst_ip, protocol, payload, &m, &our_mac, our_ip);
                    }
                    core::hint::spin_loop();
                }
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
    driver_send(&frame[..frame_len])
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
    while let Some(n) = driver_recv(&mut buf) {
        if let Some((resp, rlen)) = process_frame(&buf[..n]) {
            driver_send(&resp[..rlen]);
        }
    }
}
