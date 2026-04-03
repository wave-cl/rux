//! Minimal DNS resolver: A record queries via UDP.
//!
//! Sends queries to a configured nameserver (default: 10.0.2.3 for QEMU)
//! and caches results. Used by musl's resolver which reads /etc/resolv.conf.

/// DNS query ID counter
static mut QUERY_ID: u16 = 1;

/// DNS cache: 8 entries
static mut DNS_CACHE: [DnsEntry; 8] = [DnsEntry::empty(); 8];
static mut DNS_CACHE_IDX: usize = 0;

#[derive(Clone, Copy)]
struct DnsEntry {
    name: [u8; 64],
    name_len: u8,
    ip: [u8; 4],
    valid: bool,
}

impl DnsEntry {
    const fn empty() -> Self {
        Self { name: [0; 64], name_len: 0, ip: [0; 4], valid: false }
    }
}

/// Build a DNS A record query packet.
pub fn build_query(name: &[u8], buf: &mut [u8]) -> usize {
    if buf.len() < 512 || name.is_empty() { return 0; }

    unsafe { QUERY_ID += 1; }
    let id = unsafe { QUERY_ID };

    // Header (12 bytes)
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2] = 0x01; buf[3] = 0x00; // flags: recursion desired
    buf[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf[6..12].copy_from_slice(&[0; 6]); // ANCOUNT, NSCOUNT, ARCOUNT = 0

    // Question: encode domain name as labels
    let mut pos = 12;
    let mut i = 0;
    while i < name.len() {
        // Find next dot or end
        let mut j = i;
        while j < name.len() && name[j] != b'.' { j += 1; }
        let label_len = j - i;
        if label_len == 0 || label_len > 63 { return 0; }
        buf[pos] = label_len as u8;
        pos += 1;
        buf[pos..pos + label_len].copy_from_slice(&name[i..j]);
        pos += label_len;
        i = j + 1;
    }
    buf[pos] = 0; pos += 1; // root label
    buf[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes()); pos += 2; // QTYPE=A
    buf[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes()); pos += 2; // QCLASS=IN

    pos
}

/// Parse a DNS response and extract the first A record IP.
pub fn parse_response(buf: &[u8]) -> Option<[u8; 4]> {
    if buf.len() < 12 { return None; }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 { return None; }

    // Skip header (12 bytes) + question section
    let mut pos = 12;
    // Skip question: name + QTYPE(2) + QCLASS(2)
    while pos < buf.len() && buf[pos] != 0 {
        let label_len = buf[pos] as usize;
        if label_len & 0xC0 == 0xC0 { pos += 2; break; } // compression
        pos += 1 + label_len;
    }
    if buf[pos] == 0 { pos += 1; }
    pos += 4; // QTYPE + QCLASS

    // Parse answer records
    for _ in 0..ancount {
        if pos + 12 > buf.len() { return None; }
        // Name (might be compressed)
        if buf[pos] & 0xC0 == 0xC0 { pos += 2; }
        else {
            while pos < buf.len() && buf[pos] != 0 {
                pos += 1 + buf[pos] as usize;
            }
            pos += 1;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10; // type(2) + class(2) + ttl(4) + rdlength(2)

        if rtype == 1 && rdlen == 4 && pos + 4 <= buf.len() {
            // A record!
            return Some([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        }
        pos += rdlen;
    }
    None
}

/// Look up a hostname in the DNS cache.
pub fn cache_lookup(name: &[u8]) -> Option<[u8; 4]> {
    unsafe {
        for e in DNS_CACHE.iter() {
            if e.valid && e.name_len as usize == name.len()
                && &e.name[..name.len()] == name
            {
                return Some(e.ip);
            }
        }
    }
    None
}

/// Insert a hostname→IP mapping into the DNS cache.
pub fn cache_insert(name: &[u8], ip: [u8; 4]) {
    unsafe {
        let idx = DNS_CACHE_IDX;
        DNS_CACHE_IDX = (idx + 1) % 8;
        let e = &mut DNS_CACHE[idx];
        let n = name.len().min(63);
        e.name[..n].copy_from_slice(&name[..n]);
        e.name_len = n as u8;
        e.ip = ip;
        e.valid = true;
    }
}
