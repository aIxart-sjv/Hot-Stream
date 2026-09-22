//! Hostname lookup for a client: a reverse-DNS (PTR) query sent to the hotspot's own DHCP/DNS
//! server (the laptop's address on the hotspot subnet; dnsmasq under NetworkManager).
//!
//! The DHCP lease file that holds hostnames is root-only, but dnsmasq answers PTR queries for
//! leased addresses to anyone on the subnet. The query only ever goes to the hotspot's own
//! address: client IPs are never handed to the system resolver or any external server.
//!
//! Hostnames are chosen by the client (DHCP option 12) and are therefore untrusted text.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Longest hostname we keep, in characters (a DNS label is at most 63 octets).
const MAX_HOSTNAME_CHARS: usize = 63;
/// Compression pointers followed per name before we call it a loop.
const MAX_POINTER_JUMPS: u32 = 8;

/// Build a recursive PTR query for `ip`'s reverse name (`d.c.b.a.in-addr.arpa`).
pub fn build_ptr_query(id: u16, ip: Ipv4Addr) -> Vec<u8> {
    let mut q = Vec::with_capacity(48);
    q.extend_from_slice(&id.to_be_bytes());
    // flags: recursion desired; QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    let [a, b, c, d] = ip.octets();
    for label in [d.to_string(), c.to_string(), b.to_string(), a.to_string()] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    for label in ["in-addr", "arpa"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 12, 0, 1]); // QTYPE=PTR, QCLASS=IN
    q
}

/// Extract the hostname from a DNS response, or `None` if it is not a clean, successful PTR
/// answer to the query with transaction `expected_id`. Never panics on malformed input.
pub fn parse_ptr_response(expected_id: u16, packet: &[u8]) -> Option<String> {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None; // not a response, or RCODE != NOERROR
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);

    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(packet, pos)? + 4; // QTYPE + QCLASS
        if pos > packet.len() {
            return None;
        }
    }
    for _ in 0..answers {
        pos = skip_name(packet, pos)?;
        let fixed = packet.get(pos..pos + 10)?; // TYPE, CLASS, TTL, RDLENGTH
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdata_len = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start.checked_add(rdata_len)?;
        if rdata_end > packet.len() {
            return None;
        }
        if rtype == 12 {
            return sanitize_hostname(&read_name(packet, rdata_start)?);
        }
        pos = rdata_end;
    }
    None
}

/// Offset just past the (possibly compressed) name that starts at `pos`.
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        match len & 0xC0 {
            0xC0 => {
                packet.get(pos + 1)?;
                return Some(pos + 2);
            }
            0x00 if len == 0 => return Some(pos + 1),
            0x00 => pos += 1 + len as usize,
            _ => return None,
        }
    }
}

/// Decode the name at `pos`, following compression pointers (bounded, so loops end).
fn read_name(packet: &[u8], mut pos: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0;
    let mut total = 0;
    loop {
        let len = *packet.get(pos)?;
        match len & 0xC0 {
            0xC0 => {
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return None;
                }
                let low = *packet.get(pos + 1)?;
                pos = (((len & 0x3F) as usize) << 8) | low as usize;
            }
            0x00 if len == 0 => return Some(labels.join(".")),
            0x00 => {
                let label = packet.get(pos + 1..pos + 1 + len as usize)?;
                total += label.len() + 1;
                if total > 255 {
                    return None;
                }
                labels.push(String::from_utf8_lossy(label).into_owned());
                pos += 1 + len as usize;
            }
            _ => return None,
        }
    }
}

/// Make an untrusted hostname safe to display: strip control characters and the trailing
/// root dot, trim, cap the length. `None` if nothing usable remains.
pub fn sanitize_hostname(raw: &str) -> Option<String> {
    let printable: String = raw.chars().filter(|c| !c.is_control()).collect();
    let name = printable.trim().trim_end_matches('.').trim();
    if name.is_empty() {
        return None;
    }
    Some(name.chars().take(MAX_HOSTNAME_CHARS).collect())
}

fn next_query_id() -> u16 {
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    (nanos as u16) ^ COUNTER.fetch_add(0x9e37, Ordering::Relaxed)
}

/// Ask `server` (UDP) for the PTR record of `ip`. `None` on any failure: no answer, timeout,
/// refused, NXDOMAIN, malformed reply.
pub fn lookup_ptr(server: SocketAddr, ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(server).ok()?; // only datagrams from `server` are delivered
    let id = next_query_id();
    socket.send(&build_ptr_query(id, ip)).ok()?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        socket.set_read_timeout(Some(remaining)).ok()?;
        let n = socket.recv(&mut buf).ok()?; // timeout / ICMP "port unreachable" -> None
        let packet = &buf[..n];
        if is_reply_to(id, packet) {
            // The server has spoken. Whether or not there is a name in it, that is final.
            return parse_ptr_response(id, packet);
        }
        // A stray datagram: keep waiting for the real answer until the deadline.
    }
}

/// Is `packet` a response to the query with transaction `id`?
fn is_reply_to(id: u16, packet: &[u8]) -> bool {
    packet.len() >= 12 && u16::from_be_bytes([packet[0], packet[1]]) == id && packet[2] & 0x80 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::Instant;

    /// Hand-assembled per RFC 1035 (independent of the parser under test): id 0x1234, flags
    /// QR|RD|RA, one question `160.0.42.10.in-addr.arpa PTR IN`, one answer whose name is a
    /// compression pointer to the question, up to (not including) RDLENGTH.
    const PREFIX: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, // header
        3, b'1', b'6', b'0', 1, b'0', 2, b'4', b'2', 2, b'1', b'0', // 160.0.42.10 ...
        7, b'i', b'n', b'-', b'a', b'd', b'd', b'r', 4, b'a', b'r', b'p', b'a', 0, // .in-addr.arpa
        0, 12, 0, 1, // QTYPE=PTR, QCLASS=IN
        0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 0, // answer: name=ptr(12), PTR, IN, TTL 0
    ];
    /// RDATA for hostname "I2304" (what dnsmasq returned for a real phone on this laptop).
    const NAME_I2304: &[u8] = &[5, b'I', b'2', b'3', b'0', b'4', 0];

    fn packet(rdata: &[u8]) -> Vec<u8> {
        let mut p = PREFIX.to_vec();
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(rdata);
        p
    }

    #[test]
    fn the_query_is_a_recursive_ptr_question_for_the_reverse_name() {
        let q = build_ptr_query(0x1234, Ipv4Addr::new(10, 42, 0, 160));
        let mut expected = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(&PREFIX[12..42]); // the question section
        assert_eq!(q, expected);
    }

    #[test]
    fn a_plain_answer_yields_the_hostname() {
        assert_eq!(parse_ptr_response(0x1234, &packet(NAME_I2304)).as_deref(), Some("I2304"));
    }

    #[test]
    fn compressed_names_inside_the_answer_are_followed() {
        // label "Mac" + pointer to "in-addr.arpa" in the question section (offset 24)
        let p = packet(&[3, b'M', b'a', b'c', 0xc0, 24]);
        assert_eq!(parse_ptr_response(0x1234, &p).as_deref(), Some("Mac.in-addr.arpa"));
    }

    #[test]
    fn a_compression_loop_terminates_without_a_result() {
        let own_offset = (PREFIX.len() + 2) as u8; // the pointer points at itself
        assert_eq!(parse_ptr_response(0x1234, &packet(&[0xc0, own_offset])), None);
    }

    #[test]
    fn a_pointer_past_the_end_of_the_packet_is_rejected() {
        assert_eq!(parse_ptr_response(0x1234, &packet(&[0xc0, 0xff])), None);
    }

    #[test]
    fn nxdomain_gives_no_hostname() {
        let mut p = packet(NAME_I2304);
        p[3] = 0x83; // RCODE 3
        assert_eq!(parse_ptr_response(0x1234, &p), None);
    }

    #[test]
    fn a_query_echoed_back_is_not_an_answer() {
        let mut p = packet(NAME_I2304);
        p[2] = 0x01; // QR bit clear
        assert_eq!(parse_ptr_response(0x1234, &p), None);
    }

    #[test]
    fn an_answer_with_the_wrong_transaction_id_is_ignored() {
        assert_eq!(parse_ptr_response(0x9999, &packet(NAME_I2304)), None);
    }

    #[test]
    fn a_response_that_claims_no_answers_gives_none() {
        let mut p = packet(NAME_I2304);
        p[7] = 0; // ANCOUNT = 0
        assert_eq!(parse_ptr_response(0x1234, &p), None);
    }

    #[test]
    fn a_non_ptr_answer_gives_none() {
        let mut p = packet(NAME_I2304);
        p[45] = 1; // answer TYPE = A
        assert_eq!(parse_ptr_response(0x1234, &p), None);
    }

    #[test]
    fn every_truncation_of_a_valid_response_is_rejected_without_panicking() {
        let p = packet(NAME_I2304);
        for n in 0..p.len() {
            assert_eq!(parse_ptr_response(0x1234, &p[..n]), None, "prefix of {n} bytes");
        }
    }

    #[test]
    fn a_label_with_invalid_utf8_is_decoded_lossily_not_rejected() {
        let p = packet(&[2, b'a', 0xff, 0]);
        assert_eq!(parse_ptr_response(0x1234, &p).as_deref(), Some("a\u{fffd}"));
    }

    #[test]
    fn hostnames_are_sanitised_for_display() {
        assert_eq!(sanitize_hostname("Mac.").as_deref(), Some("Mac"));
        assert_eq!(sanitize_hostname("  Sittis-iPhone \t").as_deref(), Some("Sittis-iPhone"));
        assert_eq!(sanitize_hostname("a\x1b[31mb\x07\n").as_deref(), Some("a[31mb"));
        assert_eq!(sanitize_hostname(&"x".repeat(100)).unwrap().chars().count(), 63);
        assert_eq!(sanitize_hostname(&"é".repeat(70)).unwrap().chars().count(), 63);
    }

    #[test]
    fn hostnames_with_nothing_displayable_are_dropped() {
        for empty in ["", "   \t", "\x07\x07", ".", " . "] {
            assert_eq!(sanitize_hostname(empty), None, "{empty:?}");
        }
    }

    /// A one-shot UDP "DNS server" on loopback. Returns its address and the query it received.
    fn serve_once(
        reply: impl FnOnce(&[u8]) -> Option<Vec<u8>> + Send + 'static,
    ) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let addr = sock.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let _ = tx.send(buf[..n].to_vec());
                if let Some(resp) = reply(&buf[..n]) {
                    let _ = sock.send_to(&resp, peer);
                }
            }
        });
        (addr, rx)
    }

    const IP: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 160);
    const WAIT: Duration = Duration::from_millis(500);

    #[test]
    fn lookup_sends_the_query_over_udp_and_returns_the_answer() {
        let (addr, received) = serve_once(|q| {
            let mut r = packet(NAME_I2304);
            r[0] = q[0]; // echo the transaction id, as a real server does
            r[1] = q[1];
            Some(r)
        });
        assert_eq!(lookup_ptr(addr, IP, WAIT).as_deref(), Some("I2304"));
        let q = received.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(q, build_ptr_query(u16::from_be_bytes([q[0], q[1]]), IP));
    }

    #[test]
    fn lookup_gives_up_quietly_when_the_server_never_answers() {
        let (addr, _rx) = serve_once(|_| None);
        let started = Instant::now();
        assert_eq!(lookup_ptr(addr, IP, Duration::from_millis(150)), None);
        assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
    }

    #[test]
    fn lookup_ignores_an_answer_carrying_the_wrong_transaction_id() {
        let (addr, _rx) = serve_once(|q| {
            let mut r = packet(NAME_I2304);
            r[0] = q[0] ^ 0xff;
            r[1] = q[1];
            Some(r)
        });
        assert_eq!(lookup_ptr(addr, IP, WAIT), None);
    }

    /// Most phones that send no hostname make dnsmasq answer NXDOMAIN immediately. That is a
    /// definitive answer: waiting out the whole timeout for it would slow every refresh.
    #[test]
    fn lookup_returns_at_once_on_a_definitive_nxdomain_answer() {
        let (addr, _rx) = serve_once(|q| {
            let mut r = packet(NAME_I2304);
            r[0] = q[0];
            r[1] = q[1];
            r[3] = 0x83; // RCODE 3 = NXDOMAIN
            Some(r)
        });
        let started = Instant::now();
        assert_eq!(lookup_ptr(addr, IP, Duration::from_secs(2)), None);
        assert!(started.elapsed() < Duration::from_millis(500), "took {:?}", started.elapsed());
    }

    #[test]
    fn lookup_returns_none_fast_when_nothing_listens() {
        let addr = {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        }; // socket dropped: the kernel answers with ICMP port unreachable
        let started = Instant::now();
        assert_eq!(lookup_ptr(addr, IP, Duration::from_secs(2)), None);
        assert!(started.elapsed() < Duration::from_secs(1), "took {:?}", started.elapsed());
    }
}
