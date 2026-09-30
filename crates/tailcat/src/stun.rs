//! A minimal STUN (RFC 5389) binding request/response codec, matching
//! Tailscale's: requests carry a `SOFTWARE: tailnode` attribute and a
//! trailing `FINGERPRINT`, which Tailscale's STUN servers require.

use std::net::{IpAddr, SocketAddr};

const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;
const SOFTWARE: &[u8] = b"tailnode";
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const HEADER_LEN: usize = 20;
const FINGERPRINT_LEN: usize = 8;

/// A STUN transaction ID.
pub type TxId = [u8; 12];

/// Returns a new random transaction ID.
pub fn new_txid() -> TxId {
    rand::random()
}

/// Reports whether `b` looks like a STUN packet.
pub fn is_stun(b: &[u8]) -> bool {
    b.len() >= HEADER_LEN && b[0] & 0b1100_0000 == 0 && b[4..8] == MAGIC_COOKIE
}

/// Starts a message of type `typ` whose attributes will take `attrs_len` bytes.
fn header(typ: [u8; 2], attrs_len: usize, txid: &TxId) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);
    b.extend(typ);
    b.extend((attrs_len as u16).to_be_bytes());
    b.extend(MAGIC_COOKIE);
    b.extend(txid);
    b
}

fn put_attr(b: &mut Vec<u8>, t: u16, v: &[u8]) {
    b.extend(t.to_be_bytes());
    b.extend((v.len() as u16).to_be_bytes());
    b.extend(v);
}

/// Encodes a binding request.
pub fn request(txid: TxId) -> Vec<u8> {
    let mut b = header(BINDING_REQUEST, 4 + SOFTWARE.len() + FINGERPRINT_LEN, &txid);
    put_attr(&mut b, ATTR_SOFTWARE, SOFTWARE);
    let fp = fingerprint(&b);
    put_attr(&mut b, ATTR_FINGERPRINT, &fp.to_be_bytes());
    b
}

/// Parses a binding request, as a STUN server would, returning its
/// transaction ID. Like Tailscale's server, it insists on the
/// `tailnode` software attribute and a valid trailing fingerprint.
pub fn parse_binding_request(b: &[u8]) -> Option<TxId> {
    if !is_stun(b) || b[0..2] != BINDING_REQUEST {
        return None;
    }
    let mut software_ok = false;
    let mut last_attr = 0u16;
    let mut got_fp = None;
    for_each_attr(&b[HEADER_LEN..], |t, a| {
        last_attr = t;
        software_ok |= t == ATTR_SOFTWARE && a == SOFTWARE;
        if t == ATTR_FINGERPRINT {
            got_fp = a.try_into().ok().map(u32::from_be_bytes);
        }
    })?;
    let want_fp = fingerprint(&b[..b.len() - FINGERPRINT_LEN]);
    (software_ok && last_attr == ATTR_FINGERPRINT && got_fp == Some(want_fp)).then(|| txid(b))
}

/// Encodes a success response telling the client its address.
pub fn response(txid: TxId, addr: SocketAddr) -> Vec<u8> {
    let (fam, mut ip) = match addr.ip().to_canonical() {
        IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2, v6.octets().to_vec()),
    };
    xor_ip(&mut ip, &txid);
    let mut v = vec![0, fam];
    v.extend((addr.port() ^ 0x2112).to_be_bytes());
    v.extend(ip);
    let mut b = header(BINDING_SUCCESS, 4 + v.len(), &txid);
    put_attr(&mut b, ATTR_XOR_MAPPED_ADDRESS, &v);
    b
}

/// Parses a binding success response, returning its transaction ID and
/// the reflexive address it reports.
pub fn parse_response(b: &[u8]) -> Option<(TxId, SocketAddr)> {
    if !is_stun(b) || b[0..2] != BINDING_SUCCESS {
        return None;
    }
    let txid = txid(b);
    let attrs_len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let mut addr = None;
    let mut fallback = None;
    for_each_attr(b.get(HEADER_LEN..HEADER_LEN + attrs_len)?, |t, a| match t {
        ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_ALT => addr = decode_addr(a, Some(&txid)).or(addr),
        ATTR_MAPPED_ADDRESS => fallback = decode_addr(a, None).or(fallback),
        _ => {}
    })?;
    addr.or(fallback).map(|a| (txid, a))
}

fn txid(b: &[u8]) -> TxId {
    b[8..HEADER_LEN].try_into().unwrap()
}

/// XORs an address with the magic cookie and then the transaction ID.
fn xor_ip(ip: &mut [u8], txid: &TxId) {
    for (o, k) in ip.iter_mut().zip(MAGIC_COOKIE.iter().chain(txid)) {
        *o ^= k;
    }
}

fn decode_addr(a: &[u8], xor_txid: Option<&TxId>) -> Option<SocketAddr> {
    let len = match a.get(1)? {
        1 => 4,
        2 => 16,
        _ => return None,
    };
    let mut port = u16::from_be_bytes(a.get(2..4)?.try_into().ok()?);
    let mut ip = a.get(4..4 + len)?.to_vec();
    if let Some(txid) = xor_txid {
        port ^= 0x2112;
        xor_ip(&mut ip, txid);
    }
    let ip = match <[u8; 4]>::try_from(ip.as_slice()) {
        Ok(v4) => IpAddr::from(v4),
        Err(_) => IpAddr::from(<[u8; 16]>::try_from(ip.as_slice()).ok()?),
    };
    Some(SocketAddr::new(ip.to_canonical(), port))
}

fn for_each_attr(mut b: &[u8], mut f: impl FnMut(u16, &[u8])) -> Option<()> {
    while !b.is_empty() {
        let t = u16::from_be_bytes(b.get(0..2)?.try_into().ok()?);
        let len = u16::from_be_bytes(b.get(2..4)?.try_into().ok()?) as usize;
        let padded = (len + 3) & !3;
        f(t, b.get(4..4 + len)?);
        b = b.get(4 + padded..)?;
    }
    Some(())
}

fn fingerprint(b: &[u8]) -> u32 {
    crc32_ieee(b) ^ 0x5354_554e
}

fn crc32_ieee(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    !data.iter().fold(!0u32, |crc, &b| TABLE[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn crc_known_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32_ieee(b""), 0);
    }

    #[test]
    fn request_response_round_trip() {
        let tx = new_txid();
        let req = request(tx);
        assert!(is_stun(&req));
        assert_eq!(parse_binding_request(&req), Some(tx));
        let mut bad = req.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(parse_binding_request(&bad), None);
        // A response isn't a request, and vice versa.
        assert_eq!(parse_response(&req), None);

        for a in [addr("203.0.113.7:41641"), addr("[2001:db8::1]:3478")] {
            let res = response(tx, a);
            assert_eq!(parse_binding_request(&res), None);
            assert_eq!(parse_response(&res), Some((tx, a)));
        }
        // IPv4-mapped IPv6 addresses are reported as IPv4.
        let res = response(tx, addr("[::ffff:192.0.2.1]:5"));
        assert_eq!(res.len(), 20 + 12);
        assert_eq!(parse_response(&res), Some((tx, addr("192.0.2.1:5"))));
    }

    #[test]
    fn requests_need_software_and_trailing_fingerprint() {
        let tx = [3; 12];
        // No SOFTWARE attribute: just a fingerprint.
        let mut b = header(BINDING_REQUEST, FINGERPRINT_LEN, &tx);
        let fp = fingerprint(&b);
        put_attr(&mut b, ATTR_FINGERPRINT, &fp.to_be_bytes());
        assert_eq!(parse_binding_request(&b), None);
        // A truncated request.
        let req = request(tx);
        assert_eq!(parse_binding_request(&req[..req.len() - 2]), None);
        assert!(!is_stun(&req[..19]));
    }

    /// A response byte-for-byte as RFC 5769 section 2.2 gives it, less
    /// its SOFTWARE, MESSAGE-INTEGRITY and FINGERPRINT attributes.
    #[test]
    fn parses_rfc5769_ipv4_response() {
        let tx: TxId = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];
        let mut b = header(BINDING_SUCCESS, 12, &tx);
        put_attr(&mut b, ATTR_XOR_MAPPED_ADDRESS, &[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
        let mapped = addr("192.0.2.1:32853");
        assert_eq!(parse_response(&b), Some((tx, mapped)));
        assert_eq!(response(tx, mapped), b);
    }

    #[test]
    fn falls_back_to_mapped_address() {
        let tx = [9; 12];
        let mut b = header(BINDING_SUCCESS, 8 + 12, &tx);
        put_attr(&mut b, 0x7777, &[1, 2, 3]); // unknown, padded to 4
        b.push(0);
        put_attr(&mut b, ATTR_MAPPED_ADDRESS, &[0, 1, 0x12, 0x34, 198, 51, 100, 7]);
        assert_eq!(parse_response(&b), Some((tx, addr("198.51.100.7:4660"))));
        // An attribute running past the end is rejected.
        let mut b = header(BINDING_SUCCESS, 8, &tx);
        b.extend([0x00, 0x20, 0x00, 0x08, 0, 1, 0, 0]);
        assert_eq!(parse_response(&b), None);
    }

    /// A request byte-for-byte as Tailscale's Go stun.Request builds it for
    /// an all-zero transaction ID.
    #[test]
    fn request_matches_go_layout() {
        let req = request([0; 12]);
        assert_eq!(req.len(), 20 + 12 + 8);
        assert_eq!(&req[0..4], &[0x00, 0x01, 0x00, 0x14]);
        assert_eq!(&req[20..24], &[0x80, 0x22, 0x00, 0x08]);
        assert_eq!(&req[24..32], b"tailnode");
        assert_eq!(&req[32..36], &[0x80, 0x28, 0x00, 0x04]);
    }
}
