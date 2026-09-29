//! A minimal STUN (RFC 5389) binding request/response codec, matching
//! Tailscale's: requests carry a `SOFTWARE: tailnode` attribute and a
//! trailing `FINGERPRINT`, which Tailscale's STUN servers require.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand::RngCore;

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
    let mut t = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut t);
    t
}

/// Reports whether `b` looks like a STUN packet.
pub fn is_stun(b: &[u8]) -> bool {
    b.len() >= HEADER_LEN && b[0] & 0b1100_0000 == 0 && b[4..8] == MAGIC_COOKIE
}

/// Encodes a binding request.
pub fn request(txid: TxId) -> Vec<u8> {
    let attrs_len = 4 + SOFTWARE.len() + FINGERPRINT_LEN;
    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);
    b.extend_from_slice(&[0x00, 0x01]);
    b.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(&txid);
    b.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    b.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    b.extend_from_slice(SOFTWARE);
    let fp = fingerprint(&b);
    b.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&fp.to_be_bytes());
    b
}

/// Parses a binding request, as a STUN server would, returning its
/// transaction ID. Like Tailscale's server, it insists on the
/// `tailnode` software attribute and a valid trailing fingerprint.
pub fn parse_binding_request(b: &[u8]) -> Option<TxId> {
    if !is_stun(b) || b[0..2] != [0x00, 0x01] {
        return None;
    }
    let txid: TxId = b[8..20].try_into().ok()?;
    let mut software_ok = false;
    let mut last_attr = 0u16;
    let mut got_fp = 0u32;
    for_each_attr(&b[HEADER_LEN..], |t, a| {
        last_attr = t;
        if t == ATTR_SOFTWARE && a == SOFTWARE {
            software_ok = true;
        }
        if t == ATTR_FINGERPRINT && a.len() == 4 {
            got_fp = u32::from_be_bytes(a.try_into().unwrap());
        }
    })?;
    if !software_ok || last_attr != ATTR_FINGERPRINT {
        return None;
    }
    (got_fp == fingerprint(&b[..b.len() - FINGERPRINT_LEN])).then_some(txid)
}

/// Encodes a success response telling the client its address.
pub fn response(txid: TxId, addr: SocketAddr) -> Vec<u8> {
    let (fam, ip): (u8, Vec<u8>) = match addr.ip() {
        IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (1, v4.octets().to_vec()),
            None => (2, v6.octets().to_vec()),
        },
    };
    let attrs_len = 8 + ip.len();
    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);
    b.extend_from_slice(&[0x01, 0x01]);
    b.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(&txid);
    b.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    b.extend_from_slice(&((4 + ip.len()) as u16).to_be_bytes());
    b.push(0);
    b.push(fam);
    b.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
    for (i, o) in ip.iter().enumerate() {
        b.push(if i < 4 { o ^ MAGIC_COOKIE[i] } else { o ^ txid[i - 4] });
    }
    b
}

/// Parses a binding success response, returning its transaction ID and
/// the reflexive address it reports.
pub fn parse_response(b: &[u8]) -> Option<(TxId, SocketAddr)> {
    if !is_stun(b) || b[0..2] != [0x01, 0x01] {
        return None;
    }
    let txid: TxId = b[8..20].try_into().ok()?;
    let attrs_len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let mut rest = &b[HEADER_LEN..];
    if attrs_len > rest.len() {
        return None;
    }
    rest = &rest[..attrs_len];
    let mut addr = None;
    let mut fallback = None;
    for_each_attr(rest, |t, a| match t {
        ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_ALT => {
            if let Some(sa) = decode_addr(a, Some(&txid)) {
                addr = Some(sa);
            }
        }
        ATTR_MAPPED_ADDRESS => {
            if let Some(sa) = decode_addr(a, None) {
                fallback = Some(sa);
            }
        }
        _ => {}
    })?;
    addr.or(fallback).map(|a| (txid, a))
}

fn decode_addr(a: &[u8], xor_txid: Option<&TxId>) -> Option<SocketAddr> {
    if a.len() < 4 {
        return None;
    }
    let len = match a[1] {
        1 => 4,
        2 => 16,
        _ => return None,
    };
    let field = a.get(4..4 + len)?;
    let mut port = u16::from_be_bytes([a[2], a[3]]);
    let mut ip = field.to_vec();
    if let Some(txid) = xor_txid {
        port ^= 0x2112;
        for (i, o) in ip.iter_mut().enumerate() {
            *o ^= if i < 4 { MAGIC_COOKIE[i] } else { txid[i - 4] };
        }
    }
    let ip = if len == 4 {
        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
    } else {
        let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(ip.as_slice()).ok()?);
        v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))
    };
    Some(SocketAddr::new(ip, port))
}

fn for_each_attr(mut b: &[u8], mut f: impl FnMut(u16, &[u8])) -> Option<()> {
    while !b.is_empty() {
        if b.len() < 4 {
            return None;
        }
        let t = u16::from_be_bytes([b[0], b[1]]);
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        let padded = (len + 3) & !3;
        b = &b[4..];
        if padded > b.len() {
            return None;
        }
        f(t, &b[..len]);
        b = &b[padded..];
    }
    Some(())
}

fn fingerprint(b: &[u8]) -> u32 {
    crc32_ieee(b) ^ 0x5354_554e
}

fn crc32_ieee(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    let mut crc = !0u32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn request_response_round_trip() {
        let tx = new_txid();
        let req = request(tx);
        assert_eq!(parse_binding_request(&req), Some(tx));
        let mut bad = req.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(parse_binding_request(&bad), None);

        for a in ["203.0.113.7:41641", "[2001:db8::1]:3478"] {
            let a: SocketAddr = a.parse().unwrap();
            let res = response(tx, a);
            assert_eq!(parse_response(&res), Some((tx, a)));
        }
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
