//! Disco ("discovery") messages: NaCl boxes between peers' disco keys,
//! used to find and verify direct UDP paths.
//!
//! On the wire a disco packet is the 6-byte magic `TS💬`, the sender's
//! 32-byte disco public key, and a sealed box (24-byte nonce, tag,
//! ciphertext). Inside, a type byte and a version byte precede the
//! message body. This matches Tailscale's `disco` package.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::key::{DiscoPrivate, DiscoPublic, DiscoShared, NodePublic};

/// The 6-byte header of every disco packet: `TS💬`.
pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";

const HEADER_LEN: usize = 6 + 32;

const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;

/// A transaction ID for pings and pongs.
pub type TxId = [u8; 12];

/// A decoded disco message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A probe of a path; the recipient answers with a pong over the same path.
    Ping {
        tx_id: TxId,
        /// The sender's node key, which helps map the sender to a peer.
        node_key: Option<NodePublic>,
        /// Zero bytes of padding (for path MTU probing).
        padding: usize,
    },
    /// The answer to a ping, reporting the address the ping came from.
    Pong { tx_id: TxId, src: SocketAddr },
    /// Sent over DERP: "here are my endpoints; ping me there".
    CallMeMaybe { endpoints: Vec<SocketAddr> },
}

/// Reports whether `pkt` looks like a disco packet.
pub fn looks_like_disco(pkt: &[u8]) -> bool {
    pkt.len() >= HEADER_LEN + 24 && pkt.starts_with(MAGIC)
}

/// Returns the sender's disco key from a disco packet.
pub fn source(pkt: &[u8]) -> Option<DiscoPublic> {
    looks_like_disco(pkt).then(|| DiscoPublic::from_slice(&pkt[6..HEADER_LEN]).expect("32 bytes"))
}

fn put_addr(out: &mut Vec<u8>, a: &SocketAddr) {
    let ip16 = match a.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ip16.octets());
    out.extend_from_slice(&a.port().to_be_bytes());
}

fn get_addr(b: &[u8]) -> SocketAddr {
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).expect("16 bytes"));
    let ip = ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip));
    SocketAddr::new(ip, u16::from_be_bytes([b[16], b[17]]))
}

impl Message {
    /// Encodes the message payload (the plaintext inside the box).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Message::Ping { tx_id, node_key, padding } => {
                out.extend_from_slice(&[TYPE_PING, 0]);
                out.extend_from_slice(tx_id);
                if let Some(k) = node_key {
                    out.extend_from_slice(k.as_bytes());
                }
                out.resize(out.len() + padding, 0);
            }
            Message::Pong { tx_id, src } => {
                out.extend_from_slice(&[TYPE_PONG, 0]);
                out.extend_from_slice(tx_id);
                put_addr(&mut out, src);
            }
            Message::CallMeMaybe { endpoints } => {
                out.extend_from_slice(&[TYPE_CALL_ME_MAYBE, 0]);
                for e in endpoints {
                    put_addr(&mut out, e);
                }
            }
        }
        out
    }

    /// Decodes a message payload. Unknown types decode to `None`; longer
    /// than expected messages are accepted for forward compatibility.
    pub fn decode(p: &[u8]) -> Option<Message> {
        if p.len() < 2 {
            return None;
        }
        let (t, ver, body) = (p[0], p[1], &p[2..]);
        match t {
            TYPE_PING => {
                let tx_id: TxId = body.get(..12)?.try_into().ok()?;
                let rest = &body[12..];
                let mut padding = rest.len();
                let mut node_key = None;
                if rest.len() >= 32 {
                    let k = NodePublic::from_slice(&rest[..32]).expect("32 bytes");
                    if !k.is_zero() {
                        node_key = Some(k);
                        padding -= 32;
                    }
                }
                Some(Message::Ping { tx_id, node_key, padding })
            }
            TYPE_PONG => {
                if body.len() < 12 + 18 {
                    return None;
                }
                let tx_id: TxId = body[..12].try_into().ok()?;
                Some(Message::Pong { tx_id, src: get_addr(&body[12..30]) })
            }
            TYPE_CALL_ME_MAYBE => {
                let mut endpoints = Vec::new();
                if ver == 0 && !body.is_empty() && body.len() % 18 == 0 {
                    for chunk in body.chunks(18) {
                        endpoints.push(get_addr(chunk));
                    }
                }
                Some(Message::CallMeMaybe { endpoints })
            }
            _ => None,
        }
    }

    /// A short description for logs.
    pub fn summary(&self) -> String {
        match self {
            Message::Ping { tx_id, padding, .. } => format!("ping tx={} padding={padding}", hex::encode(&tx_id[..6])),
            Message::Pong { tx_id, .. } => format!("pong tx={}", hex::encode(&tx_id[..6])),
            Message::CallMeMaybe { endpoints } => format!("call-me-maybe ({} endpoints)", endpoints.len()),
        }
    }
}

/// Seals `msg` from `ours` to the peer whose shared key is `shared`,
/// producing a complete disco packet.
pub fn seal(our_public: &DiscoPublic, shared: &DiscoShared, msg: &Message) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);
    pkt.extend_from_slice(MAGIC);
    pkt.extend_from_slice(our_public.as_bytes());
    pkt.extend_from_slice(&shared.seal(&msg.encode()));
    pkt
}

/// Opens a disco packet with the shared key for its sender.
pub fn open(shared: &DiscoShared, pkt: &[u8]) -> Option<Message> {
    if !looks_like_disco(pkt) {
        return None;
    }
    Message::decode(&shared.open(&pkt[HEADER_LEN..])?)
}

/// Convenience: seal with a private key, computing the shared secret.
pub fn seal_with(ours: &DiscoPrivate, to: &DiscoPublic, msg: &Message) -> Vec<u8> {
    seal(&ours.public(), &ours.shared(to), msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();
        let msgs = [
            Message::Ping { tx_id: [7; 12], node_key: Some(NodePublic::from_bytes([9; 32])), padding: 0 },
            Message::Ping { tx_id: [7; 12], node_key: None, padding: 5 },
            Message::Pong { tx_id: [1; 12], src: "203.0.113.9:41641".parse().unwrap() },
            Message::Pong { tx_id: [1; 12], src: "[2001:db8::2]:5".parse().unwrap() },
            Message::CallMeMaybe {
                endpoints: vec!["192.0.2.1:1".parse().unwrap(), "[2001:db8::1]:2".parse().unwrap()],
            },
        ];
        for m in msgs {
            let pkt = seal_with(&a, &b.public(), &m);
            assert_eq!(source(&pkt), Some(a.public()));
            assert_eq!(open(&b.shared(&a.public()), &pkt), Some(m));
        }
    }

    #[test]
    fn go_wire_layout() {
        // Ping: type, version, 12-byte txid, 32-byte node key.
        let m = Message::Ping { tx_id: [0xaa; 12], node_key: Some(NodePublic::from_bytes([0xbb; 32])), padding: 0 };
        let e = m.encode();
        assert_eq!(e.len(), 2 + 12 + 32);
        assert_eq!(&e[..2], &[1, 0]);
        // Pong: IPv4 addresses are v4-mapped IPv6 on the wire.
        let m = Message::Pong { tx_id: [0; 12], src: "1.2.3.4:258".parse().unwrap() };
        let e = m.encode();
        assert_eq!(&e[14..30], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]);
        assert_eq!(&e[30..32], &[1, 2]);
    }
}
