//! Disco ("discovery") messages: NaCl boxes between peers' disco keys,
//! used to find and verify direct UDP paths.
//!
//! On the wire a disco packet is the 6-byte magic `TS💬`, the sender's
//! 32-byte disco public key, and a sealed box (24-byte nonce, tag,
//! ciphertext). Inside, a type byte and a version byte precede the
//! message body. This matches Tailscale's `disco` package.

use std::net::{IpAddr, SocketAddr};

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
    looks_like_disco(pkt).then(|| DiscoPublic::from_bytes(pkt[6..HEADER_LEN].try_into().unwrap()))
}

fn put_addr(out: &mut Vec<u8>, a: &SocketAddr) {
    let ip16 = match a.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend(ip16.octets());
    out.extend(a.port().to_be_bytes());
}

fn get_addr(b: &[u8; 18]) -> SocketAddr {
    let ip: [u8; 16] = b[..16].try_into().unwrap();
    SocketAddr::new(IpAddr::from(ip).to_canonical(), u16::from_be_bytes([b[16], b[17]]))
}

impl Message {
    /// Encodes the message payload (the plaintext inside the box).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Message::Ping { tx_id, node_key, padding } => {
                out.extend([TYPE_PING, 0]);
                out.extend(tx_id);
                if let Some(k) = node_key {
                    out.extend(k.as_bytes());
                }
                out.resize(out.len() + padding, 0);
            }
            Message::Pong { tx_id, src } => {
                out.extend([TYPE_PONG, 0]);
                out.extend(tx_id);
                put_addr(&mut out, src);
            }
            Message::CallMeMaybe { endpoints } => {
                out.extend([TYPE_CALL_ME_MAYBE, 0]);
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
        let [t, ver, body @ ..] = p else { return None };
        match *t {
            TYPE_PING => {
                let (tx_id, rest) = body.split_first_chunk::<12>()?;
                let node_key = rest.first_chunk().map(|k| NodePublic::from_bytes(*k)).filter(|k| !k.is_zero());
                let padding = rest.len() - if node_key.is_some() { 32 } else { 0 };
                Some(Message::Ping { tx_id: *tx_id, node_key, padding })
            }
            TYPE_PONG => {
                let (tx_id, rest) = body.split_first_chunk::<12>()?;
                Some(Message::Pong { tx_id: *tx_id, src: get_addr(rest.first_chunk()?) })
            }
            TYPE_CALL_ME_MAYBE => {
                let (chunks, rest) = body.as_chunks();
                let valid = *ver == 0 && rest.is_empty();
                let endpoints = if valid { chunks.iter().map(get_addr).collect() } else { Vec::new() };
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
    [MAGIC.as_slice(), our_public.as_bytes(), &shared.seal(&msg.encode())].concat()
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

    #[test]
    fn decodes_edge_cases() {
        assert_eq!(Message::decode(&[]), None);
        assert_eq!(Message::decode(&[TYPE_PING]), None);
        assert_eq!(Message::decode(&[0x7f, 0]), None, "unknown type");
        // A ping too short for its transaction ID; one with a zero node key
        // counts it as padding; one with a trailing extension is accepted.
        assert_eq!(Message::decode(&[TYPE_PING, 0, 1, 2]), None);
        let ping = |rest: &[u8]| Message::decode(&[&[TYPE_PING, 0][..], &[5; 12], rest].concat());
        assert_eq!(ping(&[0; 40]), Some(Message::Ping { tx_id: [5; 12], node_key: None, padding: 40 }));
        let k = NodePublic::from_bytes([1; 32]);
        let got = ping(&[[1; 32].as_slice(), &[0; 3]].concat());
        assert_eq!(got, Some(Message::Ping { tx_id: [5; 12], node_key: Some(k), padding: 3 }));
        // A truncated pong.
        let pong = Message::Pong { tx_id: [1; 12], src: "192.0.2.1:9".parse().unwrap() }.encode();
        assert_eq!(Message::decode(&pong[..pong.len() - 1]), None);
        // Call-me-maybe with a ragged body or unknown version carries no endpoints.
        let cmm = Message::CallMeMaybe { endpoints: vec!["192.0.2.1:9".parse().unwrap()] }.encode();
        assert_eq!(Message::decode(&cmm[..cmm.len() - 1]), Some(Message::CallMeMaybe { endpoints: vec![] }));
        let mut v1 = cmm.clone();
        v1[1] = 1;
        assert_eq!(Message::decode(&v1), Some(Message::CallMeMaybe { endpoints: vec![] }));
        assert_eq!(Message::decode(&cmm[..2]), Some(Message::CallMeMaybe { endpoints: vec![] }));
    }

    #[test]
    fn rejects_foreign_packets() {
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();
        let m = Message::CallMeMaybe { endpoints: vec![] };
        let pkt = seal_with(&a, &b.public(), &m);
        // Not ours to open, too short, or without the magic.
        assert_eq!(open(&a.shared(&a.public()), &pkt), None);
        assert_eq!(source(&pkt[..HEADER_LEN + 23]), None);
        let mut bad = pkt.clone();
        bad[0] = b'X';
        assert_eq!(source(&bad), None);
        assert_eq!(open(&b.shared(&a.public()), &bad), None);
    }
}
